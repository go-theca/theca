//go:build darwin

package lockwatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ebitengine/purego"
	"github.com/go-macos/objc"
)

// The notifications that say the person has gone, and the reason each stands for.
const (
	lockNote   = "com.apple.screenIsLocked"
	sleepNote  = "NSWorkspaceWillSleepNotification"
	resignNote = "NSWorkspaceSessionDidResignActiveNotification"
)

var reasons = map[string]string{lockNote: "lock", sleepNote: "sleep", resignNote: "session"}

// Seams the tests replace: the notification source and its timing.
var (
	observe = objc.Observe
	post    = objc.Post

	// probeEvery and probeWait pace the self-test of the observers.
	probeEvery = 50 * time.Millisecond
	probeWait  = 2 * time.Second
)

// ErrNotDelivered says the observers registered but a notification posted
// through them never came back: nothing runs the main thread's run loop.
var ErrNotDelivered = errors.New("lockwatch: notifications registered but not delivered (no run loop on the main thread)")

// listen registers the observers and proves them: it posts a distributed
// notification of its own name until the observers hear it, so a registration
// that no run loop will ever serve is found now and not at the first lock.
func listen(ctx context.Context) (<-chan string, error) {
	ictx, cancel := context.WithCancel(ctx)
	probe := fmt.Sprintf("org.go-theca.lockwatch.probe.%d", os.Getpid())
	dist, err := observe(ictx, objc.DistributedCenter, lockNote, probe)
	if err != nil {
		cancel()
		return nil, err
	}
	ws, err := observe(ictx, objc.WorkspaceCenter, sleepNote, resignNote)
	if err != nil {
		cancel()
		return nil, err
	}
	heard := make(chan struct{})
	var once sync.Once
	out := make(chan string, 1)
	go func() {
		defer close(out)
		defer cancel()
		for dist != nil || ws != nil {
			var name string
			var ok bool
			select {
			case name, ok = <-dist:
				if !ok {
					dist = nil
					continue
				}
			case name, ok = <-ws:
				if !ok {
					ws = nil
					continue
				}
			}
			if name == probe {
				once.Do(func() { close(heard) })
				continue
			}
			if r, known := reasons[name]; known {
				out <- r
				return
			}
		}
	}()
	tick := time.NewTicker(probeEvery)
	defer tick.Stop()
	deadline := time.NewTimer(probeWait)
	defer deadline.Stop()
	for {
		if err := post(objc.DistributedCenter, probe); err != nil {
			cancel()
			return nil, err
		}
		select {
		case <-heard:
			return out, nil
		case <-deadline.C:
			cancel()
			return nil, ErrNotDelivered
		case <-tick.C:
		}
	}
}

// dlopen is a seam: the tests make a framework fail to load.
var dlopen = purego.Dlopen

// cf is the handful of CoreFoundation calls a lock read makes; the tests fake it.
type cf struct {
	sessionDict func() uintptr
	dictGet     func(d, k uintptr) uintptr
	boolValue   func(b uintptr) bool
	release     func(o uintptr)
	key         uintptr
}

// locked reads the lock flag; a session without the dictionary (ssh) reads as
// not locked, and nothing is released that was never returned.
func (c cf) locked() bool {
	d := c.sessionDict()
	if d == 0 {
		return false
	}
	defer c.release(d)
	v := c.dictGet(d, c.key)
	return v != 0 && c.boolValue(v)
}

// watch listens for the lock, sleep and session-end notifications. They need
// the main thread's run loop (objc.RunMainLoop, run by the caller); when the
// observers cannot be registered, or a probe shows nothing delivers them, it
// falls back to reading CGSSessionScreenIsLocked from the session's dictionary
// every pollInterval, and says which it does.
func watch(ctx context.Context) (<-chan string, error) {
	ch, err := listen(ctx)
	if err == nil {
		Logf("close-on-lock: notifications (screen lock, sleep, session end)")
		return ch, nil
	}
	Logf("close-on-lock: notifications unavailable (%v); polling every %v", err, pollInterval)
	return pollWatch(ctx)
}

// pollWatch reads CGSSessionScreenIsLocked from the current session's
// dictionary (CoreGraphics; no run loop needed) every pollInterval, and notices
// a sleep as a wall-clock jump. A session without the dictionary (ssh) reads as
// not locked.
func pollWatch(ctx context.Context) (<-chan string, error) {
	cg, err := dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	lib, err := dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	var (
		c         cf
		strCreate func(alloc uintptr, s *byte, enc uint32) uintptr
	)
	purego.RegisterLibFunc(&c.sessionDict, cg, "CGSessionCopyCurrentDictionary")
	purego.RegisterLibFunc(&c.dictGet, lib, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&strCreate, lib, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&c.boolValue, lib, "CFBooleanGetValue")
	purego.RegisterLibFunc(&c.release, lib, "CFRelease")
	name := append([]byte("CGSSessionScreenIsLocked"), 0)
	c.key = strCreate(0, &name[0], 0x08000100) // kCFStringEncodingUTF8
	return newPoll(ctx, c.locked), nil
}
