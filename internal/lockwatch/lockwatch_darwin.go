//go:build darwin

package lockwatch

import (
	"context"

	"github.com/ebitengine/purego"
)

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

// watch reads CGSSessionScreenIsLocked from the current session's dictionary
// (CoreGraphics; no run loop needed) every pollInterval. A session without the
// dictionary (ssh) reads as not locked.
func watch(ctx context.Context) (<-chan string, error) {
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
