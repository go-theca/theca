//go:build darwin

package lockwatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-macos/objc"
)

// The main thread, served for the whole run so that the REAL notification path
// can be measured: notifications are delivered on its run loop.
func init() { runtime.LockOSThread() }

func TestMain(m *testing.M) {
	ctx, stop := context.WithCancel(context.Background())
	go func() {
		code := m.Run()
		stop()
		os.Exit(code)
	}()
	// Returns when the tests are done; had it returned early (not the main
	// thread), TestListenRealRoundTrip says so, and the process waits for it.
	objc.RunMainLoop(ctx)
	select {}
}

// fake is a notification source the tests drive by hand.
type fake struct {
	mu       sync.Mutex
	chans    map[objc.Center]chan string
	posts    int
	echo     bool  // a posted probe comes back on the distributed center
	obsErr   error // Observe fails
	obsErrOn objc.Center
	postErr  error
}

func newFake(t *testing.T) *fake {
	f := &fake{chans: map[objc.Center]chan string{}, echo: true}
	so, sp, se, sw := observe, post, probeEvery, probeWait
	t.Cleanup(func() { observe, post, probeEvery, probeWait = so, sp, se, sw })
	observe = f.observe
	post = f.post
	probeEvery, probeWait = 5*time.Millisecond, 200*time.Millisecond
	return f
}

func (f *fake) observe(ctx context.Context, c objc.Center, names ...string) (<-chan string, error) {
	if f.obsErr != nil && f.obsErrOn == c {
		return nil, f.obsErr
	}
	ch := make(chan string, 8)
	f.mu.Lock()
	f.chans[c] = ch
	f.mu.Unlock()
	go func() { <-ctx.Done(); close(ch) }()
	return ch, nil
}

func (f *fake) post(c objc.Center, name string) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.mu.Lock()
	f.posts++
	ch := f.chans[c]
	f.mu.Unlock()
	if f.echo {
		select {
		case ch <- name:
		default:
		}
	}
	return nil
}

func (f *fake) send(c objc.Center, name string) { f.chans[c] <- name }

func recvNote(t *testing.T, ch <-chan string) (string, bool) {
	t.Helper()
	select {
	case s, ok := <-ch:
		return s, ok
	case <-time.After(3 * time.Second):
		t.Fatal("nothing within 3 s")
	}
	return "", false
}

func TestListenReportsEachReason(t *testing.T) {
	for _, tc := range []struct {
		center objc.Center
		note   string
		want   string
	}{
		{objc.DistributedCenter, lockNote, "lock"},
		{objc.WorkspaceCenter, sleepNote, "sleep"},
		{objc.WorkspaceCenter, resignNote, "session"},
	} {
		f := newFake(t)
		ctx, cancel := context.WithCancel(context.Background())
		ch, err := listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		f.send(tc.center, "something.unrelated")
		f.send(tc.center, tc.note)
		if got, ok := recvNote(t, ch); !ok || got != tc.want {
			t.Errorf("%s: got %q %v, want %q", tc.note, got, ok, tc.want)
		}
		if _, ok := recvNote(t, ch); ok {
			t.Errorf("%s: more than one reason", tc.note)
		}
		cancel()
	}
}

func TestListenClosesWhenTheContextEnds(t *testing.T) {
	newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if s, ok := recvNote(t, ch); ok {
		t.Fatalf("got %q after cancel", s)
	}
}

func TestListenErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []objc.Center{objc.DistributedCenter, objc.WorkspaceCenter} {
		f := newFake(t)
		f.obsErr, f.obsErrOn = boom, c
		if _, err := listen(context.Background()); !errors.Is(err, boom) {
			t.Errorf("observe on %v: %v", c, err)
		}
	}
	f := newFake(t)
	f.postErr = boom
	if _, err := listen(context.Background()); !errors.Is(err, boom) {
		t.Errorf("post: %v", err)
	}
	f = newFake(t)
	f.echo = false
	if _, err := listen(context.Background()); !errors.Is(err, ErrNotDelivered) {
		t.Errorf("no echo: %v", err)
	}
}

func TestWatchSaysWhichModeIsActive(t *testing.T) {
	var log []string
	saved := Logf
	t.Cleanup(func() { Logf = saved })
	Logf = func(format string, args ...any) { log = append(log, fmt.Sprintf(format, args...)) }

	f := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 || !strings.Contains(log[0], "notifications (") {
		t.Fatalf("log = %q", log)
	}
	f.send(objc.WorkspaceCenter, sleepNote)
	if got, _ := recvNote(t, ch); got != "sleep" {
		t.Fatalf("got %q", got)
	}
	cancel()

	// Observers that nothing delivers: polling, and the log says so.
	f = newFake(t)
	f.echo = false
	log = nil
	ctx, cancel = context.WithCancel(context.Background())
	ch, err = Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 || !strings.Contains(log[0], "polling every") || !strings.Contains(log[0], ErrNotDelivered.Error()) {
		t.Fatalf("log = %q", log)
	}
	cancel()
	for range ch {
	}
}

// TestListenRealRoundTrip is the measurement that needs no screen lock: the
// real observers, the real main-thread run loop (TestMain), and the probe the
// code posts itself. It never posts a real lock notification, which would close
// the containers of every theca of this user.
func TestListenRealRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	ch, err := listen(ctx)
	if err != nil {
		t.Fatalf("the real observers were not proven: %v", err)
	}
	t.Logf("observers registered and proven in %v", time.Since(start))
	cancel()
	for range ch {
	}
}

func TestDlopenFailures(t *testing.T) {
	saved := dlopen
	t.Cleanup(func() { dlopen = saved })
	for _, failing := range []string{"CoreGraphics", "CoreFoundation"} {
		want := errors.New("no " + failing)
		dlopen = func(path string, mode int) (uintptr, error) {
			if strings.Contains(path, failing) {
				return 0, want
			}
			return saved(path, mode)
		}
		if _, err := pollWatch(context.Background()); !errors.Is(err, want) {
			t.Errorf("%s: %v", failing, err)
		}
	}
}

func TestPollWatchReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := pollWatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for range ch {
	}
}

func TestLockedReading(t *testing.T) {
	released := 0
	mk := func(d, v uintptr, b bool) cf {
		return cf{
			sessionDict: func() uintptr { return d },
			dictGet:     func(_, _ uintptr) uintptr { return v },
			boolValue:   func(uintptr) bool { return b },
			release:     func(uintptr) { released++ },
		}
	}
	if mk(0, 1, true).locked() || released != 0 {
		t.Fatal("no dictionary must read unlocked and release nothing")
	}
	if mk(7, 0, true).locked() || released != 1 {
		t.Fatal("no key reads unlocked", released)
	}
	if mk(7, 1, false).locked() {
		t.Fatal("false flag read locked")
	}
	if !mk(7, 1, true).locked() || released != 3 {
		t.Fatal("true flag read unlocked", released)
	}
}
