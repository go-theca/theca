//go:build windows

package lockwatch

import (
	"context"
	"testing"
	"time"

	"github.com/go-mswin/win32"
)

// The window is real; the messages are posted by the test, which is what the
// session manager does when the session locks (WM_WTSSESSION_CHANGE) or the
// machine suspends (WM_POWERBROADCAST). Whether the system sends them is
// measured by locking the session, not here.
func TestWatchWindowsMessages(t *testing.T) {
	var rw *realWindow
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := watchWindow(ctx, func(h func(uint32, uintptr)) (nativeWindow, error) {
		w, err := newRealWindow(h)
		rw, _ = w.(*realWindow)
		return w, err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		msg  uint32
		w    uintptr
		want string
	}{
		{wmWTSSessionChange, wtsSessionLock, "lock"},
		{wmPowerBroadcast, pbtAPMSuspend, "sleep"},
		{wmWTSSessionChange, wtsSessionLogoff, "shutdown"},
	} {
		win32.PostMessage(rw.Hwnd(), c.msg, win32.WPARAM(c.w), 0)
		select {
		case got := <-ch:
			if got != c.want {
				t.Errorf("msg %#x: %q, want %q", c.msg, got, c.want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("msg %#x: nothing", c.msg)
		}
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("reason after stop")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("channel not closed after stop")
	}
}

func TestWatchReal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("channel not closed")
	}
}
