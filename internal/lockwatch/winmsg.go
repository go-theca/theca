package lockwatch

import (
	"context"
	"fmt"
	"runtime"
)

// The Windows watcher, minus the Win32 calls (lockwatch_windows.go): which
// message means what, and the life of the thread that owns the window. It is plain
// Go so that every system tests it.
//
// A window receives WM_WTSSESSION_CHANGE once it has called
// WTSRegisterSessionNotification (wParam WTS_SESSION_LOCK, WTS_SESSION_LOGOFF),
// and WM_POWERBROADCAST (wParam PBT_APMSUSPEND) once it has called
// RegisterSuspendResumeNotification with a window handle. A message-only window
// receives both: they are sent to the registered window, not broadcast.

// Window messages and their wParam values (winuser.h, wtsapi32.h).
const (
	wmClose            = 0x0010
	wmDestroy          = 0x0002
	wmPowerBroadcast   = 0x0218
	wmWTSSessionChange = 0x02B1

	wtsSessionLogoff = 0x6
	wtsSessionLock   = 0x7
	pbtAPMSuspend    = 0x4
)

// reasonOf says what a window message means to the container: "lock", "sleep",
// "shutdown" (the session logs off), or "" for anything else.
func reasonOf(msg uint32, wParam uintptr) string {
	switch {
	case msg == wmWTSSessionChange && wParam == wtsSessionLock:
		return "lock"
	case msg == wmWTSSessionChange && wParam == wtsSessionLogoff:
		return "shutdown"
	case msg == wmPowerBroadcast && wParam == pbtAPMSuspend:
		return "sleep"
	}
	return ""
}

// nativeWindow is a hidden message-only window, as the Win32 calls make it. All
// its methods run on the thread that created it, except Stop.
type nativeWindow interface {
	// Register subscribes the window to the session and the power
	// notifications.
	Register() error
	// Pump runs the message loop until Stop.
	Pump() error
	// Stop ends the loop; any thread may call it.
	Stop()
	// Destroy releases the window.
	Destroy()
}

// createWindow makes a window whose messages go to handle.
type createWindow func(handle func(msg uint32, wParam uintptr)) (nativeWindow, error)

// watchWindow runs the window and its message loop on a goroutine locked to one
// OS thread (a window belongs to the thread that made it), and returns once the
// subscriptions are in place: a window that could not be made or registered is
// an error, which the caller treats as "no lock detection" and fails closed. The
// returned channel receives one reason per lock, sleep or logoff and is closed
// when ctx ends.
func watchWindow(ctx context.Context, create createWindow) (<-chan string, error) {
	out := make(chan string, 1)
	var w nativeWindow
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(out)
		var err error
		w, err = create(func(msg uint32, wParam uintptr) {
			if r := reasonOf(msg, wParam); r != "" {
				select {
				case out <- r:
				default: // one reason is waiting already
				}
			}
		})
		if err != nil {
			ready <- fmt.Errorf("window: %w", err)
			return
		}
		defer w.Destroy()
		if err := w.Register(); err != nil {
			ready <- fmt.Errorf("register: %w", err)
			return
		}
		ready <- nil
		if err := w.Pump(); err != nil {
			Logf("lockwatch: message loop ended: %v", err)
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	Logf("lockwatch: Windows session and power notifications")
	go func() {
		<-ctx.Done()
		w.Stop()
	}()
	return out, nil
}
