//go:build windows

package lockwatch

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-mswin/win32"
	"golang.org/x/sys/windows"
)

// notifyForThisSession: only the notifications of the session the window lives
// in (NOTIFY_FOR_THIS_SESSION); deviceNotifyWindowHandle: hRecipient is a window.
const (
	notifyForThisSession     = 0
	deviceNotifyWindowHandle = 0
)

var (
	wtsapi32                    = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSRegister             = wtsapi32.NewProc("WTSRegisterSessionNotification")
	procWTSUnregister           = wtsapi32.NewProc("WTSUnRegisterSessionNotification")
	procRegisterSuspendResume   = win32.User32.NewProc("RegisterSuspendResumeNotification")
	procUnregisterSuspendResume = win32.User32.NewProc("UnregisterSuspendResumeNotification")
	wndProcOnce                 sync.Once
	wndProcPtr                  uintptr
	classSeq                    atomic.Uint32
	windowsMu                   sync.Mutex
	windowsByHandle             = map[win32.HWND]*realWindow{}
)

func watch(ctx context.Context) (<-chan string, error) {
	return watchWindow(ctx, newRealWindow)
}

// realWindow is a message-only window with the two subscriptions.
type realWindow struct {
	mw     *win32.MessageWindow
	handle func(msg uint32, wParam uintptr)

	mu    sync.Mutex
	wts   bool
	power uintptr
}

// newRealWindow creates the window, on the calling (locked) thread.
func newRealWindow(handle func(msg uint32, wParam uintptr)) (nativeWindow, error) {
	wndProcOnce.Do(func() { wndProcPtr = win32.NewCallback(wndProc) })
	mw, err := win32.NewMessageWindow(fmt.Sprintf("theca-lockwatch-%d", classSeq.Add(1)), wndProcPtr)
	if err != nil {
		return nil, err
	}
	w := &realWindow{mw: mw, handle: handle}
	windowsMu.Lock()
	windowsByHandle[mw.Hwnd] = w
	windowsMu.Unlock()
	return w, nil
}

// Hwnd is the window's handle (tests post messages to it).
func (w *realWindow) Hwnd() win32.HWND { return w.mw.Hwnd }

func (w *realWindow) Register() error {
	r, _, err := procWTSRegister.Call(uintptr(w.mw.Hwnd), notifyForThisSession)
	if r == 0 {
		return fmt.Errorf("WTSRegisterSessionNotification: %w", err)
	}
	w.mu.Lock()
	w.wts = true
	w.mu.Unlock()
	h, _, err := procRegisterSuspendResume.Call(uintptr(w.mw.Hwnd), deviceNotifyWindowHandle)
	if h == 0 {
		return fmt.Errorf("RegisterSuspendResumeNotification: %w", err)
	}
	w.mu.Lock()
	w.power = h
	w.mu.Unlock()
	return nil
}

// unregister drops both subscriptions; WTSUnRegisterSessionNotification must
// come before the window is destroyed.
func (w *realWindow) unregister() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wts {
		procWTSUnregister.Call(uintptr(w.mw.Hwnd))
		w.wts = false
	}
	if w.power != 0 {
		procUnregisterSuspendResume.Call(w.power)
		w.power = 0
	}
}

func (w *realWindow) Pump() error { return win32.Pump() }

// Stop asks the window to close (WM_CLOSE); the loop ends when it is destroyed.
func (w *realWindow) Stop() { win32.PostMessage(w.mw.Hwnd, wmClose, 0, 0) }

func (w *realWindow) Destroy() {
	w.unregister()
	windowsMu.Lock()
	delete(windowsByHandle, w.mw.Hwnd)
	windowsMu.Unlock()
	w.mw.Destroy()
}

// wndProc is the one window procedure of the class: it hands the message to the
// window's handler, unregisters before a close, and ends the loop with the window.
func wndProc(hwnd win32.HWND, msg uint32, wParam win32.WPARAM, lParam win32.LPARAM) win32.LRESULT {
	windowsMu.Lock()
	w := windowsByHandle[hwnd]
	windowsMu.Unlock()
	if w != nil {
		switch msg {
		case wmClose:
			w.unregister()
		case wmDestroy:
			win32.PostQuitMessage(0)
		}
		w.handle(msg, uintptr(wParam))
	}
	return win32.DefWindowProc(hwnd, msg, wParam, lParam)
}
