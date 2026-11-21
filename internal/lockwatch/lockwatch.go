// Package lockwatch tells the process that holds an unlocked container when the
// person has stepped away: the screen locked, the machine is going to sleep, the
// session is ending. The caller then closes the container.
//
// Linux asks logind over D-Bus (Session.Lock, LockedHint, PrepareForSleep,
// PrepareForShutdown). macOS listens for com.apple.screenIsLocked
// (NSDistributedNotificationCenter), NSWorkspaceWillSleepNotification and
// NSWorkspaceSessionDidResignActiveNotification (go-macos/objc), which arrive
// before the sleep and without polling lag; they are delivered on the main
// thread's run loop, which the caller runs (objc.RunMainLoop). It proves the
// observers with a notification of its own, and when they cannot be registered
// or heard it falls back to reading the session's CGSSessionScreenIsLocked every
// 2 s and noticing a sleep as a gap between the wall clock and the monotonic
// clock. Other systems have no source: Watch says ErrUnsupported and the caller says so.
package lockwatch

import "errors"

// ErrUnsupported is returned where no lock or sleep source is implemented.
var ErrUnsupported = errors.New("lockwatch: no screen-lock or sleep notification on this system")

// Logf says which detection mode is active (notifications or polling). The
// caller points it at the person's terminal; it is silent by default.
var Logf = func(format string, args ...any) {}

// Watch returns a channel that receives one reason ("lock", "sleep",
// "shutdown") when the person has gone, and is closed when ctx ends. Replaced
// by tests.
var Watch = watch
