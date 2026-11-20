// Package lockwatch tells the process that holds an unlocked container when the
// person has stepped away: the screen locked, the machine is going to sleep, the
// session is ending. The caller then closes the container.
//
// Linux asks logind over D-Bus (Session.Lock, LockedHint, PrepareForSleep,
// PrepareForShutdown). macOS reads the session's CGSSessionScreenIsLocked and
// notices a sleep as a gap between the wall clock and the monotonic clock (the
// latter stops while the machine sleeps); no run loop, no Objective-C. Other
// systems have no source: Watch says ErrUnsupported and the caller says so.
package lockwatch

import "errors"

// ErrUnsupported is returned where no lock or sleep source is implemented.
var ErrUnsupported = errors.New("lockwatch: no screen-lock or sleep notification on this system")

// Watch returns a channel that receives one reason ("lock", "sleep",
// "shutdown") when the person has gone, and is closed when ctx ends. Replaced
// by tests.
var Watch = watch
