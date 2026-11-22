// Package lockwatch tells the process that holds an unlocked container when the
// person has stepped away: the screen locked, the machine is going to sleep, the
// session is ending. The caller then closes the container.
//
// Linux asks logind over D-Bus (Session.Lock, LockedHint, PrepareForSleep,
// PrepareForShutdown). macOS is go-macos/sessionwatch (screen-lock, sleep and
// session notifications on the main thread's run loop, which the caller runs
// with objc.RunMainLoop, and a polling fallback). Windows listens to session
// and power notifications. Other systems have no source: Watch says
// ErrUnsupported and the caller says so.
package lockwatch

import (
	"errors"
	"fmt"
	"io"
)

// ErrUnsupported is returned where no lock or sleep source is implemented.
var ErrUnsupported = errors.New("lockwatch: no screen-lock or sleep notification on this system")

// Logf says which detection mode is active (notifications or polling). The
// caller points it at the person's terminal; it is silent by default.
var Logf = func(format string, args ...any) {}

// LogTo makes Logf write one line per message to w.
func LogTo(w io.Writer) {
	Logf = func(format string, args ...any) {
		fmt.Fprintf(w, format+"\n", args...)
	}
}

// Watch returns a channel that receives one reason ("lock", "sleep",
// "shutdown") when the person has gone, and is closed when ctx ends. Replaced
// by tests.
var Watch = watch
