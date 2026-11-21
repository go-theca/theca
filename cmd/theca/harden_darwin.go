package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// The system calls, replaced by tests.
var (
	setrlimit  = unix.Setrlimit
	denyAttach = unix.PtraceDenyAttach
)

// hardenPlatform removes the core file (RLIMIT_CORE 0) and refuses debuggers
// (PT_DENY_ATTACH: a later attach fails, and a debugger already attached is
// ended). Both are tried; the errors are joined.
func hardenPlatform() error {
	return errors.Join(
		setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}),
		denyAttach(),
	)
}
