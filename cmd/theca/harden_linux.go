package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// The system calls, replaced by tests.
var (
	setrlimit = unix.Setrlimit
	prctl     = unix.Prctl
)

// hardenPlatform removes the core file (RLIMIT_CORE 0) and makes the process
// undumpable (PR_SET_DUMPABLE 0: no core file whatever the limit, and
// /proc/PID/mem, ptrace and process_vm_readv refused to a process of the same
// user). Both are tried; the errors are joined.
func hardenPlatform() error {
	return errors.Join(
		setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}),
		prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0),
	)
}
