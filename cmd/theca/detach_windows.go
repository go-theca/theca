//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// The Win32 calls, replaced by tests.
var (
	freeConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole")
	lockFileEx  = windows.LockFileEx
)

// detachStdio cuts the process loose from the console that started it. Called
// once the container is open and the parent has been told. `theca open` starts
// this process with the console (so that a PIN prompt reaches the person) and in a
// process group of its own; FreeConsole lets go of the console, so that closing
// the window, or the end of an ssh session, no longer sends it a control event. A
// process that has no console (FreeConsole fails) is as detached as it gets.
func detachStdio() error {
	freeConsole.Call()
	return nullStreams(stdStreams()...)
}

// lockOffsetHigh puts the locked byte at 0x7FFFFFFF00000000, far beyond the end
// of any container: LockFileEx admits a region past the end of the file, and a
// byte-range lock on Windows is mandatory, so a lock on a real byte would stop
// this very process from reading the container through its other handle.
const lockOffsetHigh = 0x7FFFFFFF

// lockContainer takes an exclusive lock (LockFileEx, LOCKFILE_FAIL_IMMEDIATELY)
// on a byte beyond the end of the container file for the life of the process; the
// system releases it when the handle closes or the process dies.
func lockContainer(path string) (func(), error) {
	return lockContainerWith(path, func(f *os.File) error {
		ol := &windows.Overlapped{OffsetHigh: lockOffsetHigh}
		return lockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	}, func(err error) bool { return errors.Is(err, windows.ERROR_LOCK_VIOLATION) })
}
