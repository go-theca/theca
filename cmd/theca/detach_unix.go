//go:build unix

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// flock is the seam the tests replace.
var flock = syscall.Flock

// detachStdio cuts the process loose from the terminal that started it. Called
// once the container is open and the parent has been told.
func detachStdio() error { return detachTo(stdStreams()...) }

// detachTo ignores the hang-up, starts a session of its own, and points each
// stream at /dev/null, closing what it held.
func detachTo(streams ...**os.File) error {
	signal.Ignore(syscall.SIGHUP)
	// EPERM means this process already leads a session, which is as detached as
	// it gets; no other error is possible here.
	syscall.Setsid()
	return nullStreams(streams...)
}

// lockContainer takes an exclusive advisory lock on the container file for the
// life of the process (flock).
func lockContainer(path string) (func(), error) {
	return lockContainerWith(path, func(f *os.File) error {
		return flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}, func(err error) bool { return errors.Is(err, syscall.EWOULDBLOCK) })
}
