//go:build unix

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// Seams the tests replace.
var (
	devNull = os.DevNull
	flock   = syscall.Flock
)

// detachStdio cuts the process loose from the terminal that started it. Called
// once the container is open and the parent has been told.
func detachStdio() error { return detachTo(&os.Stdin, &os.Stdout, &os.Stderr) }

// detachTo ignores the hang-up, starts a session of its own, and points each
// stream at /dev/null, closing what it held.
func detachTo(streams ...**os.File) error {
	signal.Ignore(syscall.SIGHUP)
	// EPERM means this process already leads a session, which is as detached as
	// it gets; no other error is possible here.
	syscall.Setsid()
	null, err := os.OpenFile(devNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	for _, s := range streams {
		old := *s
		*s = null
		old.Close()
	}
	return nil
}

// lockContainer takes an exclusive advisory lock on the container file for the
// life of the process, before anything is unlocked: a second open of the same
// container is refused here, and does not touch the rollback counter.
func lockContainer(path string) (func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("this container is already open in another theca process")
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
