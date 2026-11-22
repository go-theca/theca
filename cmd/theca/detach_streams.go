package main

import (
	"errors"
	"os"
)

// The parts of detaching and of the container lock that every system shares;
// detach_unix.go and detach_windows.go supply the system calls.

// devNull is the file the standard streams are pointed at; tests replace it.
var devNull = os.DevNull

// stdStreams are the process's standard streams; tests point it elsewhere.
var stdStreams = func() []**os.File { return []**os.File{&os.Stdin, &os.Stdout, &os.Stderr} }

// nullStreams points each stream at the null device, closing what it held.
func nullStreams(streams ...**os.File) error {
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

// errBusy is what lockContainerWith says when another process holds the lock.
var errBusy = errors.New("this container is already open in another theca process")

// lockContainerWith opens the container file and takes an exclusive lock on it
// through try, for the life of the process, before anything is unlocked: a second
// open of the same container is refused here, and does not touch the rollback
// counter. busy says whether try's error means "someone else holds it".
func lockContainerWith(path string, try func(*os.File) error, busy func(error) bool) (func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := try(f); err != nil {
		f.Close()
		if busy(err) {
			return nil, errBusy
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
