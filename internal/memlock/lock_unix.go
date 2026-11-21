//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package memlock

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func lockRange(p unsafe.Pointer, n uintptr) error {
	return unix.Mlock(unsafe.Slice((*byte)(p), n))
}

func unlockRange(p unsafe.Pointer, n uintptr) {
	_ = unix.Munlock(unsafe.Slice((*byte)(p), n))
}
