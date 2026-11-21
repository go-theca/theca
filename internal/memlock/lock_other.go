//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package memlock

import (
	"errors"
	"unsafe"
)

func lockRange(unsafe.Pointer, uintptr) error { return errors.ErrUnsupported }

func unlockRange(unsafe.Pointer, uintptr) {}
