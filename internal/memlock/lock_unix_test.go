//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package memlock

import (
	"testing"
	"unsafe"
)

// The real system calls, on one page: a refusal by the host's RLIMIT_MEMLOCK
// is not a defect of this package, but a success must lock and unlock cleanly.
func TestTheRealSystemCalls(t *testing.T) {
	b, _ := block(1)
	if err := lockRange(unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
		t.Skipf("this host refuses mlock of one page: %v", err)
	}
	unlockRange(unsafe.Pointer(&b[0]), uintptr(len(b)))
	r, err := Lock(unsafe.Pointer(&b[0]), 16) // the default seams, end to end
	if err != nil || r == nil {
		t.Fatalf("%v %v", r, err)
	}
	r.Release()
}
