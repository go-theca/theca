//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package memlock

import (
	"errors"
	"testing"
)

func TestThereIsNoMlockHere(t *testing.T) {
	b, _ := block(1)
	if err := lockRange(nil, 0); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("lockRange: %v", err)
	}
	unlockRange(nil, 0)
	_ = b
}
