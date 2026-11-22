package format

import (
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"unsafe"

	"github.com/go-authn/harden/memlock"
	"github.com/go-theca/theca/internal/pin"
	"github.com/go-theca/theca/internal/ta1"
)

// Under --mlock=required the wrap key that cannot be pinned is an error from
// both directions of the slot wrap.
func TestWrapReportsARefusedLock(t *testing.T) {
	ms, err := ta1.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var kek [32]byte
	blob, err := SealWrap(ms, &kek, 0, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restore := pin.SetLocker(memlock.NewLocker(memlock.Syscalls{
		Lock:   func(unsafe.Pointer, uintptr) error { return errors.New("operation not permitted") },
		Unlock: func(unsafe.Pointer, uintptr) {},
	}, uintptr(os.Getpagesize())))
	pin.SetMode(pin.Required)
	defer func() { restore(); pin.SetMode(pin.BestEffort) }()
	if _, err := SealWrap(ms, &kek, 0, rand.Reader); err == nil {
		t.Fatal("SealWrap ignored the refusal")
	}
	if _, err := OpenWrap(&kek, 0, blob); err == nil {
		t.Fatal("OpenWrap ignored the refusal")
	}
}
