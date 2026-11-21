package format

import (
	"crypto/rand"
	"errors"
	"testing"
	"unsafe"

	"github.com/go-theca/theca/internal/memlock"
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
	restore := memlock.SetSyscalls(func(unsafe.Pointer, uintptr) error { return errors.New("operation not permitted") },
		func(unsafe.Pointer, uintptr) {})
	memlock.SetMode(memlock.Required)
	defer func() { restore(); memlock.SetMode(memlock.BestEffort) }()
	if _, err := SealWrap(ms, &kek, 0, rand.Reader); err == nil {
		t.Fatal("SealWrap ignored the refusal")
	}
	if _, err := OpenWrap(&kek, 0, blob); err == nil {
		t.Fatal("OpenWrap ignored the refusal")
	}
}
