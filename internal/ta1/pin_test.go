package ta1

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"unsafe"

	"github.com/go-authn/harden/memlock"
	"github.com/go-theca/theca/internal/pin"
)

func refuse(t *testing.T, at int) *int {
	t.Helper()
	calls := new(int)
	restore := pin.SetLocker(memlock.NewLocker(memlock.Syscalls{
		Lock: func(unsafe.Pointer, uintptr) error {
			*calls++
			if at == 0 || *calls == at {
				return errors.New("operation not permitted")
			}
			return nil
		},
		Unlock: func(unsafe.Pointer, uintptr) {},
	}, uintptr(os.Getpagesize())))
	pin.SetMode(pin.Required)
	t.Cleanup(func() { restore(); pin.SetMode(pin.BestEffort) })
	return calls
}

func TestGenerateAndFromBytesFailWhenTheKeysCannotBePinned(t *testing.T) {
	refuse(t, 0)
	if k, err := Generate(bytes.NewReader(make([]byte, 96))); err == nil || k != nil {
		t.Fatalf("Generate: %v %v", k, err)
	}
	if k, err := FromBytes(make([]byte, MSSize)); err == nil || k != nil {
		t.Fatalf("FromBytes: %v %v", k, err)
	}
}

// The cache is a second region: when only it is refused, the first is given back.
func TestPinReleasesTheKeysWhenTheCacheIsRefused(t *testing.T) {
	// Far apart, so the two regions cannot share a page.
	s := new(struct {
		k   Keys
		pad [1 << 17]byte
		c   cache
	})
	s.k.c = &s.c
	calls := refuse(t, 2)
	if err := s.k.pin(); err == nil {
		t.Fatal("pin ignored the refusal of the cache")
	}
	if *calls != 2 || s.k.mem[0] != nil {
		t.Fatalf("%d calls, mem[0]=%v: the keys' region was not released", *calls, s.k.mem[0])
	}
}

// A refusal of the keys' own region is an error even when the cache's is not.
func TestPinFailsWhenOnlyTheKeysAreRefused(t *testing.T) {
	s := new(struct {
		k   Keys
		pad [1 << 17]byte
		c   cache
	})
	s.k.c = &s.c
	refuse(t, 1)
	if err := s.k.pin(); err == nil {
		t.Fatal("pin ignored the refusal of the keys")
	}
	if s.k.mem[1] != nil {
		t.Fatal("the cache was locked after the keys were refused")
	}
}

func TestZeroizeReleasesTheRegions(t *testing.T) {
	pin.SetMode(pin.BestEffort)
	k, err := FromBytes(make([]byte, MSSize))
	if err != nil {
		t.Fatal(err)
	}
	k.Zeroize()
	if k.mem != [2]*memlock.Region{} {
		t.Fatal("Zeroize kept the regions")
	}
}
