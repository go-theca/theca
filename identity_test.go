package theca

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// idCounter is a fakeCounter that names its TPM, and counts its reads.
type idCounter struct {
	fakeCounter
	id    []byte
	idErr error
	reads int
}

func (c *idCounter) Identity() ([]byte, error) { return c.id, c.idErr }
func (c *idCounter) Read() (uint64, error)     { c.reads++; return c.v, nil }

func tpmID(b byte) []byte { return bytes.Repeat([]byte{b}, IDSize) }

func newIDCounter(id byte, v uint64) *idCounter {
	return &idCounter{fakeCounter: fakeCounter{handle: 0x01800001, name: bytes.Repeat([]byte{9}, 34), v: v}, id: tpmID(id)}
}

func mkContainer(t *testing.T, ctr Counter) *memFile {
	t.Helper()
	geo, _ := format.NewGeometry(testSectors, testJournal)
	f := newMem(int(geo.End))
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal,
		Password: []byte("pw"), Counter: ctr})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	return f
}

func TestIdentityPinnedAtCreateAndCheckedAtMount(t *testing.T) {
	a := newIDCounter(0xA1, 1000)
	f := mkContainer(t, a)
	u := Unlock{Password: []byte("pw")}

	// The same TPM opens it, any number of times: the mount rewrites the
	// header and must carry the pin along.
	for i := 0; i < 3; i++ {
		c, err := Open(ctx, f, u, OpenOptions{Counter: a})
		if err != nil {
			t.Fatalf("mount %d: %v", i, err)
		}
		if !bytes.Equal(c.Info().CounterTPM, tpmID(0xA1)) {
			t.Fatalf("mount %d: Info.CounterTPM %x", i, c.Info().CounterTPM)
		}
		c.Close()
	}

	// Another TPM with the same handle, the same Name and the same value: the
	// attack of go-theca/theca#39. Refused, naming both, before the value is read.
	b := newIDCounter(0xB2, a.v)
	b.name = a.name
	_, err := Open(ctx, f, u, OpenOptions{Counter: b})
	if !errors.Is(err, ErrCounterIdentity) {
		t.Fatalf("another TPM: %v", err)
	}
	if !strings.Contains(err.Error(), ShortID(tpmID(0xA1))) || !strings.Contains(err.Error(), ShortID(tpmID(0xB2))) {
		t.Fatalf("the refusal names neither identity: %v", err)
	}
	if b.reads != 0 {
		t.Fatalf("the counter of another TPM was read %d times before it was refused", b.reads)
	}
	// AcceptRollback is about the value, not about whose TPM it is.
	if _, err := Open(ctx, f, u, OpenOptions{Counter: b, AcceptRollback: true}); !errors.Is(err, ErrCounterIdentity) {
		t.Fatalf("AcceptRollback with another TPM: %v", err)
	}
	// The same through CounterFor, as the CLI opens it.
	if _, err := Open(ctx, f, u, OpenOptions{CounterFor: func(uint32, []byte) (Counter, error) { return b, nil }}); !errors.Is(err, ErrCounterIdentity) {
		t.Fatalf("CounterFor: %v", err)
	}

	// A counter that cannot say which TPM it is on, a TPM that fails to say,
	// and one that answers a wrong size: all refused, never read as "no pin".
	plain := &fakeCounter{handle: a.handle, name: a.name, v: a.v}
	broken := newIDCounter(0xA1, a.v)
	broken.name, broken.idErr = a.name, errors.New("endorsement auth set")
	short := newIDCounter(0xA1, a.v)
	short.name, short.id = a.name, []byte{1, 2, 3}
	for name, c := range map[string]struct {
		ctr  Counter
		want string
	}{
		"not identified": {plain, "cannot report its TPM identity"},
		"identity error": {broken, "reading the TPM identity"},
		"wrong size":     {short, "3 bytes, want 32"},
	} {
		_, err := Open(ctx, f, u, OpenOptions{Counter: c.ctr})
		if !errors.Is(err, ErrCounterIdentity) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if !strings.Contains(func() string { _, e := Open(ctx, f, u, OpenOptions{Counter: broken}); return e.Error() }(), "endorsement auth set") {
		t.Error("the reason the TPM gave is lost")
	}
	// None of that disturbed the container: its own TPM still opens it.
	if c, err := Open(ctx, f, u, OpenOptions{Counter: a}); err != nil {
		t.Fatalf("after the refusals: %v", err)
	} else {
		c.Close()
	}
}

func TestCreateWithoutAnIdentityMovesNothing(t *testing.T) {
	geo, _ := format.NewGeometry(testSectors, testJournal)
	for name, mk := range map[string]func() *idCounter{
		"error": func() *idCounter { c := newIDCounter(1, 5); c.idErr = errors.New("no EK"); return c },
		"size":  func() *idCounter { c := newIDCounter(1, 5); c.id = []byte{1}; return c },
	} {
		ctr := mk()
		_, _, err := Create(newMem(int(geo.End)), CreateOptions{Sectors: testSectors, JournalEntries: testJournal,
			Password: []byte("pw"), Counter: ctr})
		if !errors.Is(err, ErrCounterIdentity) {
			t.Errorf("%s: %v", name, err)
		}
		if ctr.v != 5 {
			t.Errorf("%s: the counter moved to %d before the identity was known", name, ctr.v)
		}
	}
}

// A container made before the pin opens, with no identity, and the mount does
// not pin it: only a rebind does.
func TestOldFormatContainerOpensUnpinned(t *testing.T) {
	plain := &fakeCounter{handle: 0x01800001, name: bytes.Repeat([]byte{9}, 34), v: 50}
	f := mkContainer(t, plain)
	u := Unlock{Password: []byte("pw")}
	a := &idCounter{fakeCounter: *plain, id: tpmID(0xA1)}

	for i, ctr := range []Counter{plain, a} {
		a.v = plain.v // the two stand for one counter
		c, err := Open(ctx, f, u, OpenOptions{Counter: ctr})
		if err != nil {
			t.Fatalf("%T: %v", ctr, err)
		}
		if c.Info().CounterTPM != nil || !c.Info().RollbackProtected {
			t.Fatalf("%T: info %+v", ctr, c.Info())
		}
		c.Close()
		if i == 1 {
			plain.v = a.v
		}
	}

	// Rebind pins the identity it is given.
	fresh := newIDCounter(0xC3, 3)
	fresh.handle = 0x01800002
	r, err := Open(ctx, f, u, OpenOptions{RebindFor: func(uint32, []byte) (Counter, error) { return fresh, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Info().CounterTPM, tpmID(0xC3)) {
		t.Fatalf("rebind pinned %x", r.Info().CounterTPM)
	}
	r.Close()
	// ... and from then on another TPM is refused.
	other := newIDCounter(0xD4, fresh.v)
	other.handle, other.name = fresh.handle, fresh.name
	if _, err := Open(ctx, f, u, OpenOptions{Counter: other}); !errors.Is(err, ErrCounterIdentity) {
		t.Fatalf("after the rebind: %v", err)
	}
	// A rebind to a counter that cannot name its TPM leaves the header unpinned,
	// as it was; one whose TPM fails to answer is refused.
	again := &fakeCounter{handle: 0x01800003, name: []byte("n"), v: 1}
	r, err = Open(ctx, f, u, OpenOptions{RebindFor: func(uint32, []byte) (Counter, error) { return again, nil }})
	if err != nil || r.Info().CounterTPM != nil {
		t.Fatalf("rebind to a plain counter: %v %+v", err, r)
	}
	r.Close()
	bad := newIDCounter(1, 1)
	bad.idErr = errors.New("no EK")
	if _, err := Open(ctx, f, u, OpenOptions{RebindFor: func(uint32, []byte) (Counter, error) { return bad, nil }}); !errors.Is(err, ErrCounterIdentity) {
		t.Fatalf("rebind with a TPM that cannot name itself: %v", err)
	}
}

func TestShortID(t *testing.T) {
	if got := ShortID(tpmID(0xAB)); got != "abababababab" {
		t.Fatal(got)
	}
	if got := ShortID([]byte{1, 2}); got != "0102" {
		t.Fatal(got)
	}
	if got := ShortID(nil); got != "" {
		t.Fatal(got)
	}
}
