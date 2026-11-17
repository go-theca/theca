package theca

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// RebindFor moves a container to a new counter after the old one is gone.
func TestRebindFor(t *testing.T) {
	old := &fakeCounter{handle: 0x01500000, name: bytes.Repeat([]byte{1}, 34), v: 500}
	geo, _ := format.NewGeometry(testSectors, testJournal)
	f := newMem(int(geo.End))
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal,
		Password: []byte("pw"), Counter: old})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	u := Unlock{Password: []byte("pw")}

	// The old counter is gone: the ordinary open refuses, whatever it is given.
	gone := errors.New("no such index")
	if _, err := Open(ctx, f, u, OpenOptions{CounterFor: func(uint32, []byte) (Counter, error) { return nil, gone }}); !errors.Is(err, gone) {
		t.Fatalf("open with a missing counter: %v", err)
	}
	if _, err := Open(ctx, f, u, OpenOptions{AcceptRollback: true}); !errors.Is(err, ErrCounter) {
		t.Fatalf("AcceptRollback does not replace a missing counter: %v", err)
	}

	// Rebind to a fresh counter whose value is lower than the old bound.
	fresh := &fakeCounter{handle: 0x01500001, name: bytes.Repeat([]byte{2}, 34), v: 3}
	var gotH uint32
	var gotN []byte
	r, err := Open(ctx, f, u, OpenOptions{RebindFor: func(h uint32, n []byte) (Counter, error) {
		gotH, gotN = h, n
		return fresh, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if gotH != 0x01500000 || !bytes.Equal(gotN, old.name) {
		t.Fatalf("RebindFor was given %#x %x, not the recorded counter", gotH, gotN)
	}
	if fresh.v != 4 || r.Info().CounterHandle != 0x01500001 || !r.Info().RollbackProtected {
		t.Fatalf("after rebind: counter %d, info %+v", fresh.v, r.Info())
	}
	r.Close()

	// From now on it is the new counter that protects it, and the old one no longer opens it.
	op := OpenOptions{Counter: fresh}
	s1, err := Open(ctx, f, u, op)
	if err != nil {
		t.Fatalf("mount with the new counter: %v", err)
	}
	s1.Close()
	snapshot := f.clone()
	s2, err := Open(ctx, f, u, op)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
	if _, err := Open(ctx, snapshot, u, op); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older copy under the new counter: %v", err)
	}
	if _, err := Open(ctx, f, u, OpenOptions{Counter: old}); !errors.Is(err, ErrCounter) {
		t.Fatalf("the old counter after a rebind: %v", err)
	}

	// Errors: the replacement cannot be made, cannot increment, cannot read.
	boom := errors.New("tpm unreachable")
	if _, err := Open(ctx, f, u, OpenOptions{RebindFor: func(uint32, []byte) (Counter, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Fatalf("RebindFor error: %v", err)
	}
	bad := &fakeCounter{handle: 9, name: []byte("n"), failInc: true}
	if _, err := Open(ctx, f, u, OpenOptions{RebindFor: func(uint32, []byte) (Counter, error) { return bad, nil }}); err == nil {
		t.Fatal("a counter that cannot increment")
	}
	unread := &readFails{fakeCounter{handle: 9, name: []byte("n")}}
	if _, err := Open(ctx, f, u, OpenOptions{RebindFor: func(uint32, []byte) (Counter, error) { return unread, nil }}); err == nil {
		t.Fatal("a counter that cannot be read")
	}

	// A container with no counter can be given one.
	f2 := newMem(int(geo.End))
	c2, _, err := Create(f2, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	var zeroH uint32 = 1
	third := &fakeCounter{handle: 0x01500002, name: bytes.Repeat([]byte{3}, 34), v: 7}
	r2, err := Open(ctx, f2, u, OpenOptions{RebindFor: func(h uint32, n []byte) (Counter, error) {
		zeroH = h
		if n != nil {
			t.Fatalf("a name %x for a container with no counter", n)
		}
		return third, nil
	}})
	if err != nil || zeroH != 0 || !r2.Info().RollbackProtected {
		t.Fatalf("rebind of an unprotected container: %v %d", err, zeroH)
	}
	r2.Close()
}

// readFails is a counter whose value cannot be read.
type readFails struct{ fakeCounter }

func (readFails) Read() (uint64, error) { return 0, errors.New("read failed") }
