package theca

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// A counter whose authValue is derived from the master secret (DESIGN 5.4.2):
// Create hands the derived value to NewCounter, the header records it, a mount
// hands the SAME value (found only by unlocking) to CounterDerived, a wrong
// password gets none, and a rebind can move a stored-auth container to a derived
// one.
func TestDerivedCounterAuth(t *testing.T) {
	geo, _ := format.NewGeometry(testSectors, testJournal)
	f := newMem(int(geo.End))
	ctr := &fakeCounter{handle: 0x01500000, name: bytes.Repeat([]byte{7}, 34), v: 10}
	var made []byte
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"),
		NewCounter: func(auth []byte) (Counter, error) {
			made = append([]byte(nil), auth...)
			return ctr, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Info().CounterDerivedAuth || !c.Info().RollbackProtected || len(made) != 32 || made[31] == 0 {
		t.Fatalf("info %+v auth %x", c.Info(), made)
	}
	c.Close()
	u := Unlock{Password: []byte("pw")}

	// The mount is given the same value, and not through CounterFor.
	var got []byte
	r, err := Open(ctx, f, u, OpenOptions{
		CounterFor: func(uint32, []byte) (Counter, error) {
			t.Fatal("CounterFor asked for a derived counter")
			return nil, nil
		},
		CounterDerived: func(h uint32, n, auth []byte) (Counter, error) {
			got = append([]byte(nil), auth...)
			return ctr, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, made) || !r.Info().CounterDerivedAuth {
		t.Fatalf("mount got %x, create gave %x", got, made)
	}
	r.Close()

	// A container whose counter is derived and a caller with no CounterDerived:
	// refused, not opened with a guessed authValue.
	if _, err := Open(ctx, f, u, OpenOptions{CounterFor: func(uint32, []byte) (Counter, error) { return ctr, nil }}); !errors.Is(err, ErrCounter) {
		t.Fatalf("no CounterDerived: %v", err)
	}
	// A wrong password never reaches the callback.
	if _, err := Open(ctx, f, Unlock{Password: []byte("no")}, OpenOptions{CounterDerived: func(uint32, []byte, []byte) (Counter, error) {
		t.Fatal("asked with a wrong password")
		return nil, nil
	}}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("wrong password: %v", err)
	}
	// The callback's error refuses the open.
	boom := errors.New("tpm unreachable")
	if _, err := Open(ctx, f, u, OpenOptions{CounterDerived: func(uint32, []byte, []byte) (Counter, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Fatalf("callback error: %v", err)
	}
	// NewCounter's error refuses the create.
	if _, _, err := Create(newMem(int(geo.End)), CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"),
		NewCounter: func([]byte) (Counter, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Fatalf("NewCounter error: %v", err)
	}

	// Another container, another derived value.
	f2 := newMem(int(geo.End))
	var made2 []byte
	c2, _, err := Create(f2, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"),
		NewCounter: func(auth []byte) (Counter, error) {
			made2 = append([]byte(nil), auth...)
			return &fakeCounter{handle: 0x01500001, name: bytes.Repeat([]byte{8}, 34), v: 1}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	if bytes.Equal(made, made2) {
		t.Fatal("two containers, one derived authValue")
	}

	// Migration: a container with a stored-auth counter is rebound to a derived one.
	f3 := newMem(int(geo.End))
	old := &fakeCounter{handle: 0x01500002, name: bytes.Repeat([]byte{9}, 34), v: 3}
	c3, _, err := Create(f3, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"), Counter: old})
	if err != nil {
		t.Fatal(err)
	}
	if c3.Info().CounterDerivedAuth {
		t.Fatal("a caller-made counter is not derived")
	}
	c3.Close()
	fresh := &fakeCounter{handle: 0x01500003, name: bytes.Repeat([]byte{4}, 34), v: 0}
	var seenH uint32
	var rauth []byte
	r3, err := Open(ctx, f3, u, OpenOptions{RebindDerived: func(h uint32, _ []byte, auth []byte) (Counter, error) {
		seenH, rauth = h, append([]byte(nil), auth...)
		return fresh, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if seenH != 0x01500002 || len(rauth) != 32 || !r3.Info().CounterDerivedAuth || r3.Info().CounterHandle != 0x01500003 {
		t.Fatalf("rebind: handle %#x auth %x info %+v", seenH, rauth, r3.Info())
	}
	r3.Close()
	// And the next mount is a derived one, with the value the rebind was given.
	r4, err := Open(ctx, f3, u, OpenOptions{CounterDerived: func(_ uint32, _ []byte, auth []byte) (Counter, error) {
		if !bytes.Equal(auth, rauth) {
			t.Errorf("mount auth %x, rebind auth %x", auth, rauth)
		}
		return fresh, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	r4.Close()
	// RebindFor wins over RebindDerived, and RebindDerived's error refuses.
	if _, err := Open(ctx, f3, u, OpenOptions{RebindDerived: func(uint32, []byte, []byte) (Counter, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Fatalf("rebind error: %v", err)
	}
	r5, err := Open(ctx, f3, u, OpenOptions{
		RebindFor:     func(uint32, []byte) (Counter, error) { return &fakeCounter{handle: 5, name: []byte("n"), v: 0}, nil },
		RebindDerived: func(uint32, []byte, []byte) (Counter, error) { t.Fatal("RebindDerived asked"); return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if r5.Info().CounterDerivedAuth {
		t.Fatal("RebindFor made a derived binding")
	}
	r5.Close()
}
