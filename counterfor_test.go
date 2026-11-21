package theca

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// CounterFor finds the counter from the authenticated header, then the mount
// protocol runs on what it returned.
func TestCounterFor(t *testing.T) {
	ctr := &fakeCounter{handle: 0x01500000, name: bytes.Repeat([]byte{7}, 34), v: 10}
	geo, _ := format.NewGeometry(testSectors, testJournal)
	f := newMem(int(geo.End))
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal,
		Password: []byte("pw"), Counter: ctr})
	if err != nil {
		t.Fatal(err)
	}
	if c.Info().CounterHandle != 0x01500000 {
		t.Fatalf("created: %+v", c.Info())
	}
	c.Close()
	u := Unlock{Password: []byte("pw")}

	var asked uint32
	var askedName []byte
	r, err := Open(ctx, f, u, OpenOptions{CounterFor: func(h uint32, name []byte) (Counter, error) {
		asked, askedName = h, name
		return ctr, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Info().CounterHandle != 0x01500000 || asked != 0x01500000 || !bytes.Equal(askedName, ctr.name) || ctr.v != 12 {
		t.Fatalf("info %+v asked %#x name %x counter %d", r.Info(), asked, askedName, ctr.v)
	}
	r.Close()

	boom := errors.New("tpm unreachable")
	if _, err := Open(ctx, f, u, OpenOptions{CounterFor: func(uint32, []byte) (Counter, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Fatalf("resolver error: %v", err)
	}
	other := &fakeCounter{handle: 0x01500000, name: []byte("x"), v: ctr.v}
	if _, err := Open(ctx, f, u, OpenOptions{CounterFor: func(uint32, []byte) (Counter, error) { return other, nil }}); !errors.Is(err, ErrCounter) {
		t.Fatalf("a resolver's wrong counter: %v", err)
	}
	// An explicit Counter wins; the resolver is not asked.
	if r, err := Open(ctx, f, u, OpenOptions{Counter: ctr, CounterFor: func(uint32, []byte) (Counter, error) {
		t.Fatal("asked")
		return nil, nil
	}}); err != nil {
		t.Fatal(err)
	} else {
		r.Close()
	}
	// A container with no counter never asks, and a caller that holds a
	// counter is refused (#66): there is nothing to consult.
	f2 := newMem(int(geo.End))
	c2, _, err := Create(f2, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	if _, err := Open(ctx, f2, u, OpenOptions{CounterFor: func(uint32, []byte) (Counter, error) {
		t.Fatal("asked")
		return nil, nil
	}}); !errors.Is(err, ErrCounterRequired) {
		t.Fatal(err)
	}
}
