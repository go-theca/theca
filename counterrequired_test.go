package theca

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// Asking for a counter means requiring it (go-theca/theca#66): a header that
// names none, opened by a caller that holds a counter, is refused, whichever
// way the counter is given. Without a counter asked, it still opens.
func TestOpenCounterAskedHeaderNamesNone(t *testing.T) {
	geo, _ := format.NewGeometry(testSectors, testJournal)
	f := newMem(int(geo.End))
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	u := Unlock{Password: []byte("pw")}
	ctr := &fakeCounter{handle: 0x01500000, name: bytes.Repeat([]byte{1}, 34), v: 7}
	forFn := func(uint32, []byte) (Counter, error) { return ctr, nil }
	derFn := func(uint32, []byte, []byte) (Counter, error) { return ctr, nil }
	for name, o := range map[string]OpenOptions{
		"Counter":        {Counter: ctr},
		"CounterFor":     {CounterFor: forFn},
		"CounterDerived": {CounterDerived: derFn},
	} {
		if _, err := Open(ctx, f, u, o); !errors.Is(err, ErrCounterRequired) {
			t.Errorf("%s: %v, want ErrCounterRequired", name, err)
		}
	}
	// Control: nothing asked, it opens, unprotected.
	c, err = Open(ctx, f, u, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Info().RollbackProtected {
		t.Fatal("a container with no counter reports protected")
	}
	c.Close()
}
