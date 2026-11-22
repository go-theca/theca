package main

// A real container on a real software TPM, through go-tpm2/nvcounter: the
// tests that lived in the tpmcounter package before it moved to go-tpm2
// (they need a container, which that package must not depend on). Skipped
// when swtpm is not installed, unless THECA_REQUIRE_SWTPM is set.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/go-tpm2/nvcounter"

	"github.com/go-theca/theca"
)

// The counter is a theca.Counter that names its TPM.
var _ theca.IdentifiedCounter = (*nvcounter.Counter)(nil)

func TestSwtpmRollbackProtection(t *testing.T) {
	dev := startSwtpmDevice(t)
	opts := nvcounter.Options{Device: dev, Auth: []byte("index secret")}
	ctr, err := nvcounter.Create(opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ctr.Handle() != nvcounter.First {
		t.Fatalf("handle %#x, want the first free one", ctr.Handle())
	}

	f, err := os.CreateTemp("", "theca")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	pw := []byte("correct horse")
	c, _, err := theca.Create(theca.FileBacking{File: f}, theca.CreateOptions{
		Sectors: 256, Password: pw, Counter: ctr})
	if err != nil {
		t.Fatalf("theca.Create: %v", err)
	}
	if !c.Info().RollbackProtected || c.Info().CounterHandle != nvcounter.First {
		t.Fatalf("info %+v", c.Info())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// The state a stolen copy of the container would have: now, before any mount.
	old, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	open := func() (*theca.Container, error) {
		return theca.Open(context.Background(), theca.FileBacking{File: f},
			theca.Unlock{Password: pw}, theca.OpenOptions{
				CounterFor: func(h uint32, name []byte) (theca.Counter, error) {
					o := opts
					o.Handle = h
					return nvcounter.Open(o)
				}})
	}
	// Two honest mounts: the counter moves once per mount.
	before, _ := ctr.Read()
	for i := 0; i < 2; i++ {
		c, err := open()
		if err != nil {
			t.Fatalf("mount %d: %v", i, err)
		}
		c.Close()
	}
	after, _ := ctr.Read()
	if after != before+2 {
		t.Fatalf("counter %d -> %d after two mounts", before, after)
	}
	// Put the older image back: refused, and the counter does not move.
	if _, err := f.WriteAt(old, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := open(); !errors.Is(err, theca.ErrRollback) {
		t.Fatalf("rolled-back image: %v", err)
	}
	if v, _ := ctr.Read(); v != after {
		t.Fatalf("a refused mount moved the counter: %d -> %d", after, v)
	}
	// Undo: delete the index (owner password empty on swtpm).
	if err := ctr.Destroy(); err != nil {
		t.Fatal(err)
	}
}

// withoutIdentity hides Identity: what a container made before the pin was.
type withoutIdentity struct{ theca.Counter }

// The attack of go-theca/theca#39, on two real software TPMs: a second TPM
// where someone defines the same index (same Name) and raises it to the bound
// of an old copy of the container.
func TestSwtpmIdentityPinning(t *testing.T) {
	devA, devB := startSwtpmDevice(t), startSwtpmDevice(t)
	auth := []byte("index secret")
	optsA := nvcounter.Options{Device: devA, Auth: auth}
	optsB := nvcounter.Options{Device: devB, Auth: auth}

	ctrA, err := nvcounter.Create(optsA)
	if err != nil {
		t.Fatal(err)
	}
	idA, err := ctrA.Identity()
	if err != nil || len(idA) != nvcounter.IDSize {
		t.Fatalf("identity of A: %x %v", idA, err)
	}
	ctrB, err := nvcounter.Create(optsB)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := ctrB.Identity()
	if err != nil || bytes.Equal(idA, idB) {
		t.Fatalf("two TPMs, identities %x and %x (%v)", idA, idB, err)
	}

	mk := func(c theca.Counter) *os.File {
		f, err := os.CreateTemp("", "theca")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(f.Name()); f.Close() })
		ct, _, err := theca.Create(theca.FileBacking{File: f}, theca.CreateOptions{
			Sectors: 256, Password: []byte("pw"), Counter: c})
		if err != nil {
			t.Fatal(err)
		}
		if err := ct.Close(); err != nil {
			t.Fatal(err)
		}
		return f
	}
	openOn := func(f *os.File, o nvcounter.Options) (*theca.Container, error) {
		return theca.Open(context.Background(), theca.FileBacking{File: f}, theca.Unlock{Password: []byte("pw")},
			theca.OpenOptions{CounterFor: func(h uint32, _ []byte) (theca.Counter, error) {
				o.Handle = h
				return nvcounter.Open(o)
			}})
	}
	// The attacker's counter: the same handle, the same Name, raised to exactly
	// the value an old copy of the container is bound to.
	raise := func(to uint64) {
		t.Helper()
		for {
			if v, err := ctrB.Read(); err == nil && v >= to {
				if v != to {
					t.Fatalf("counter B is at %d, past %d", v, to)
				}
				return
			}
			if err := ctrB.Increment(); err != nil {
				t.Fatal(err)
			}
		}
	}

	// A container pinned to TPM A, and the copy a thief holds of it.
	pinned := mk(ctrA)
	bound, _ := ctrA.Read()
	raise(bound)
	if !bytes.Equal(ctrA.Name(), ctrB.Name()) {
		t.Fatalf("the attack needs the same Name: %x vs %x", ctrA.Name(), ctrB.Name())
	}
	// The attacker's TPM has the same handle, the same Name and exactly the
	// bound: before the pin this was accepted (the control below). Now it is not.
	before, _ := ctrB.Read()
	_, err = openOn(pinned, optsB)
	if !errors.Is(err, theca.ErrCounterIdentity) {
		t.Fatalf("the attacker's TPM: %v, want ErrCounterIdentity", err)
	}
	for _, want := range []string{theca.ShortID(idA), theca.ShortID(idB)} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
	if after, _ := ctrB.Read(); after != before {
		t.Fatalf("a refused mount moved the attacker's counter %d -> %d", before, after)
	}
	// The same TPM opens it, and the header says which TPM that is.
	c, err := openOn(pinned, optsA)
	if err != nil {
		t.Fatalf("same TPM: %v", err)
	}
	if got := c.Info().CounterTPM; !bytes.Equal(got, idA) {
		t.Fatalf("Info.CounterTPM %x, want %x", got, idA)
	}
	c.Close()

	// CONTROL: a container made before the pin (no identity in its header) IS
	// accepted by the attacker's TPM. This is the attack, and it works: the
	// refusal above is the pin, not something else.
	old := mk(withoutIdentity{ctrA})
	boundOld, _ := ctrA.Read()
	raise(boundOld)
	if !bytes.Equal(ctrA.Name(), ctrB.Name()) {
		t.Fatalf("the attack needs the same Name: %x vs %x", ctrA.Name(), ctrB.Name())
	}
	if c, err = openOn(old, optsB); err != nil {
		t.Fatalf("control: the old-format container was refused on the attacker's TPM: %v", err)
	}
	if c.Info().CounterTPM != nil {
		t.Fatal("control: an old-format container reports an identity")
	}
	c.Close()
	// The old-format container still opens on its own TPM (A is at its bound,
	// the attacker's mount moved only B's counter).
	if c, err = openOn(old, optsA); err != nil {
		t.Fatalf("old-format container on its own TPM: %v", err)
	}
	c.Close()

	// Recovery: rebind on B pins B; B then opens the container, A refuses it.
	rb, err := theca.Open(context.Background(), theca.FileBacking{File: pinned}, theca.Unlock{Password: []byte("pw")},
		theca.OpenOptions{RebindFor: func(h uint32, _ []byte) (theca.Counter, error) {
			if err := ctrB.Destroy(); err != nil {
				return nil, err
			}
			return nvcounter.Create(nvcounter.Options{Device: devB, Auth: auth, Handle: h})
		}})
	if err != nil {
		t.Fatalf("rebind on B: %v", err)
	}
	if !bytes.Equal(rb.Info().CounterTPM, idB) {
		t.Fatalf("rebind pinned %x, want B's %x", rb.Info().CounterTPM, idB)
	}
	rb.Close()
	if c, err = openOn(pinned, optsB); err != nil {
		t.Fatalf("after rebind, on B: %v", err)
	}
	c.Close()
	if _, err := openOn(pinned, optsA); !errors.Is(err, theca.ErrCounterIdentity) {
		t.Fatalf("after rebind, on A: %v, want ErrCounterIdentity", err)
	}
}
