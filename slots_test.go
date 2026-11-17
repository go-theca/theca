package theca

import (
	"errors"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// factorsOf derives the password and recovery factors of a container made by
// create(): the password is "correct horse".
func factorsOf(t *testing.T, f *memFile, code string) (pw, rc Factor) {
	t.Helper()
	pw, err := PasswordFactor(0, []byte("correct horse"), f.b[:format.SaltSize])
	if err != nil {
		t.Fatal(err)
	}
	rc, err = RecoveryFactor(code)
	if err != nil {
		t.Fatal(err)
	}
	return pw, rc
}

func opens(t *testing.T, f Backing, u Unlock) bool {
	t.Helper()
	c, err := Open(ctx, f, u, OpenOptions{})
	if err != nil {
		if !errors.Is(err, ErrNoMatch) {
			t.Fatal(err)
		}
		return false
	}
	c.Close()
	return true
}

func TestRemoveFactorsByRecoveryCode(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, f, code)
	if got := c.Slots(); len(got) != 2 {
		t.Fatalf("Slots %v", got)
	}
	idx, err := c.SlotsOf(rc)
	if err != nil || len(idx) != 1 {
		t.Fatalf("SlotsOf(rc) = %v, %v", idx, err)
	}
	n, err := c.RemoveFactors([]Factor{rc}, []Factor{pw})
	if err != nil || n != 1 {
		t.Fatalf("RemoveFactors = %d, %v", n, err)
	}
	if got := c.Slots(); len(got) != 1 || c.Info().SlotsUsed != 1 {
		t.Fatalf("Slots after %v", got)
	}
	c.Close()
	if opens(t, f, Unlock{Recovery: code}) {
		t.Fatal("the removed recovery code still opens the container")
	}
	if !opens(t, f, pwUnlock()) {
		t.Fatal("the password no longer opens it")
	}
}

func TestRemoveFactorsRefusals(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, f, code)
	stranger := randomFactor()
	before := f.writes
	for name, tc := range map[string]struct {
		remove, keep []Factor
		want         error
	}{
		"same factor to remove and keep":        {[]Factor{pw}, []Factor{pw}, ErrLastWay},
		"keep opens nothing":                    {[]Factor{rc}, []Factor{stranger}, ErrLastWay},
		"keep is the removed one":               {[]Factor{rc}, []Factor{rc}, ErrLastWay},
		"remove opens nothing":                  {[]Factor{stranger}, []Factor{pw}, ErrNoMatch},
		"nothing to remove":                     {nil, []Factor{pw}, ErrOption},
		"nothing to keep":                       {[]Factor{rc}, nil, ErrOption},
		"a key alone to remove":                 {[]Factor{FIDO2Factor(rnd(32))}, []Factor{pw}, ErrOption},
		"a key alone to keep":                   {[]Factor{rc}, []Factor{FIDO2Factor(rnd(32))}, ErrOption},
		"three factors":                         {[]Factor{pw, rc, stranger}, []Factor{pw}, ErrOption},
		"pair that opens nothing, keep nothing": {[]Factor{pw, rc}, []Factor{stranger}, ErrNoMatch},
	} {
		n, err := c.RemoveFactors(tc.remove, tc.keep)
		if !errors.Is(err, tc.want) || n != 0 {
			t.Errorf("%s: %d, %v (want %v)", name, n, err, tc.want)
		}
	}
	if f.writes != before {
		t.Fatalf("a refused removal wrote %d times", f.writes-before)
	}
	// Still opens with both.
	c.Close()
	if !opens(t, f, pwUnlock()) || !opens(t, f, Unlock{Recovery: code}) {
		t.Fatal("a refusal changed the slots")
	}
}

func TestRemoveFactorsPairAndDuplicates(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, f, code)
	other := randomFactor()
	// A pair slot, added twice (two slots open under the same pair).
	if err := c.AddSlot(other, pw); err != nil {
		t.Fatal(err)
	}
	if err := c.AddSlot(other, pw); err != nil {
		t.Fatal(err)
	}
	if idx, _ := c.SlotsOf(other, pw); len(idx) != 2 {
		t.Fatalf("pair slots %v", idx)
	}
	n, err := c.RemoveFactors([]Factor{other, pw}, []Factor{rc})
	if err != nil || n != 2 {
		t.Fatalf("RemoveFactors = %d, %v", n, err)
	}
	if idx, _ := c.SlotsOf(other, pw); len(idx) != 0 {
		t.Fatalf("pair still opens %v", idx)
	}
	// The password alone is the only other way and is not the pair: removing
	// the password while keeping the pair that is gone must be refused.
	if _, err := c.RemoveFactors([]Factor{pw}, []Factor{other, pw}); !errors.Is(err, ErrLastWay) {
		t.Fatalf("keeping a removed pair: %v", err)
	}
	c.Close()
}

func TestRemoveFactorsSlotNotRecorded(t *testing.T) {
	// A working slot the header does not record still counts as a way in to
	// keep, and can be the one removed.
	c, f, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, f, code)
	k := randomFactor()
	free := c.freeSlots()[0]
	blob, err := format.SealWrap(c.k, &k.KEK, free, c.rng)
	if err != nil {
		t.Fatal(err)
	}
	c.writeSlot(free, blob)
	if n, err := c.RemoveFactors([]Factor{pw}, []Factor{k}); err != nil || n != 1 {
		t.Fatalf("keep an unrecorded slot: %d, %v", n, err)
	}
	if _, err := c.RemoveFactors([]Factor{k}, []Factor{rc}); err != nil {
		t.Fatalf("remove the unrecorded slot: %v", err)
	}
	c.Close()
}

func TestRemoveFactorsOnAClosedContainer(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, f, code)
	c.Close()
	if _, err := c.RemoveFactors([]Factor{rc}, []Factor{pw}); !errors.Is(err, ErrClosed) {
		t.Fatalf("RemoveFactors: %v", err)
	}
	if _, err := c.SlotsOf(pw); !errors.Is(err, ErrClosed) {
		t.Fatalf("SlotsOf: %v", err)
	}
}

// A power cut at every write: the password keeps working at every cut, the
// removed code is gone once the call returned nil, and no slot ever works
// without being recorded.
func TestRemoveFactorsCrashAtEveryWrite(t *testing.T) {
	base, f, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, f, code)
	base.Close()
	for cut := 0; ; cut++ {
		img := f.clone()
		c := reopen(t, img, pwUnlock())
		img.failAfter = img.writes + cut
		_, err := c.RemoveFactors([]Factor{rc}, []Factor{pw})
		img.failAfter = -1
		if bad := workingUnrecorded(t, img, &rc); len(bad) > 0 {
			t.Fatalf("cut %d: slots %v open but are not recorded", cut, bad)
		}
		if !opens(t, img, pwUnlock()) {
			t.Fatalf("cut %d: the password no longer opens it", cut)
		}
		if err == nil {
			if opens(t, img, Unlock{Recovery: code}) {
				t.Fatal("removed code still opens")
			}
			if cut < 2 {
				t.Fatalf("finished after %d writes: the cut never landed between steps", cut)
			}
			return
		}
	}
}

// Every I/O failure is reported: not swallowed.
func TestRemoveFactorsIOErrors(t *testing.T) {
	_, base, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, base, code)
	sweep(t, "remove factors", base.clone, func(f Backing) error {
		c, err := Open(ctx, f, pwUnlock(), OpenOptions{})
		if err != nil {
			// A fault while opening is reported by Open itself.
			return err
		}
		if _, err := c.RemoveFactors([]Factor{rc}, []Factor{pw}); err != nil {
			return err
		}
		return c.Close()
	})
}
