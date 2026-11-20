package theca

import (
	"context"
	"errors"
	"testing"
)

// keyed makes a PolicyAny container (password and recovery alone each open it)
// with a key paired to both, and returns what the tests need.
func keyed(t *testing.T) (c *Container, f *memFile, code string, pw, rc Factor, key *fakeKey) {
	t.Helper()
	c, f, code = create(t, PolicyAny)
	pw, rc = factorsOf(t, f, code)
	key = newKey()
	if err := c.EnrollFIDO2(ctx, key, pw, rc); err != nil {
		t.Fatal(err)
	}
	return c, f, code, pw, rc, key
}

func TestKeyPairsOpenTheKeySlots(t *testing.T) {
	c, _, _, pw, rc, key := keyed(t)
	before := key.derives
	pairs, err := KeyPairs(ctx, key, pw, rc)
	if err != nil || len(pairs) != 2 || key.derives != before+1 {
		t.Fatalf("KeyPairs = %d pairs, %v, %d touches", len(pairs), err, key.derives-before)
	}
	for i, p := range pairs {
		idx, err := c.SlotsOf(p...)
		if err != nil || len(idx) != 1 {
			t.Fatalf("pair %d opens %v, %v", i, idx, err)
		}
	}
	// A key that is not enrolled in this container forms pairs that open nothing.
	stranger := newKey()
	stranger.Enroll(ctx, [][32]byte{{1}})
	sp, err := KeyPairs(ctx, stranger, pw)
	if err != nil {
		t.Fatal(err)
	}
	if idx, _ := c.SlotsOf(sp[0]...); len(idx) != 0 {
		t.Fatalf("a stranger key opens %v", idx)
	}
	WipeSets(pairs)
	WipeSets(sp)
	if pairs[0][0].KEK != ([32]byte{}) || pairs[0][1].KEK != ([32]byte{}) {
		t.Fatal("WipeSets left a key")
	}
	c.Close()
}

type fixedKey struct {
	res [][][]byte
	err error
}

func (fixedKey) Enroll(context.Context, [][32]byte) ([][]byte, error) { return nil, nil }
func (k fixedKey) Derive(context.Context, [][32]byte) ([][][]byte, error) {
	return k.res, k.err
}

func TestKeyPairsRefusals(t *testing.T) {
	_, _, _, pw, rc, _ := keyed(t)
	boom := errors.New("touch timed out")
	many := make([][][]byte, MaxFIDO2Credentials+1)
	for i := range many {
		many[i] = [][]byte{rnd(32)}
	}
	for name, tc := range map[string]struct {
		dev      FIDO2
		partners []Factor
		want     error
	}{
		"no partner":          {newKey(), nil, ErrOption},
		"three partners":      {newKey(), []Factor{pw, rc, pw}, ErrOption},
		"no credential":       {newKey(), []Factor{pw}, ErrNoCredential},
		"empty answer":        {fixedKey{}, []Factor{pw}, ErrNoCredential},
		"the key fails":       {fixedKey{err: boom}, []Factor{pw}, boom},
		"too many credential": {fixedKey{res: many}, []Factor{pw}, ErrAuthenticator},
		"wrong output count":  {fixedKey{res: [][][]byte{{rnd(32)}}}, []Factor{pw, rc}, ErrAuthenticator},
		"short output":        {fixedKey{res: [][][]byte{{rnd(7)}}}, []Factor{pw}, ErrAuthenticator},
		"bad second answer":   {fixedKey{res: [][][]byte{{rnd(32)}, {rnd(7)}}}, []Factor{pw}, ErrAuthenticator},
	} {
		if p, err := KeyPairs(ctx, tc.dev, tc.partners...); !errors.Is(err, tc.want) || p != nil {
			t.Errorf("%s: %v, %v (want %v)", name, p, err, tc.want)
		}
	}
}

// Removing the password-only slot with a key pair to keep: both sides of every
// boundary, and a refusal never writes.
func TestRemoveFactorSetsWithTheKey(t *testing.T) {
	c, f, code, pw, rc, key := keyed(t)
	pairs, err := KeyPairs(ctx, key, pw, rc)
	if err != nil {
		t.Fatal(err)
	}
	pwKey, rcKey := pairs[0], pairs[1]
	stranger := newKey()
	stranger.Enroll(ctx, [][32]byte{{1}})
	sp, _ := KeyPairs(ctx, stranger, pw)
	before := f.writes
	for name, tc := range map[string]struct {
		remove, keep [][]Factor
		want         error
	}{
		"keep is another key":            {[][]Factor{{pw}}, [][]Factor{sp[0]}, ErrLastWay},
		"keep overlaps the removal":      {[][]Factor{{pw}, pwKey}, [][]Factor{pwKey}, ErrLastWay},
		"keep opens only what goes":      {[][]Factor{{pw}}, [][]Factor{{pw}}, ErrLastWay},
		"remove opens nothing":           {[][]Factor{sp[0]}, [][]Factor{pwKey}, ErrNoMatch},
		"no remove sets":                 {nil, [][]Factor{pwKey}, ErrOption},
		"no keep sets":                   {[][]Factor{{pw}}, nil, ErrOption},
		"keep set that cannot be a slot": {[][]Factor{{pw}}, [][]Factor{{pwKey[1]}}, ErrOption},
	} {
		if n, err := c.RemoveFactorSets(tc.remove, tc.keep); !errors.Is(err, tc.want) || n != 0 {
			t.Errorf("%s: %d, %v (want %v)", name, n, err, tc.want)
		}
	}
	if f.writes != before {
		t.Fatalf("a refused removal wrote %d times", f.writes-before)
	}
	// The key pair keeps it open: the password-only slot goes, and nothing else
	// (the recovery-only slot and both key slots stay).
	n, err := c.RemoveFactorSets([][]Factor{{pw}}, [][]Factor{pwKey})
	if err != nil || n != 1 {
		t.Fatalf("RemoveFactorSets = %d, %v", n, err)
	}
	c.Close()
	if opens(t, f, pwUnlock()) {
		t.Fatal("the password alone still opens it")
	}
	if !opens(t, f, Unlock{Password: []byte("correct horse"), FIDO: key}) || !opens(t, f, Unlock{Recovery: code}) {
		t.Fatal("the key, or the recovery code, stopped working")
	}
	// Both key slots go at once by naming both pairs, keeping the recovery code.
	c = reopen(t, f, Unlock{Recovery: code})
	n, err = c.RemoveFactorSets([][]Factor{pwKey, rcKey}, [][]Factor{{rc}})
	if err != nil || n != 2 {
		t.Fatalf("removing both key slots = %d, %v", n, err)
	}
	c.Close()
}

// A power cut at every write while the password-only slot goes: the password
// with the key opens the container at every cut.
func TestRemoveFactorSetsCrashAtEveryWrite(t *testing.T) {
	base, f, _, pw, rc, key := keyed(t)
	pairs, err := KeyPairs(ctx, key, pw, rc)
	if err != nil {
		t.Fatal(err)
	}
	base.Close()
	u := Unlock{Password: []byte("correct horse"), FIDO: key}
	for cut := 0; ; cut++ {
		img := f.clone()
		c := reopen(t, img, u)
		img.failAfter = img.writes + cut
		_, err := c.RemoveFactorSets([][]Factor{{pw}}, [][]Factor{pairs[0]})
		img.failAfter = -1
		if !opens(t, img, u) {
			t.Fatalf("cut %d: the password with the key no longer opens it", cut)
		}
		if err == nil {
			if opens(t, img, pwUnlock()) {
				t.Fatal("the password alone still opens it")
			}
			if cut < 2 {
				t.Fatalf("finished after %d writes: the cut never landed between steps", cut)
			}
			return
		}
	}
}
