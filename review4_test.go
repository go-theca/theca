package theca

// Witnesses for the review of PR #4 (findings 2, 3, 4 and 6). Each test
// fails on the code before that review.

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// workingUnrecorded returns the indexes of slots the factor opens but the
// header does not record.
func workingUnrecorded(t *testing.T, f *memFile, k *Factor) []int {
	t.Helper()
	r := reopen(t, f, pwUnlock())
	defer r.Close()
	var bad []int
	for i := 0; i < format.NumSlots; i++ {
		b := make([]byte, format.SlotSize)
		f.ReadAt(b, int64(format.SlotsOff+i*format.SlotSize))
		if _, err := format.OpenWrap(&k.KEK, i, b); err == nil && r.body.SlotsUsed&(1<<i) == 0 {
			bad = append(bad, i)
		}
	}
	return bad
}

func slotOf(t *testing.T, f *memFile, k *Factor) int {
	t.Helper()
	for i := 0; i < format.NumSlots; i++ {
		b := make([]byte, format.SlotSize)
		f.ReadAt(b, int64(format.SlotsOff+i*format.SlotSize))
		if _, err := format.OpenWrap(&k.KEK, i, b); err == nil {
			return i
		}
	}
	return -1
}

// TestSlotCrashNeverLeavesAnUnrecordedWorkingSlot cuts the power at every
// backing write of AddSlot and of RemoveSlot (finding 3).
func TestSlotCrashNeverLeavesAnUnrecordedWorkingSlot(t *testing.T) {
	base, f, _ := create(t, PolicyAny)
	base.Close()
	k := FIDO2Factor(rnd(32))

	cuts := 0
	for cut := 0; ; cut++ {
		img := f.clone()
		c := reopen(t, img, pwUnlock())
		img.failAfter = img.writes + cut
		err := c.AddSlot(k)
		img.failAfter = -1
		if bad := workingUnrecorded(t, img, &k); len(bad) > 0 {
			t.Fatalf("add, cut after %d writes: slots %v open but are not recorded", cut, bad)
		}
		if err == nil {
			cuts = cut
			break
		}
	}
	if cuts < 3 {
		t.Fatalf("AddSlot completed after %d writes: the cut never landed between its steps", cuts)
	}

	c := reopen(t, f, pwUnlock())
	if err := c.AddSlot(k); err != nil {
		t.Fatal(err)
	}
	c.Close()
	idx := slotOf(t, f, &k)
	for cut := 0; ; cut++ {
		img := f.clone()
		c := reopen(t, img, pwUnlock())
		img.failAfter = img.writes + cut
		err := c.RemoveSlot(idx)
		img.failAfter = -1
		if bad := workingUnrecorded(t, img, &k); len(bad) > 0 {
			t.Fatalf("remove, cut after %d writes: slots %v open but are not recorded", cut, bad)
		}
		if err == nil {
			if slotOf(t, img, &k) >= 0 {
				t.Fatal("removed slot still opens")
			}
			break
		}
	}
}

// TestUnrecordedWorkingSlotCanBeRemoved: a working slot the header does not
// record (an older version's crash, another tool) can still be destroyed.
func TestUnrecordedWorkingSlotCanBeRemoved(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	k := FIDO2Factor(rnd(32))
	free := c.freeSlots()[0]
	blob, err := format.SealWrap(c.k, &k.KEK, free, c.rng)
	if err != nil {
		t.Fatal(err)
	}
	c.writeSlot(free, blob)
	if slotOf(t, f, &k) != free || c.body.SlotsUsed&(1<<free) != 0 {
		t.Fatal("setup: expected a working, unrecorded slot")
	}
	if err := c.RemoveSlot(free); err != nil {
		t.Fatal(err)
	}
	if slotOf(t, f, &k) >= 0 {
		t.Fatal("unrecorded slot survived RemoveSlot")
	}
	c.Close()
}

// closingKey closes the container while it "waits for the touch".
type closingKey struct {
	fakeKey
	c *Container
}

func (k *closingKey) Enroll(ctx context.Context) (Locator, []byte, error) {
	k.c.Close()
	return k.fakeKey.Enroll(ctx)
}

// badLocatorKey returns a locator the format refuses to store.
type badLocatorKey struct{ fakeKey }

func (*badLocatorKey) Enroll(context.Context) (Locator, []byte, error) {
	return Locator{}, rnd(32), nil
}

// TestEnrollChecksFirstAndCommitsOnce (finding 6).
func TestEnrollChecksFirstAndCommitsOnce(t *testing.T) {
	c, f, code := create(t, PolicyTwoOfThree)
	salt := make([]byte, format.SaltSize)
	f.ReadAt(salt, 0)
	pw, _ := PasswordFactor(0, []byte("correct horse"), salt)
	rc, _ := RecoveryFactor(code)

	key := newKey()
	e := c.Info().Epoch
	if err := c.EnrollFIDO2(ctx, key, pw, rc); err != nil {
		t.Fatal(err)
	}
	if got := c.Info().Epoch; got != e+1 {
		t.Fatalf("enrolment of 4 slots took %d commits, want 1", got-e)
	}
	// 5 slots used; fill to 14, so only 2 are free.
	for c.Info().SlotsUsed < 14 {
		if err := c.AddSlot(FIDO2Factor(rnd(32))); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.EnrollFIDO2(ctx, key, pw, rc); !errors.Is(err, ErrNoSlot) || key.enrolls != 1 {
		t.Fatalf("no room for 4 slots: %v after %d touches", err, key.enrolls)
	}
	// A locator the format refuses: nothing is reserved or committed.
	e, used := c.Info().Epoch, c.body.SlotsUsed
	if err := c.EnrollFIDO2(ctx, &badLocatorKey{}, pw); err == nil {
		t.Fatal("bad locator accepted")
	}
	if c.Info().Epoch != e || c.body.SlotsUsed != used {
		t.Fatal("a failed enrolment left reservations or a commit behind")
	}
	// A random source that dies during the touch: same.
	rk := &failRandKey{c: c}
	if err := c.EnrollFIDO2(ctx, rk, pw); err == nil {
		t.Fatal("random failure swallowed")
	}
	c.rng = rk.saved
	if c.Info().Epoch != e || c.body.SlotsUsed != used {
		t.Fatal("a failed enrolment left reservations or a commit behind")
	}
	// Closed while waiting for the touch.
	if err := c.EnrollFIDO2(ctx, &closingKey{fakeKey: *newKey(), c: c}, pw); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed during the touch: %v", err)
	}
	// Closed before: no touch at all.
	if err := c.EnrollFIDO2(ctx, key, pw); !errors.Is(err, ErrClosed) || key.enrolls != 1 {
		t.Fatalf("closed container: %v after %d touches", err, key.enrolls)
	}
}

type failRandKey struct {
	fakeKey
	c     *Container
	saved interface{ Read([]byte) (int, error) }
}

func (k *failRandKey) Enroll(ctx context.Context) (Locator, []byte, error) {
	k.saved = k.c.rng
	k.c.rng = failReader{}
	return newKey().Enroll(ctx)
}

func counterContainer(t *testing.T, v uint64) (*memFile, *fakeCounter) {
	t.Helper()
	ctr := &fakeCounter{handle: 0x01800001, name: bytes.Repeat([]byte{9}, 34), v: v}
	geo, _ := format.NewGeometry(testSectors, testJournal)
	f := newMem(int(geo.End))
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal,
		Password: []byte("correct horse"), Counter: ctr})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	return f, ctr
}

// TestCrashedMountImageIsRefused (finding 2): an image copied while a mount
// had written its header but not incremented must be refused once a later
// mount has resolved that state.
func TestCrashedMountImageIsRefused(t *testing.T) {
	f, ctr := counterContainer(t, 1000)
	op := OpenOptions{Counter: ctr}
	ctr.failInc = true
	if _, err := Open(ctx, f, pwUnlock(), op); err == nil {
		t.Fatal("increment failure swallowed")
	}
	crashed := f.clone() // header bound = counter + 1
	// Finishing the earlier increment can fail too, and changes nothing.
	v := ctr.v
	if _, err := Open(ctx, f, pwUnlock(), op); err == nil || ctr.v != v {
		t.Fatalf("finish failure: %v, counter %d -> %d", err, v, ctr.v)
	}
	ctr.failInc = false
	r, err := Open(ctx, f, pwUnlock(), op)
	if err != nil {
		t.Fatalf("resolve b == c+1: %v", err)
	}
	r.Close()
	if ctr.v != v+2 {
		t.Fatalf("counter %d -> %d: want the unfinished increment AND this mount's", v, ctr.v)
	}
	if _, err := Open(ctx, crashed, pwUnlock(), op); !errors.Is(err, ErrRollback) {
		t.Fatalf("image from the crashed mount accepted: %v", err)
	}
	// The resolved container itself keeps opening.
	r, err = Open(ctx, f, pwUnlock(), op)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

// TestRolledBackImageIsRefusedUntouched (finding 4): an old image holding a
// committed but unapplied transaction is refused before recovery writes.
func TestRolledBackImageIsRefusedUntouched(t *testing.T) {
	f, ctr := counterContainer(t, 1000)
	op := OpenOptions{Counter: ctr}
	var img *memFile
	for cut := 1; cut < 60 && img == nil; cut++ {
		try := f.clone()
		probe := *ctr // same identity, separate value
		c, err := Open(ctx, try, pwUnlock(), OpenOptions{Counter: &probe})
		if err != nil {
			t.Fatal(err)
		}
		m := make(model, testSectors*SectorSize)
		put(t, c, m, 4096, rnd(6000))
		try.failAfter = try.writes + cut
		c.Sync()
		try.failAfter = -1
		check := *ctr
		check.v = probe.v
		r, err := Open(ctx, try.clone(), pwUnlock(), OpenOptions{Counter: &check})
		if err != nil {
			t.Fatal(err)
		}
		if r.Info().ReplayedTransaction {
			img = try
			ctr.v = probe.v
		}
		r.Close()
	}
	if img == nil {
		t.Fatal("no crash point left a transaction to replay")
	}
	ctr.v += 3 // later sessions moved the counter on
	before, writes := append([]byte(nil), img.b...), img.writes
	if _, err := Open(ctx, img, pwUnlock(), op); !errors.Is(err, ErrRollback) {
		t.Fatalf("rolled-back image: %v", err)
	}
	if img.writes != writes || !bytes.Equal(img.b, before) {
		t.Fatalf("a refused image was written to (%d writes)", img.writes-writes)
	}
}

// TestCounterExhausted: a counter at its maximum cannot be rebound.
func TestCounterExhausted(t *testing.T) {
	f, ctr := counterContainer(t, math.MaxUint64-1)
	if ctr.v != math.MaxUint64 {
		t.Fatalf("counter %d", ctr.v)
	}
	if _, err := Open(ctx, f, pwUnlock(), OpenOptions{Counter: ctr}); !errors.Is(err, ErrCounter) {
		t.Fatalf("exhausted counter: %v", err)
	}
}
