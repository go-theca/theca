package theca

// Tests written for the survivors of `mutsweep -files theca.go` (issue #76).
// Each one asserts the behaviour a guard exists for.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/go-theca/theca/internal/format"
)

// within fails the test, instead of hanging it, when fn does not return in
// time: a mutant that turns a loop into an endless one must be CAUGHT.
func within(t testing.TB, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		// Not t.Fatalf: it runs the test's deferred Close, which would wait for
		// the lock the endless call still holds, and the run would hang anyway.
		fmt.Fprintf(os.Stderr, "--- FAIL: %s: %s did not return within the deadline\nFAIL\n", t.Name(), what)
		os.Exit(1)
	}
}

var errFlaky = errors.New("flaky read")

// flakyRand is a random source whose failAt-th Read call (1-based) fails once,
// then recovers; failAt 0 never fails. calls counts every Read.
type flakyRand struct{ calls, failAt int }

func (r *flakyRand) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == r.failAt {
		return 0, errFlaky
	}
	return rand.Read(p)
}

// shotFile fails exactly the failAt-th WriteAt (1-based, counted from
// arming) once; every other call works. failReads makes every ReadAt fail.
type shotFile struct {
	*memFile
	n, failAt int
	failReads bool
}

func (s *shotFile) WriteAt(p []byte, off int64) (int, error) {
	s.n++
	if s.n == s.failAt {
		return 0, errCut
	}
	return s.memFile.WriteAt(p, off)
}

func (s *shotFile) ReadAt(p []byte, off int64) (int, error) {
	if s.failReads {
		return 0, errCut
	}
	return s.memFile.ReadAt(p, off)
}

func testGeo(t *testing.T) format.Geometry {
	t.Helper()
	geo, err := format.NewGeometry(testSectors, testJournal)
	if err != nil {
		t.Fatal(err)
	}
	return geo
}

func createWith(t *testing.T, f Backing, r io.Reader, p Policy) (*Container, error) {
	t.Helper()
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal,
		Password: []byte("correct horse"), Policy: p, Rand: r})
	return c, err
}

// A random source that fails once, at ANY call, must fail Create: no read of
// the source may be ignored.
func TestCreateRefusesEveryRandomFailure(t *testing.T) {
	geo := testGeo(t)
	for _, p := range []Policy{PolicyAny, PolicyTwoOfThree} {
		count := &flakyRand{}
		if _, err := createWith(t, newMem(int(geo.End)), count, p); err != nil {
			t.Fatal(err)
		}
		if count.calls == 0 {
			t.Fatal("Create read no randomness")
		}
		for k := 1; k <= count.calls; k++ {
			f := newMem(int(geo.End))
			c, err := createWith(t, f, &flakyRand{failAt: k}, p)
			if err == nil || c != nil {
				t.Fatalf("policy %d: read %d of %d failed, Create returned %v", p, k, count.calls, err)
			}
		}
	}
}

func TestCreateZeroSectorsIsAnOptionError(t *testing.T) {
	f := newMem(1 << 20)
	_, _, err := Create(f, CreateOptions{Sectors: 0, JournalEntries: testJournal,
		Password: []byte("correct horse"), Policy: PolicyAny})
	if !errors.Is(err, ErrOption) {
		t.Fatalf("zero sectors: %v", err)
	}
	if f.writes != 0 {
		t.Fatalf("a refused Create wrote %d times", f.writes)
	}
}

// A failure of any single write during Create (one-shot, then the backing
// works again) must fail Create, never be skipped.
func TestCreateRefusesEveryWriteFailure(t *testing.T) {
	geo := testGeo(t)
	probe := &shotFile{memFile: newMem(int(geo.End))}
	if _, err := createWith(t, probe, nil, PolicyAny); err != nil {
		t.Fatal(err)
	}
	for k := 1; k <= probe.n; k++ {
		f := &shotFile{memFile: newMem(int(geo.End)), failAt: k}
		if c, err := createWith(t, f, nil, PolicyAny); err == nil || c != nil {
			t.Fatalf("write %d of %d failed, Create returned %v", k, probe.n, err)
		}
	}
}

// Every random read of a slot or sector write may fail once; none is ignored.
func TestAddSlotAndWriteRefuseEveryRandomFailure(t *testing.T) {
	fresh := func(r *flakyRand) *Container {
		c, _, _ := create(t, PolicyAny)
		c.rng = r
		return c
	}
	sector := bytes.Repeat([]byte{7}, SectorSize)
	ops := map[string]func(c *Container) error{
		"AddSlot":      func(c *Container) error { return c.AddSlot(randomFactor()) },
		"WriteAt":      func(c *Container) error { _, err := c.WriteAt(sector, 0); return err },
		"WriteAtOther": func(c *Container) error { _, err := c.WriteAt(sector, 5*SectorSize); return err },
	}
	for name, op := range ops {
		count := &flakyRand{}
		if err := op(fresh(count)); err != nil {
			t.Fatal(err)
		}
		for k := 1; k <= count.calls; k++ {
			c := fresh(&flakyRand{failAt: k})
			used := c.body.SlotsUsed
			if err := op(c); err == nil {
				t.Fatalf("%s: read %d of %d failed, no error", name, k, count.calls)
			}
			// A failure inside the commit breaks the container (reopen decides);
			// a failure before it must leave nothing reserved.
			if name == "AddSlot" && c.broken == nil && c.body.SlotsUsed != used {
				t.Fatalf("%s: read %d: a refused slot stays reserved", name, k)
			}
		}
	}
}

// One failed write while publishing a slot must fail AddSlot, whichever write.
func TestAddSlotRefusesEveryWriteFailure(t *testing.T) {
	geo := testGeo(t)
	mk := func(failAt int) (*Container, *shotFile) {
		f := &shotFile{memFile: newMem(int(geo.End))}
		c, err := createWith(t, f, nil, PolicyAny)
		if err != nil {
			t.Fatal(err)
		}
		f.n, f.failAt = 0, failAt
		return c, f
	}
	c, probe := mk(0)
	if err := c.AddSlot(randomFactor()); err != nil {
		t.Fatal(err)
	}
	for k := 1; k <= probe.n; k++ {
		c, _ := mk(k)
		if err := c.AddSlot(randomFactor()); err == nil {
			t.Fatalf("write %d of %d failed, AddSlot returned nil", k, probe.n)
		}
	}
}

type enrollRefused struct {
	FIDO2
	err error
}

func (e enrollRefused) Enroll(context.Context, [][32]byte) ([][]byte, error) { return nil, e.err }

func TestEnrollFIDO2ReturnsTheDeviceError(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	pw, rc := factorsOf(t, f, code)
	boom := errors.New("touch timed out")
	used := c.body.SlotsUsed
	if err := c.EnrollFIDO2(ctx, enrollRefused{err: boom}, pw, rc); !errors.Is(err, boom) {
		t.Fatalf("a failed enrolment returned %v", err)
	}
	if c.body.SlotsUsed != used {
		t.Fatal("a failed enrolment reserved slots")
	}
}

func TestCheckOutputsCountsOutputsAgainstSalts(t *testing.T) {
	one, two := [][]byte{make([]byte, 32)}, [][]byte{make([]byte, 32), make([]byte, 32)}
	if err := checkOutputs(one, 2); !errors.Is(err, ErrAuthenticator) {
		t.Fatalf("one output for two salts: %v", err)
	}
	if err := checkOutputs(two, 1); !errors.Is(err, ErrAuthenticator) {
		t.Fatalf("two outputs for one salt: %v", err)
	}
	if err := checkOutputs(two, 2); err != nil {
		t.Fatalf("two outputs for two salts: %v", err)
	}
	if err := checkOutputs([][]byte{make([]byte, 32), make([]byte, 31)}, 2); !errors.Is(err, ErrAuthenticator) {
		t.Fatalf("a short output: %v", err)
	}
}

func TestRandOr(t *testing.T) {
	if randOr(nil) != rand.Reader {
		t.Fatal("a nil source is not the system source")
	}
	r := &flakyRand{}
	if randOr(r) != io.Reader(r) {
		t.Fatal("a given source is replaced")
	}
}

// recFile records the shape of the writes it receives.
type recFile struct {
	*memFile
	empty int // zero-length writes
	last  uint64
}

func (r *recFile) WriteAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		r.empty++
	}
	r.last = uint64(off) + uint64(len(p))
	return r.memFile.WriteAt(p, off)
}

// fillRandomAt covers exactly [at, at+size): no empty write past the end, and
// the last byte written is the last of the range.
func TestFillRandomAtCoversTheRangeAndNoMore(t *testing.T) {
	for _, size := range []uint64{0, 1, 1 << 20, 2 << 20, 3<<20 + 5} {
		const at = 4096
		f := &recFile{memFile: newMem(int(at + size))}
		if err := fillRandomAt(f, at, size, rand.Reader); err != nil {
			t.Fatal(err)
		}
		if f.empty != 0 {
			t.Fatalf("size %d: %d empty writes", size, f.empty)
		}
		if size > 0 && f.last != at+size {
			t.Fatalf("size %d: last byte written at %d, want %d", size, f.last, at+size)
		}
		if size == 0 && f.last != 0 {
			t.Fatalf("size 0 wrote at %d", f.last)
		}
	}
}

// truncFile counts Truncate calls.
type truncFile struct {
	*memFile
	size   int64
	truncs []int64
}

func (f *truncFile) Size() (int64, error) { return f.size, nil }
func (f *truncFile) Truncate(n int64) error {
	f.truncs = append(f.truncs, n)
	return nil
}

func TestTruncOnlyShrinksALargerBacking(t *testing.T) {
	for _, tc := range []struct {
		have int64
		want int
	}{{99, 0}, {100, 0}, {101, 1}} {
		f := &truncFile{memFile: newMem(1), size: tc.have}
		if err := trunc(f, 100); err != nil {
			t.Fatal(err)
		}
		if len(f.truncs) != tc.want || (tc.want == 1 && f.truncs[0] != 100) {
			t.Fatalf("backing of %d bytes: truncated %v", tc.have, f.truncs)
		}
	}
}

// ReadAt and WriteAt must terminate and agree with a model at every edge:
// zero length, one byte, exactly a sector, a range ending on the volume end,
// a range running past it, the end itself, and far beyond.
func TestReadWriteAtEdges(t *testing.T) {
	c, _, _ := create(t, PolicyAny)
	size := int64(testSectors) * SectorSize
	model := make([]byte, size)
	write := func(off int64, n int) {
		t.Helper()
		p := make([]byte, n)
		rand.Read(p)
		var got int
		var err error
		within(t, "WriteAt", func() { got, err = c.WriteAt(p, off) })
		if err != nil || got != n {
			t.Fatalf("WriteAt(%d bytes at %d) = %d, %v", n, off, got, err)
		}
		copy(model[off:], p)
	}
	read := func(off int64, n int) {
		t.Helper()
		p := make([]byte, n)
		var got int
		var err error
		within(t, "ReadAt", func() { got, err = c.ReadAt(p, off) })
		want := min(int64(n), max(size-off, 0))
		if got != int(want) {
			t.Fatalf("ReadAt(%d bytes at %d) read %d, want %d", n, off, got, want)
		}
		if want < int64(n) && !errors.Is(err, io.EOF) || want == int64(n) && err != nil {
			t.Fatalf("ReadAt(%d bytes at %d): err %v, short %v", n, off, err, want < int64(n))
		}
		if got > 0 && !bytes.Equal(p[:got], model[off:off+int64(got)]) {
			t.Fatalf("ReadAt(%d bytes at %d) returned the wrong bytes", n, off)
		}
	}
	for _, e := range []struct {
		off int64
		n   int
	}{
		{0, 0}, {size, 0}, {0, 1}, {SectorSize - 1, 2}, {SectorSize, SectorSize},
		{0, 2 * SectorSize}, {100, 3*SectorSize + 7}, {size - 1, 1},
		{size - SectorSize, SectorSize}, {size - 10, 10},
	} {
		write(e.off, e.n)
		read(e.off, e.n)
	}
	read(0, int(size))
	// Past the end: a short read with EOF, never an error or a hang.
	read(size-5, 100)
	read(size, 10)
	read(size+1, 10)
	read(size+10*SectorSize, 10)
	read(1<<40, 10)
	if _, err := c.WriteAt(make([]byte, 2), size-1); !errors.Is(err, ErrRange) {
		t.Fatalf("a write across the end: %v", err)
	}
}

// Rewriting part of a sector needs its old content: a sector that no longer
// opens must refuse a partial write, not be silently replaced with zeros
// around the new bytes. A whole-sector write needs no old content.
func TestPartialWriteOfACorruptSectorIsRefused(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	if _, err := c.WriteAt(bytes.Repeat([]byte{1}, SectorSize), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	geo := testGeo(t)
	f.b[geo.DataOff+10] ^= 0xff
	c = reopen(t, f, pwUnlock())
	defer c.Close()
	if _, err := c.WriteAt([]byte{9}, 0); !errors.Is(err, ErrSector) {
		t.Fatalf("a partial write over a corrupt sector: %v", err)
	}
	if _, err := c.WriteAt(bytes.Repeat([]byte{2}, SectorSize), 0); err != nil {
		t.Fatalf("a whole-sector write over a corrupt sector: %v", err)
	}
}

// A metadata block that fails verification must stop a write into it.
func TestWriteIntoACorruptMetadataBlockIsRefused(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	if _, err := c.WriteAt(bytes.Repeat([]byte{1}, SectorSize), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	geo := testGeo(t)
	f.b[geo.MetaOff+3] ^= 0xff
	c = reopen(t, f, pwUnlock())
	defer c.Close()
	if _, err := c.WriteAt(bytes.Repeat([]byte{2}, SectorSize), SectorSize); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a write into a corrupt metadata block: %v", err)
	}
}

// Sync with nothing pending only flushes the backing: no new epoch.
func TestSyncWithNothingPendingKeepsTheEpoch(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	defer c.Close()
	epoch, syncs := c.Info().Epoch, f.syncs
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := c.Info().Epoch; got != epoch {
		t.Fatalf("an idle Sync moved the epoch %d -> %d", epoch, got)
	}
	if f.syncs <= syncs {
		t.Fatal("an idle Sync did not flush the backing")
	}
	if _, err := c.WriteAt([]byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(); err != nil || c.Info().Epoch != epoch+1 {
		t.Fatalf("a Sync with a pending write: %v, epoch %d -> %d", err, epoch, c.Info().Epoch)
	}
}
