package theca

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// growMem is a memFile that grows on write, like a file made with O_EXCL.
type growMem struct{ memFile }

func newGrow() *growMem { return &growMem{memFile{failAfter: -1}} }

func (g *growMem) WriteAt(p []byte, off int64) (int, error) {
	if g.failAfter >= 0 && g.writes >= g.failAfter {
		return 0, errCut
	}
	if need := int(off) + len(p); need > len(g.b) {
		g.b = append(g.b, make([]byte, need-len(g.b))...)
	}
	return g.memFile.WriteAt(p, off)
}

// readCut fails every ReadAt from the at-th on (1-based); at 0: never.
type readCut struct {
	Backing
	n, at int
}

func (r *readCut) ReadAt(p []byte, off int64) (int, error) {
	r.n++
	if r.at > 0 && r.n >= r.at {
		return 0, errCut
	}
	return r.Backing.ReadAt(p, off)
}

type sizeErr struct{ Backing }

func (sizeErr) Size() (int64, error) { return 0, errCut }

// mkSized makes a closed container of the given sectors and journal, holding
// random data at several places (the first and the last sector included), and
// returns the file and the volume content.
func mkSized(t *testing.T, sectors uint64, journal uint32, co CreateOptions) (*memFile, model) {
	t.Helper()
	geo, err := format.NewGeometry(sectors, journal)
	if err != nil {
		t.Fatal(err)
	}
	f := newMem(int(geo.End))
	co.Sectors, co.JournalEntries = sectors, journal
	if co.Password == nil {
		co.Password = []byte("correct horse")
	}
	c, _, err := Create(f, co)
	if err != nil {
		t.Fatal(err)
	}
	m := make(model, sectors*SectorSize)
	put(t, c, m, 0, rnd(5000))
	put(t, c, m, 3*SectorSize+17, rnd(9000))
	put(t, c, m, len(m)-SectorSize, rnd(SectorSize))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return f, m
}

func readAll(t *testing.T, c *Container) []byte {
	t.Helper()
	b := make([]byte, c.Size())
	if _, err := c.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestResizeUpAndDown(t *testing.T) {
	// 300 sectors: the volume is hashed and copied in more than one 1 MiB chunk.
	src, m := mkSized(t, 300, 8, CreateOptions{})
	before := append([]byte(nil), src.b...)
	dst := newGrow()
	info, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, dst, ResizeOptions{Entries: 40})
	if err != nil {
		t.Fatal(err)
	}
	if info.OldEntries != 8 || info.Entries != 40 || info.Sectors != 300 || info.Size != uint64(len(dst.b)) || len(dst.b)%(1<<20) != 0 {
		t.Fatalf("info %+v, file %d bytes", info, len(dst.b))
	}
	if !bytes.Equal(src.b, before) {
		t.Fatal("the source was written")
	}
	c := reopen(t, dst, pwUnlock())
	if c.Info().JournalEntries != 40 {
		t.Fatalf("journal %d", c.Info().JournalEntries)
	}
	if !bytes.Equal(readAll(t, c), m) {
		t.Fatal("the copy's content differs")
	}
	if _, err := c.Verify(); err != nil {
		t.Fatal(err)
	}
	// The copy is a working container: write, close, reopen.
	put(t, c, m, 100000, rnd(70000))
	c.Close()
	if !bytes.Equal(readAll(t, reopen(t, dst, pwUnlock())), m) {
		t.Fatal("a write to the copy was lost")
	}

	// And back down to the minimum, from a copy that has been written to.
	back := newGrow()
	info, err = Resize(ctx, dst, pwUnlock(), OpenOptions{}, back, ResizeOptions{Entries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if info.Entries != format.MinJournal(mustGeo(t, 300, 8).Shape) {
		t.Fatalf("the minimum was not applied: %d", info.Entries)
	}
	if !bytes.Equal(readAll(t, reopen(t, back, pwUnlock())), m) {
		t.Fatal("the shrunk copy's content differs")
	}
}

func mustGeo(t *testing.T, sectors uint64, journal uint32) format.Geometry {
	t.Helper()
	g, err := format.NewGeometry(sectors, journal)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestResizeDefaultEntries(t *testing.T) {
	src, m := mkSized(t, 16, 8, CreateOptions{})
	want := DefaultJournal(16)
	if want == 8 {
		t.Skip("the default is the test's journal")
	}
	dst := newGrow()
	info, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, dst, ResizeOptions{})
	if err != nil || info.Entries != want {
		t.Fatalf("%+v, %v", info, err)
	}
	if !bytes.Equal(readAll(t, reopen(t, dst, pwUnlock())), m) {
		t.Fatal("content differs")
	}
}

func TestResizeKeepsSlotsAndPolicy(t *testing.T) {
	src, m := mkSized(t, 16, 8, CreateOptions{})
	dst := newGrow()
	if _, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, dst, ResizeOptions{Entries: 30}); err != nil {
		t.Fatal(err)
	}
	a, b := reopen(t, src, pwUnlock()), reopen(t, dst, pwUnlock())
	ia, ib := a.Info(), b.Info()
	if ia.SlotsUsed != ib.SlotsUsed || ia.SlotsUsed == 0 {
		t.Fatalf("source %+v, copy %+v", ia, ib)
	}
	if !bytes.Equal(readAll(t, b), m) {
		t.Fatal("content differs")
	}
	// The wrong password opens neither.
	if _, err := Open(ctx, dst, Unlock{Password: []byte("no")}, OpenOptions{}); err == nil {
		t.Fatal("the copy opened with a wrong password")
	}
}

func TestResizeErrors(t *testing.T) {
	src, _ := mkSized(t, 16, 8, CreateOptions{})
	for name, tc := range map[string]struct {
		dst  Backing
		u    Unlock
		o    OpenOptions
		ro   ResizeOptions
		want error
	}{
		"rebind counter":         {newGrow(), pwUnlock(), OpenOptions{RebindFor: func(uint32, []byte) (Counter, error) { return nil, nil }}, ResizeOptions{Entries: 20}, ErrOption},
		"rebind derived counter": {newGrow(), pwUnlock(), OpenOptions{RebindDerived: func(uint32, []byte, []byte) (Counter, error) { return nil, nil }}, ResizeOptions{Entries: 20}, ErrOption},
		"destination not empty":  {newMem(100), pwUnlock(), OpenOptions{}, ResizeOptions{Entries: 20}, ErrOption},
		"destination size":       {sizeErr{newGrow()}, pwUnlock(), OpenOptions{}, ResizeOptions{Entries: 20}, errCut},
		"wrong password":         {newGrow(), Unlock{Password: []byte("no")}, OpenOptions{}, ResizeOptions{Entries: 20}, nil},
		"same size":              {newGrow(), pwUnlock(), OpenOptions{}, ResizeOptions{Entries: 8}, ErrResizeSame},
		"too many entries":       {newGrow(), pwUnlock(), OpenOptions{}, ResizeOptions{Entries: format.MaxJournal + 1}, format.ErrGeometry},
	} {
		_, err := Resize(ctx, src, tc.u, tc.o, tc.dst, tc.ro)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Entries 0 on a container already at the default: the same-size refusal.
	d, _ := mkSized(t, 16, DefaultJournal(16), CreateOptions{})
	if _, err := Resize(ctx, d, pwUnlock(), OpenOptions{}, newGrow(), ResizeOptions{}); !errors.Is(err, ErrResizeSame) {
		t.Errorf("default size: %v", err)
	}
}

// Kill the copy at every write and every sync: the source stays as it was and
// the copy is never reported as done.
func TestResizeCrashLeavesSourceIntact(t *testing.T) {
	src, m := mkSized(t, 16, 8, CreateOptions{})
	before := append([]byte(nil), src.b...)
	ok := newGrow()
	if _, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, ok, ResizeOptions{Entries: 20}); err != nil {
		t.Fatal(err)
	}
	writes, syncs := ok.writes, ok.syncs
	if writes < 5 || syncs < 2 {
		t.Fatalf("a resize wrote %d times and synced %d times", writes, syncs)
	}
	for k := 0; k < writes; k++ {
		dst := newGrow()
		dst.failAfter = k
		if _, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, dst, ResizeOptions{Entries: 20}); err == nil {
			t.Fatalf("a copy cut at write %d was reported done", k)
		}
		if !bytes.Equal(src.b, before) {
			t.Fatalf("the source changed when the copy was cut at write %d", k)
		}
	}
	for k := 1; k <= syncs; k++ {
		dst := newGrow()
		dst.syncCut = k
		if _, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, dst, ResizeOptions{Entries: 20}); !errors.Is(err, errCut) {
			t.Fatalf("a copy whose sync %d failed: %v", k, err)
		}
		if !bytes.Equal(src.b, before) {
			t.Fatalf("the source changed when sync %d failed", k)
		}
	}
	if !bytes.Equal(readAll(t, reopen(t, src, pwUnlock())), m) {
		t.Fatal("the source no longer holds its content")
	}
}

// Fail every read, from the first to the last: each is an error, never a copy
// reported done, and the source is not written.
func TestResizeReadFailures(t *testing.T) {
	src, _ := mkSized(t, 16, 8, CreateOptions{})
	before := append([]byte(nil), src.b...)
	for at := 1; ; at++ {
		if at > 100000 {
			t.Fatal("no end to the reads")
		}
		_, err := Resize(ctx, &readCut{Backing: src, at: at}, pwUnlock(), OpenOptions{}, newGrow(), ResizeOptions{Entries: 20})
		if !bytes.Equal(src.b, before) {
			t.Fatalf("the source changed with the read %d failing", at)
		}
		if err == nil {
			if at < 20 {
				t.Fatalf("read %d failing was not noticed", at)
			}
			return
		}
	}
}

// A random source that runs dry is an error wherever it happens: in the two
// fills (44 bytes each) or in sealing the header.
func TestResizeRandomExhausted(t *testing.T) {
	src, _ := mkSized(t, 16, 8, CreateOptions{})
	failed := 0
	for n := int64(0); n < 400; n++ {
		_, err := Resize(ctx, src, pwUnlock(), OpenOptions{Rand: io.LimitReader(rand.Reader, n)}, newGrow(), ResizeOptions{Entries: 20})
		if err != nil {
			failed++
		} else if failed < 89 {
			t.Fatalf("a source of %d bytes sufficed, after %d refusals", n, failed)
		}
	}
	if failed < 89 || failed == 400 {
		t.Fatalf("%d refusals", failed)
	}
}

// The same on the copy: its reads fail during the verification.
type dstReadCut struct {
	growMem
	n, at int
}

func (d *dstReadCut) ReadAt(p []byte, off int64) (int, error) {
	d.n++
	if d.at > 0 && d.n >= d.at {
		return 0, errCut
	}
	return d.growMem.ReadAt(p, off)
}

func TestResizeVerificationReadFailures(t *testing.T) {
	src, _ := mkSized(t, 16, 8, CreateOptions{})
	for at := 1; ; at++ {
		if at > 100000 {
			t.Fatal("no end to the reads")
		}
		d := &dstReadCut{growMem: *newGrow(), at: at}
		_, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, d, ResizeOptions{Entries: 20})
		if err == nil {
			if at < 20 {
				t.Fatalf("read %d failing on the copy was not noticed", at)
			}
			return
		}
	}
}

func TestVerifyResizedRefuses(t *testing.T) {
	src, _ := mkSized(t, 16, 8, CreateOptions{})
	dst := newGrow()
	info, err := Resize(ctx, src, pwUnlock(), OpenOptions{}, dst, ResizeOptions{Entries: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyResized(ctx, dst, pwUnlock(), OpenOptions{}, nil, info); err != nil {
		t.Fatal(err)
	}
	for name, w := range map[string]ResizeInfo{
		"entries": {Entries: 21, Sectors: info.Sectors, Hash: info.Hash},
		"sectors": {Entries: 20, Sectors: info.Sectors + 1, Hash: info.Hash},
		"hash":    {Entries: 20, Sectors: info.Sectors, Hash: [32]byte{1}},
	} {
		if err := verifyResized(ctx, dst, pwUnlock(), OpenOptions{}, nil, w); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A flipped byte in a sector of the copy.
	geo := mustGeo(t, 16, 20)
	bad := dst.clone()
	bad.b[geo.DataOff+100] ^= 1
	if err := verifyResized(ctx, bad, pwUnlock(), OpenOptions{}, nil, info); err == nil {
		t.Error("a corrupted copy verified")
	}
	// A copy that does not open.
	if err := verifyResized(ctx, newMem(1<<20), pwUnlock(), OpenOptions{}, nil, info); err == nil {
		t.Error("an empty copy verified")
	}
}

// resizeCounter runs a resize with a counter of each kind the library accepts
// and checks the rollback story end to end.
func TestResizeCounterCoherence(t *testing.T) {
	name := bytes9()
	type variant struct {
		ctr    func() (Counter, *uint64)
		create func(Counter) CreateOptions
		open   func(Counter) OpenOptions
	}
	fc := func() (Counter, *uint64) {
		c := &fakeCounter{handle: 0x01800001, name: name, v: 1000}
		return c, &c.v
	}
	ic := func() (Counter, *uint64) {
		c := newIDCounter(0xA1, 1000)
		return c, &c.v
	}
	for vname, v := range map[string]variant{
		"plain": {fc,
			func(c Counter) CreateOptions { return CreateOptions{Counter: c} },
			func(c Counter) OpenOptions { return OpenOptions{Counter: c} }},
		"identity pinned": {ic,
			func(c Counter) CreateOptions { return CreateOptions{Counter: c} },
			func(c Counter) OpenOptions { return OpenOptions{Counter: c} }},
		"counter for": {fc,
			func(c Counter) CreateOptions { return CreateOptions{Counter: c} },
			func(c Counter) OpenOptions {
				return OpenOptions{CounterFor: func(uint32, []byte) (Counter, error) { return c, nil }}
			}},
		"derived auth": {fc,
			func(c Counter) CreateOptions {
				return CreateOptions{NewCounter: func([]byte) (Counter, error) { return c, nil }}
			},
			func(c Counter) OpenOptions {
				return OpenOptions{CounterDerived: func(uint32, []byte, []byte) (Counter, error) { return c, nil }}
			}},
	} {
		t.Run(vname, func(t *testing.T) {
			ctr, val := v.ctr()
			src, m := mkSized(t, 16, 8, v.create(ctr))
			before := *val
			dst := newGrow()
			if _, err := Resize(ctx, src, pwUnlock(), v.open(ctr), dst, ResizeOptions{Entries: 20}); err != nil {
				t.Fatal(err)
			}
			// The source's own mount moved the counter once; the verification of
			// the copy did not move it.
			if *val != before+1 {
				t.Fatalf("counter %d -> %d: the resize must move it exactly once", before, *val)
			}
			// The copy is accepted, not refused as a rollback, and holds the content.
			c, err := Open(ctx, dst, pwUnlock(), v.open(ctr))
			if err != nil {
				t.Fatalf("the copy is refused: %v", err)
			}
			if !bytes.Equal(readAll(t, c), m) || !c.Info().RollbackProtected {
				t.Fatal("the copy lost its content or its counter")
			}
			c.Close()
			// And now the old file is refused as an older copy.
			if _, err := Open(ctx, src, pwUnlock(), v.open(ctr)); !errors.Is(err, ErrRollback) {
				t.Fatalf("the old file after the copy was mounted: %v", err)
			}
		})
	}
}

func bytes9() []byte { return bytes.Repeat([]byte{9}, 34) }

// A copy mounted twice stays accepted, and a copy made from a copy is too.
func TestResizeChain(t *testing.T) {
	ctr := &fakeCounter{handle: 0x01800001, name: bytes9(), v: 5}
	src, m := mkSized(t, 16, 8, CreateOptions{Counter: ctr})
	o := OpenOptions{Counter: ctr}
	a := newGrow()
	if _, err := Resize(ctx, src, pwUnlock(), o, a, ResizeOptions{Entries: 20}); err != nil {
		t.Fatal(err)
	}
	b := newGrow()
	if _, err := Resize(ctx, a, pwUnlock(), o, b, ResizeOptions{Entries: 9}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c, err := Open(ctx, b, pwUnlock(), o)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(readAll(t, c), m) {
			t.Fatal("content differs")
		}
		c.Close()
	}
	if _, err := Open(ctx, a, pwUnlock(), o); !errors.Is(err, ErrRollback) {
		t.Fatalf("the middle copy: %v", err)
	}
}

func TestReadOnlyCounter(t *testing.T) {
	f := &fakeCounter{handle: 1, name: []byte("n"), v: 7}
	if _, ok := readOnlyCounter(f).(IdentifiedCounter); ok {
		t.Fatal("a plain counter became an identified one")
	}
	i := newIDCounter(3, 7)
	r := readOnlyCounter(i)
	if _, ok := r.(IdentifiedCounter); !ok {
		t.Fatal("the identity was lost")
	}
	for _, c := range []Counter{readOnlyCounter(f), r} {
		if err := c.Increment(); err != nil {
			t.Fatal(err)
		}
	}
	if f.v != 7 || i.v != 7 {
		t.Fatalf("the increment went through: %d %d", f.v, i.v)
	}
}
