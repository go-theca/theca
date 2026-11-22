package theca

import (
	"bytes"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

func TestDefaultJournal(t *testing.T) {
	for _, tc := range []struct {
		sectors uint64
		want    uint32
	}{
		{1, 64},
		{200, 64},
		{1024, 64},           // the floor: 1024/16 = 64
		{16*64 + 15, 64},     // rounds down onto the floor
		{16 * 65, 65},        // first size above the floor
		{16384, 1024},        // 64 MiB
		{16 * 4095, 4095},    // one under the cap
		{16 * 4096, 4096},    // the cap
		{16*4096 + 16, 4096}, // above it
		{1 << 40, 4096},
	} {
		if got := DefaultJournal(tc.sectors); got != tc.want {
			t.Errorf("DefaultJournal(%d) = %d, want %d", tc.sectors, got, tc.want)
		}
	}
	if DefaultJournalEntries != 64 || MaxDefaultJournalEntries != 4096 {
		t.Error("the default journal bounds moved: update DESIGN I12 and the README")
	}
}

// TestCreateUsesDefaultJournal: a zero JournalEntries means DefaultJournal of
// the container's size, and an explicit one is kept.
func TestCreateUsesDefaultJournal(t *testing.T) {
	for _, tc := range []struct {
		sectors uint64
		journal uint32
		want    uint32
	}{
		{2048, 0, 128},
		{200, 0, 64},
		{2048, 40, 40},
	} {
		geo, err := format.NewGeometry(tc.sectors, tc.want)
		if err != nil {
			t.Fatal(err)
		}
		f := newMem(int(geo.End))
		c, _, err := Create(f, CreateOptions{Sectors: tc.sectors, JournalEntries: tc.journal,
			Password: []byte("correct horse"), Policy: PolicyAny})
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		if got := c.Info().JournalEntries; got != tc.want {
			t.Errorf("sectors %d journal %d: %d entries, want %d", tc.sectors, tc.journal, got, tc.want)
		}
	}
}

// TestWriteAtBatchesIntoOneTransaction (go-theca/theca#73): a WriteAt that
// fits the journal touches the backing's flush not at all, and the Sync after
// it is ONE epoch step, however many sectors were written.
func TestWriteAtBatchesIntoOneTransaction(t *testing.T) {
	c, f, _ := createJ(t, PolicyAny, 64)
	e0, s0 := c.Info().Epoch, f.syncs
	if n, err := c.WriteAt(rnd(40*SectorSize), 0); err != nil || n != 40*SectorSize {
		t.Fatalf("write: %d %v", n, err)
	}
	if f.syncs != s0 || c.Info().Epoch != e0 {
		t.Fatalf("WriteAt of 40 sectors committed: %d syncs, epoch %d -> %d", f.syncs-s0, e0, c.Info().Epoch)
	}
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if c.Info().Epoch != e0+1 {
		t.Fatalf("Sync stepped the epoch %d -> %d, want one step", e0, c.Info().Epoch)
	}
}

// TestCrashInMultiTransactionWriteAt: one WriteAt larger than the journal is
// several transactions. Cut the power at every backing write, and fail every
// flush in turn: after reopening, Verify passes (every tag and the tree) and
// the range holds whole sectors, each exactly old or exactly new, the new ones
// forming a prefix (transactions commit in order, each atomically).
func TestCrashInMultiTransactionWriteAt(t *testing.T) {
	const first, n = 10, 12
	base, f, _ := createJ(t, PolicyAny, 8)
	old := rnd(n * SectorSize)
	if _, err := base.WriteAt(old, first*SectorSize); err != nil {
		t.Fatal(err)
	}
	if err := base.Sync(); err != nil {
		t.Fatal(err)
	}
	fresh := rnd(n * SectorSize)

	run := func(img *memFile) error {
		c := reopen(t, img, pwUnlock())
		e0 := c.Info().Epoch
		if _, err := c.WriteAt(fresh, first*SectorSize); err != nil {
			return err
		}
		err := c.Sync()
		if err == nil && c.Info().Epoch < e0+2 {
			t.Fatalf("the write was one transaction (%d -> %d): the test needs several", e0, c.Info().Epoch)
		}
		return err
	}
	probe := f.clone()
	w0, s0 := probe.writes, probe.syncs
	if err := run(probe); err != nil {
		t.Fatal(err)
	}
	writes, syncs := probe.writes-w0, probe.syncs-s0

	check := func(label string, img *memFile, err error, complete bool) {
		t.Helper()
		if complete && err != nil {
			t.Fatalf("%s: complete run failed: %v", label, err)
		}
		if !complete && err == nil {
			t.Fatalf("%s: survived the cut", label)
		}
		img.failAfter, img.syncCut = -1, 0
		r := reopen(t, img, pwUnlock())
		defer r.Close()
		if got, err := r.Verify(); err != nil || got != testSectors {
			t.Fatalf("%s: verify %d %v", label, got, err)
		}
		got := make([]byte, n*SectorSize)
		if _, err := r.ReadAt(got, first*SectorSize); err != nil {
			t.Fatalf("%s: read: %v", label, err)
		}
		sawOld := false
		for s := 0; s < n; s++ {
			sec := got[s*SectorSize : (s+1)*SectorSize]
			switch {
			case bytes.Equal(sec, fresh[s*SectorSize:(s+1)*SectorSize]):
				if sawOld {
					t.Fatalf("%s: sector %d is new after an old one", label, s)
				}
			case bytes.Equal(sec, old[s*SectorSize:(s+1)*SectorSize]):
				sawOld = true
			default:
				t.Fatalf("%s: sector %d is neither old nor new", label, s)
			}
		}
		if complete && !bytes.Equal(got, fresh) {
			t.Fatalf("%s: a complete run lost data", label)
		}
	}
	for cut := 0; cut <= writes; cut++ {
		img := f.clone()
		img.failAfter = img.writes + cut
		check("write cut", img, run(img), cut == writes)
	}
	for cut := 1; cut <= syncs+1; cut++ {
		img := f.clone()
		img.syncCut = img.syncs + cut
		check("sync cut", img, run(img), cut == syncs+1)
	}
}
