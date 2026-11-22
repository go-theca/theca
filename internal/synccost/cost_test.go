// Package synccost holds a measurement, not a check (go-theca/theca#73): how
// many flushes a sustained write costs and what that does to its throughput,
// against the journal size. It has no code of its own and its test is skipped
// unless asked for.
package synccost

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/internal/format"
	"github.com/go-theca/theca/internal/kdf"
)

type counting struct {
	theca.FileBacking
	syncs int
}

func (c *counting) Sync() error { c.syncs++; return c.FileBacking.Sync() }

// TestSyncCost writes THECA_SYNC_MIB MiB through Container.WriteAt in 1 MiB
// calls, for each journal size, in interleaved rounds:
//
//	THECA_SYNC_COST=5 THECA_SYNC_MIB=64 GOMAXPROCS=1 gotest -run TestSyncCost -v ./internal/synccost
func TestSyncCost(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("THECA_SYNC_COST"))
	if rounds == 0 {
		t.Skip("measurement: set THECA_SYNC_COST=<rounds>")
	}
	mib, _ := strconv.Atoi(os.Getenv("THECA_SYNC_MIB"))
	if mib == 0 {
		mib = 64
	}
	kdf.Table = [3]kdf.Profile{{Time: 1, MemKiB: 64, Threads: 1}, {Time: 2, MemKiB: 64, Threads: 2}, {Time: 1, MemKiB: 128, Threads: 1}}
	sectors := uint64(mib) << 8
	var sizes []uint32
	spec := os.Getenv("THECA_SYNC_JOURNALS")
	if spec == "" {
		spec = "8,64,256,1024,4096"
	}
	for _, f := range strings.Split(spec, ",") {
		n, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, uint32(n))
	}
	times := map[uint32][]time.Duration{}
	syncs := map[uint32]int{}
	buf := make([]byte, 1<<20)
	for r := 0; r < rounds; r++ {
		for _, j := range sizes {
			dir := t.TempDir()
			jn := j
			geo, err := format.NewGeometry(sectors, jn)
			if err != nil {
				t.Fatal(err)
			}
			osf, err := os.OpenFile(filepath.Join(dir, "c.theca"), os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := osf.Truncate(int64(geo.End)); err != nil {
				t.Fatal(err)
			}
			f := &counting{FileBacking: theca.FileBacking{File: osf}}
			c, _, err := theca.Create(f, theca.CreateOptions{Sectors: sectors, JournalEntries: jn, Password: []byte("correct horse"), Policy: theca.PolicyAny})
			if err != nil {
				t.Fatal(err)
			}
			f.syncs = 0
			start := time.Now()
			for off := int64(0); off < int64(mib)<<20; off += int64(len(buf)) {
				if _, err := c.WriteAt(buf, off); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Sync(); err != nil {
				t.Fatal(err)
			}
			times[j] = append(times[j], time.Since(start))
			syncs[j] = f.syncs
			c.Close()
			osf.Close()
		}
	}
	for _, j := range sizes {
		s := slices.Clone(times[j])
		slices.Sort(s)
		med := s[len(s)/2]
		t.Logf("journal=%-5d median %-12v min %-12v max %-12v %.1f MiB/s, %d syncs", j, med, s[0], s[len(s)-1], float64(mib)/med.Seconds(), syncs[j])
	}
}
