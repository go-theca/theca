// Package memlockcost holds a measurement, not a check (go-theca/theca#68): what
// mlock of the key pages costs, through internal/pin over
// github.com/go-authn/harden/memlock. It has no code of its own, so it adds nothing to
// coverage, and its test is skipped unless asked for.
package memlockcost

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/internal/format"
	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/internal/pin"
)

// TestMlockCost measures open latency and sustained write and read of the
// volume, with --mlock=off and --mlock=auto in interleaved rounds. It runs only
// with THECA_MLOCK_COST=<rounds>, on a single core and a quiet machine:
//
//	THECA_MLOCK_COST=15 GOMAXPROCS=1 go test -count=1 -run TestMlockCost -v ./internal/memlockcost
//
// The volume is read and written through Container.ReadAt/WriteAt, the calls the
// SMB share makes: mlock acts once, at Open, not on that path. The Argon2id
// profile is the test one (64 KiB), so the open figure is the part of Open that
// is NOT the KDF: the relative cost is an upper bound.
func TestMlockCost(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("THECA_MLOCK_COST"))
	if rounds == 0 {
		t.Skip("measurement: set THECA_MLOCK_COST=<rounds>")
	}
	kdf.Table = [3]kdf.Profile{{Time: 1, MemKiB: 64, Threads: 1}, {Time: 2, MemKiB: 64, Threads: 2}, {Time: 1, MemKiB: 128, Threads: 1}}
	const sectors, journal = 2048, 8 // 8 MiB
	geo, err := format.NewGeometry(sectors, journal)
	if err != nil {
		t.Fatal(err)
	}
	osf, err := os.OpenFile(filepath.Join(t.TempDir(), "c.theca"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer osf.Close()
	if err := osf.Truncate(int64(geo.End)); err != nil {
		t.Fatal(err)
	}
	f := theca.FileBacking{File: osf}
	pw := []byte("correct horse")
	c, _, err := theca.Create(f, theca.CreateOptions{Sectors: sectors, JournalEntries: journal, Password: slices.Clone(pw), Policy: theca.PolicyAny})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	vol := int64(sectors) * theca.SectorSize
	buf := make([]byte, 1<<20)
	const writeVol = 2 << 20 // writes commit to the file, which costs seconds per MiB here

	modes := []pin.Mode{pin.Off, pin.BestEffort}
	open, write, read := map[pin.Mode][]time.Duration{}, map[pin.Mode][]time.Duration{}, map[pin.Mode][]time.Duration{}
	defer pin.SetMode(pin.BestEffort)
	for r := 0; r < rounds; r++ {
		for _, m := range modes {
			pin.SetMode(m)
			start := time.Now()
			c, err := theca.Open(context.Background(), f, theca.Unlock{Password: slices.Clone(pw)}, theca.OpenOptions{})
			if err != nil {
				t.Fatal(err)
			}
			open[m] = append(open[m], time.Since(start))
			start = time.Now()
			for off := int64(0); off < writeVol; off += int64(len(buf)) {
				if _, err := c.WriteAt(buf, off); err != nil {
					t.Fatal(err)
				}
			}
			write[m] = append(write[m], time.Since(start))
			start = time.Now()
			for off := int64(0); off < vol; off += int64(len(buf)) {
				if _, err := c.ReadAt(buf, off); err != nil {
					t.Fatal(err)
				}
			}
			read[m] = append(read[m], time.Since(start))
			c.Close()
		}
	}
	report := func(name string, d map[pin.Mode][]time.Duration, per float64, unit string) {
		for _, m := range modes {
			s := slices.Clone(d[m])
			slices.Sort(s)
			med := s[len(s)/2]
			t.Logf("%-6s mlock=%-4v median %-12v min %-12v max %-12v %.1f %s", name, m, med, s[0], s[len(s)-1], per/med.Seconds(), unit)
		}
	}
	mib := float64(vol) / (1 << 20)
	report("open", open, 1, "opens/s")
	report("write", write, float64(writeVol)/(1<<20), "MiB/s")
	report("read", read, mib, "MiB/s")
}
