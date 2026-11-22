package synccost

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/share"
)

// TestShareCost writes THECA_SYNC_MIB MiB (64 by default) to a file on the
// loopback SMB share of a 2x larger exFAT container, through a real SMB
// client, with the share's own commit every THECA_SYNC_EVERY (5s, the
// `theca open` default), for each journal size, in interleaved rounds. The
// time includes the final commit at Stop. Journal 0 is theca.DefaultJournal.
//
//	THECA_SHARE_COST=3 GOMAXPROCS=1 gotest -run TestShareCost -v ./internal/synccost
func TestShareCost(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("THECA_SHARE_COST"))
	if rounds == 0 {
		t.Skip("measurement: set THECA_SHARE_COST=<rounds>")
	}
	mib, _ := strconv.Atoi(os.Getenv("THECA_SYNC_MIB"))
	if mib == 0 {
		mib = 64
	}
	every := 5 * time.Second
	if s := os.Getenv("THECA_SYNC_EVERY"); s != "" {
		var err error
		if every, err = time.ParseDuration(s); err != nil {
			t.Fatal(err)
		}
	}
	spec := os.Getenv("THECA_SYNC_JOURNALS")
	if spec == "" {
		spec = "64,0"
	}
	var sizes []uint32
	for _, f := range strings.Split(spec, ",") {
		n, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, uint32(n))
	}
	kdf.Table = [3]kdf.Profile{{Time: 1, MemKiB: 64, Threads: 1}, {Time: 2, MemKiB: 64, Threads: 2}, {Time: 1, MemKiB: 128, Threads: 1}}
	size := int64(mib) << 21
	times := map[uint32][]time.Duration{}
	buf := make([]byte, 32<<10)
	for r := 0; r < rounds; r++ {
		for _, j := range sizes {
			osf, err := os.OpenFile(filepath.Join(t.TempDir(), "c.theca"), os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := osf.Truncate(size + 64<<20); err != nil {
				t.Fatal(err)
			}
			c, _, err := theca.Create(theca.FileBacking{File: osf}, theca.CreateOptions{
				Sectors: uint64(size) / theca.SectorSize, JournalEntries: j, Password: []byte("correct horse"), Policy: theca.PolicyAny})
			if err != nil {
				t.Fatal(err)
			}
			if err := share.Format(c); err != nil {
				t.Fatal(err)
			}
			if err := c.Sync(); err != nil {
				t.Fatal(err)
			}
			s, err := share.Start(context.Background(), c, share.Options{Addr: "127.0.0.1:0", Name: "theca", Sync: every})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: s.User(), Password: s.Password()}}
			sess, err := d.Dial(ctx, strings.TrimSuffix(strings.TrimPrefix(s.URL(), "smb://"), "/theca"))
			if err != nil {
				t.Fatal(err)
			}
			fs, err := sess.Mount("theca")
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			f, err := fs.Create("big.bin")
			if err != nil {
				t.Fatal(err)
			}
			for w := 0; w < mib*32; w++ {
				if _, err := f.Write(buf); err != nil {
					t.Fatalf("write %d of %d bytes: %v", w, len(buf), err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			sess.Logoff()
			cancel()
			if err := s.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			times[j] = append(times[j], time.Since(start))
			osf.Close()
		}
	}
	for _, j := range sizes {
		s := slices.Clone(times[j])
		slices.Sort(s)
		med := s[len(s)/2]
		t.Logf("share journal=%-5d median %-12v min %-12v max %-12v %.1f MiB/s", j, med, s[0], s[len(s)-1], float64(mib)/med.Seconds())
	}
}
