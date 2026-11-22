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

// shareWrite writes mib MiB to a file on the loopback SMB share of c through a
// real SMB client, then stops the share (its final commit is in the time).
func shareWrite(t *testing.T, c *theca.Container, mib int, every time.Duration) time.Duration {
	t.Helper()
	s, err := share.Start(context.Background(), c, share.Options{Addr: "127.0.0.1:0", Name: "theca", Sync: every})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: s.User(), Password: s.Password()}}
	sess, err := d.Dial(ctx, strings.TrimSuffix(strings.TrimPrefix(s.URL(), "smb://"), "/theca"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sess.Mount("theca")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32<<10)
	start := time.Now()
	f, err := fs.Create("big.bin")
	if err != nil {
		t.Fatal(err)
	}
	for w := 0; w < mib*32; w++ {
		if _, err := f.Write(buf); err != nil {
			t.Fatalf("write %d: %v", w, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	sess.Logoff()
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

// TestResizeShareCost measures what `theca journal resize` buys: the SMB share
// write speed on a container made with a journal of THECA_RESIZE_FROM entries
// (64: what v0.26.0 created) before the resize and after it, to the default
// size, in interleaved rounds on fresh identical containers. It also times the
// resize itself.
//
//	THECA_SHARE_RESIZE=3 GOMAXPROCS=1 gotest -run TestResizeShareCost -v ./internal/synccost
func TestResizeShareCost(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("THECA_SHARE_RESIZE"))
	if rounds == 0 {
		t.Skip("measurement: set THECA_SHARE_RESIZE=<rounds>")
	}
	mib, _ := strconv.Atoi(os.Getenv("THECA_SYNC_MIB"))
	if mib == 0 {
		mib = 64
	}
	from := uint64(64)
	if s := os.Getenv("THECA_RESIZE_FROM"); s != "" {
		var err error
		if from, err = strconv.ParseUint(s, 10, 32); err != nil {
			t.Fatal(err)
		}
	}
	kdf.Table = [3]kdf.Profile{{Time: 1, MemKiB: 64, Threads: 1}, {Time: 2, MemKiB: 64, Threads: 2}, {Time: 1, MemKiB: 128, Threads: 1}}
	size := int64(mib) << 21
	u := theca.Unlock{Password: []byte("correct horse")}
	var before, after, resizeTimes []time.Duration
	for r := 0; r < rounds; r++ {
		dir := t.TempDir()
		mk := func(name string) (*os.File, *theca.Container) {
			osf, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := osf.Truncate(size + 64<<20); err != nil {
				t.Fatal(err)
			}
			c, _, err := theca.Create(theca.FileBacking{File: osf}, theca.CreateOptions{
				Sectors: uint64(size) / theca.SectorSize, JournalEntries: uint32(from), Password: u.Password, Policy: theca.PolicyAny})
			if err != nil {
				t.Fatal(err)
			}
			if err := share.Format(c); err != nil {
				t.Fatal(err)
			}
			if err := c.Sync(); err != nil {
				t.Fatal(err)
			}
			return osf, c
		}
		// Before: the container as created.
		osf, c := mk("old.theca")
		before = append(before, shareWrite(t, c, mib, 5*time.Second))
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		osf.Close()

		// After: an identical fresh one, resized to the default, then mounted.
		src, c := mk("src.theca")
		c.Close()
		dst, err := os.OpenFile(filepath.Join(dir, "new.theca"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		info, err := theca.Resize(context.Background(), theca.FileBacking{File: src}, u, theca.OpenOptions{}, theca.FileBacking{File: dst}, theca.ResizeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		resizeTimes = append(resizeTimes, time.Since(start))
		if r == 0 {
			t.Logf("resize %d -> %d entries, %d bytes", info.OldEntries, info.Entries, info.Size)
		}
		src.Close()
		c, err = theca.Open(context.Background(), theca.FileBacking{File: dst}, u, theca.OpenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		after = append(after, shareWrite(t, c, mib, 5*time.Second))
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		dst.Close()
	}
	med := func(d []time.Duration) time.Duration {
		s := slices.Clone(d)
		slices.Sort(s)
		return s[len(s)/2]
	}
	t.Logf("share write %d MiB: before (journal %d) median %v = %.1f MiB/s, min %v max %v", mib, from, med(before), float64(mib)/med(before).Seconds(),
		slices.Min(before), slices.Max(before))
	t.Logf("share write %d MiB: after the resize median %v = %.1f MiB/s, min %v max %v", mib, med(after), float64(mib)/med(after).Seconds(),
		slices.Min(after), slices.Max(after))
	t.Logf("resize of a %d MiB volume: median %v", mib*2, med(resizeTimes))
}
