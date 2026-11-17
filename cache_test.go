package theca

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/go-theca/theca/internal/format"
)

// bigContainer makes a container of 40 metadata blocks (2560 sectors) with a
// 3-block-ish cache budget, far below what a full pass needs.
func bigContainer(t *testing.T, cacheBytes int) (*Container, *memFile, format.Geometry) {
	t.Helper()
	const sectors, journal = 64 * 40, 32
	geo, err := format.NewGeometry(sectors, journal)
	if err != nil {
		t.Fatal(err)
	}
	f := newMem(int(geo.End))
	c, _, err := Create(f, CreateOptions{Sectors: sectors, JournalEntries: journal,
		Password: []byte("correct horse"), CacheBytes: cacheBytes})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, geo
}

// The cache stays within its budget through a full Verify and a random
// read/write load, the content still agrees with a plain byte slice, and an
// entry evicted between a tamper and the read is authenticated again.
func TestMetadataCacheIsBounded(t *testing.T) {
	c, f, geo := bigContainer(t, 1) // the smallest budget: minCacheEntries
	m := make(model, 64*40*SectorSize)
	rng := rand.New(rand.NewPCG(1, 2))
	// Touch every metadata block, committing as we go.
	for blk := 0; blk < 40; blk++ {
		put(t, c, m, blk*64*SectorSize+rng.IntN(1000), rnd(300))
		if blk%4 == 3 {
			if err := c.Sync(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Verify(); err != nil || n != 64*40 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	if c.meta.Len() > minCacheEntries {
		t.Fatalf("%d clean blocks held after Verify, budget %d", c.meta.Len(), minCacheEntries)
	}
	for i := 0; i < 300; i++ {
		off := rng.IntN(len(m) - 700)
		if i%3 == 0 {
			put(t, c, m, off, rnd(1+rng.IntN(600)))
		} else {
			got := make([]byte, 1+rng.IntN(600))
			if _, err := c.ReadAt(got, int64(off)); err != nil || !bytes.Equal(got, m[off:off+len(got)]) {
				t.Fatalf("read at %d: %v", off, err)
			}
		}
	}
	m.check(t, c)
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	// The peak is the budget plus what a transaction has pinned (dirty blocks
	// are bounded by the journal): never the 40 blocks of the volume.
	if limit := minCacheEntries + 32; c.meta.Peak() > limit {
		t.Fatalf("metadata cache peaked at %d, bound %d", c.meta.Peak(), limit)
	}
	if limit := minCacheEntries + 32 + 8; c.tree.CachePeak() > limit {
		t.Fatalf("node cache peaked at %d, bound %d", c.tree.CachePeak(), limit)
	}

	// Tamper with a metadata block that is not cached any more: the read meets
	// it, because an evicted block is authenticated again.
	var cold = -1
	for b := 0; b < 40; b++ {
		if _, ok := c.meta.Peek(uint64(b)); !ok {
			cold = b
			break
		}
	}
	if cold < 0 {
		t.Fatal("every block is cached")
	}
	f.b[geo.MetaOff+uint64(cold)*4096+10] ^= 1
	if _, err := c.ReadAt(make([]byte, 10), int64(cold*64*SectorSize)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a tampered, evicted block: %v", err)
	}
}

// Close wipes what the caches held.
func TestCloseWipesTheCaches(t *testing.T) {
	c, _, _ := bigContainer(t, 0)
	c.WriteAt(rnd(100), 0)
	c.Sync()
	blk, ok := c.meta.Peek(0)
	if !ok {
		t.Fatal("block 0 is not cached")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blk[:], make([]byte, 4096)) {
		t.Fatal("a cached metadata block was not wiped at Close")
	}
	if c.meta.Len() != 0 || c.tree.CacheLen() != 0 {
		t.Fatalf("caches hold %d and %d entries after Close", c.meta.Len(), c.tree.CacheLen())
	}
}

// The default budget holds the whole of a small volume: nothing is evicted.
func TestDefaultCacheBudget(t *testing.T) {
	c, _, _ := bigContainer(t, 0)
	m := make(model, 64*40*SectorSize)
	for b := 0; b < 40; b++ {
		put(t, c, m, b*64*SectorSize, rnd(10))
	}
	c.Sync()
	c.Verify()
	if c.meta.Len() != 40 {
		t.Fatalf("%d blocks cached under the default budget", c.meta.Len())
	}
}

// BenchmarkReads compares sequential and random 4 KiB reads with the default
// budget (everything cached) and the smallest (constant eviction). Run it on a
// quiet machine, single core, interleaved:
//
//	go test -run '^$' -bench Reads -cpu 1 -count 10 .
func BenchmarkReads(b *testing.B) {
	for _, budget := range []struct {
		name  string
		bytes int
	}{{"default", 0}, {"smallest", 1}} {
		for _, pattern := range []string{"sequential", "random"} {
			b.Run(budget.name+"/"+pattern, func(b *testing.B) {
				const sectors = 64 * 40
				geo, _ := format.NewGeometry(sectors, 32)
				f := newMem(int(geo.End))
				c, _, err := Create(f, CreateOptions{Sectors: sectors, JournalEntries: 32,
					Password: []byte("pw"), CacheBytes: budget.bytes})
				if err != nil {
					b.Fatal(err)
				}
				c.WriteAt(rnd(sectors*SectorSize), 0)
				c.Sync()
				rng := rand.New(rand.NewPCG(1, 2))
				buf := make([]byte, SectorSize)
				b.SetBytes(SectorSize)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					s := i % sectors
					if pattern == "random" {
						s = rng.IntN(sectors)
					}
					if _, err := c.ReadAt(buf, int64(s)*SectorSize); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
