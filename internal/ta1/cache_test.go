package ta1

import (
	"bytes"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
)

// The cached AES schedule and HMAC state (go-theca/theca#8, #9) must give
// exactly what a cipher and an HMAC built from scratch give, for every key a
// Keys value holds over its life.

func TestCacheMatchesFreshState(t *testing.T) {
	k := testKeys(t)
	var cid [16]byte
	var seed [SeedSize]byte
	rand.Read(cid[:])
	plain := make([]byte, SectorSize)
	rand.Read(plain)
	for i := range 3 { // first use builds the cache, the rest reuse it
		rand.Read(seed[:])
		got := make([]byte, SectorSize)
		k.cascade(got, plain, &seed)
		want := make([]byte, SectorSize)
		xchacha20(&k.Kc, (*[24]byte)(seed[:24]), want, plain)
		aes256ctr(&k.Ka, (*[16]byte)(seed[24:]), want, want)
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d: cascade differs from a fresh AES-256-CTR", i)
		}
		tag := k.SectorTag(&cid, uint64(i), &seed, got)
		var idx [8]byte
		idx[0] = byte(i)
		msg := append([]byte{byte(len(LabelLeaf))}, LabelLeaf...)
		msg = append(append(append(append(msg, cid[:]...), idx[:]...), seed[:]...), got...)
		if ref := refHMAC(k.Km[:], msg); !bytes.Equal(tag[:], ref[:SectorTagSize]) {
			t.Fatalf("round %d: tag differs from RFC 2104 HMAC", i)
		}
	}
}

func TestCacheFollowsAChangedKey(t *testing.T) {
	// A copy shares the cache pointer; changing the copy's key must rebuild,
	// not reuse the original's schedule, and the original must still work.
	a := testKeys(t)
	var seed [SeedSize]byte
	plain := []byte("sixteen bytes!!!")
	ca := make([]byte, len(plain))
	a.cascade(ca, plain, &seed)
	b := *a
	b.Ka[0] ^= 1
	b.Km[0] ^= 1
	cb := make([]byte, len(plain))
	b.cascade(cb, plain, &seed)
	want := make([]byte, len(plain))
	xchacha20(&b.Kc, (*[24]byte)(seed[:24]), want, plain)
	aes256ctr(&b.Ka, (*[16]byte)(seed[24:]), want, want)
	if !bytes.Equal(cb, want) || bytes.Equal(cb, ca) {
		t.Fatal("a changed Ka reused the old schedule")
	}
	if a.MAC(LabelNode, plain) == b.MAC(LabelNode, plain) {
		t.Fatal("a changed Km reused the old HMAC state")
	}
	again := make([]byte, len(plain))
	a.cascade(again, plain, &seed)
	if !bytes.Equal(again, ca) {
		t.Fatal("the original key no longer gives its own output")
	}
}

func TestCacheConcurrentUse(t *testing.T) {
	k := testKeys(t)
	var cid [16]byte
	var seed [SeedSize]byte
	ct := make([]byte, SectorSize)
	want := k.SectorTag(&cid, 7, &seed, ct)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if k.SectorTag(&cid, 7, &seed, ct) != want {
					t.Error("concurrent tags differ")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// mustPanic reports whether f panics.
func mustPanic(f func()) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	f()
	return false
}

// Zeroize wipes the keyed HMAC states (go-theca/theca#74 item 4): the MAC
// the cache held is unusable afterwards.
func TestZeroizeWipesTheMAC(t *testing.T) {
	k := testKeys(t)
	k.MAC(LabelNode, []byte("x"))
	m := k.c.mac
	k.Zeroize()
	if !mustPanic(func() { m.Write([]byte("x")) }) {
		t.Fatal("Zeroize left the HMAC state usable: it was not wiped")
	}
}

// A changed Km rebuilds the MAC and wipes the one it replaces.
func TestRebuildWipesTheOldMAC(t *testing.T) {
	k := testKeys(t)
	k.MAC(LabelNode, []byte("x"))
	old := k.c.mac
	k.Km[0] ^= 1
	k.MAC(LabelNode, []byte("x"))
	if k.c.mac == old {
		t.Fatal("MAC not rebuilt")
	}
	if !mustPanic(func() { old.Reset() }) {
		t.Fatal("the replaced HMAC state was not wiped")
	}
}

func TestZeroizeDropsTheCache(t *testing.T) {
	k := testKeys(t)
	k.MAC(LabelNode, []byte("x")) // build it
	c := k.c
	k.Zeroize()
	if k.c != nil || c.block != nil || c.mac != nil || c.ka != [KeySize]byte{} || c.km != [KeySize]byte{} {
		t.Fatal("cache survived Zeroize")
	}
	k.Zeroize() // twice is fine
	// A zeroised Keys still works (with the zero key), building a new cache.
	k.MAC(LabelNode, []byte("x"))
	if k.c == nil {
		t.Fatal("no cache rebuilt")
	}
}

func TestLiteralKeysBuildTheCacheLazily(t *testing.T) {
	k := &Keys{}
	if k.c != nil {
		t.Fatal("literal has a cache")
	}
	k.MAC(LabelEmpty)
	if k.c == nil {
		t.Fatal("cache not built on first use")
	}
}

func TestLabelLongerThanScratchPanicsAndUnlocks(t *testing.T) {
	k := testKeys(t)
	func() {
		defer func() {
			if r := recover(); r == nil || !strings.Contains(r.(string), "scratch") {
				t.Fatalf("recover: %v", r)
			}
		}()
		k.mac().label(strings.Repeat("x", 64))
	}()
	// The lock was released: the next MAC does not deadlock.
	k.MAC(LabelNode, []byte("y"))
}

func TestSectorPathAllocations(t *testing.T) {
	k := testKeys(t)
	var cid [16]byte
	seed := new([SeedSize]byte)
	ct := make([]byte, SectorSize)
	dst := make([]byte, SectorSize)
	k.SectorTag(&cid, 1, seed, ct) // build the cache
	if n := testing.AllocsPerRun(100, func() { k.SectorTag(&cid, 1, seed, ct) }); n != 0 {
		t.Errorf("SectorTag: %v allocations, want 0", n)
	}
	// NewCTR allocates its counter state, and chacha20's cipher value
	// escapes: 2 per sector at most, down from 2 for AES alone before.
	if n := testing.AllocsPerRun(100, func() { k.cascade(dst, ct, seed) }); n > 2 {
		t.Errorf("cascade: %v allocations, want at most 2", n)
	}
}
