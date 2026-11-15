package bench

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-scikit/refbench"
	"github.com/go-scikit/refbench/rbtest"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"

	"github.com/go-theca/theca/internal/ta1"
)

// fixture is one sector's worth of fixed inputs, shared by both sides.
type fixture struct {
	k      *ta1.Keys
	cid    [16]byte
	idx    uint64
	seed   [ta1.SeedSize]byte
	plain  []byte
	prefix []byte // label(leaf) || cid || u64(idx) || seed: the tag input before C
	block  cipher.Block
}

type zeroReader struct{ seed *[ta1.SeedSize]byte }

// Read hands out the fixture's seed, so SealSector uses the same one as C.
func (z zeroReader) Read(b []byte) (int, error) { return copy(b, z.seed[:]), nil }

func newFixture(t testing.TB) *fixture {
	ms := make([]byte, ta1.MSSize)
	for i := range ms {
		ms[i] = byte(i*7 + 1)
	}
	k, err := ta1.FromBytes(ms)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{k: k, idx: 123456}
	for i := range f.cid {
		f.cid[i] = byte(0xc0 + i)
	}
	for i := range f.seed {
		f.seed[i] = byte(0x50 + i)
	}
	f.plain = make([]byte, SectorSize)
	for i := range f.plain {
		f.plain[i] = byte(i * 13)
	}
	f.prefix = append([]byte{byte(len(ta1.LabelLeaf))}, ta1.LabelLeaf...)
	f.prefix = append(f.prefix, f.cid[:]...)
	f.prefix = binary.LittleEndian.AppendUint64(f.prefix, f.idx)
	f.prefix = append(f.prefix, f.seed[:]...)
	if err := Init(f.k.Ka[:], f.k.Km[:]); err != nil {
		t.Fatal(err)
	}
	return f
}

// The Go component bodies are the exact code of internal/ta1's cascade: the
// XChaCha20 cipher is built per sector (it is keyed by the per-sector
// nonce); the AES-256 key schedule is built once per key and only the CTR
// state per sector (go-theca/theca#8).
func goXChaCha(f *fixture, buf []byte) {
	c, _ := chacha20.NewUnauthenticatedCipher(f.k.Kc[:], f.seed[:24])
	c.XORKeyStream(buf, buf)
}

func goAESCTR(f *fixture, buf []byte) {
	if f.block == nil {
		f.block, _ = aes.NewCipher(f.k.Ka[:])
	}
	cipher.NewCTR(f.block, f.seed[24:]).XORKeyStream(buf, buf)
}

// Argon2id at profile 1's time and memory (t=3, 64 MiB), one lane: libsodium
// has no multi-lane Argon2id, and the comparison is single-core anyway.
const (
	argonT      = 3
	argonMemKiB = 64 << 10
)

var argonSalt = []byte("theca-bench-salt") // 16 bytes, libsodium's salt size

// TestParity: both sides produce the same bytes for every case before any
// time is compared.
func TestParity(t *testing.T) {
	f := newFixture(t)
	a, b := bytes.Clone(f.plain), bytes.Clone(f.plain)
	goXChaCha(f, a)
	if err := XChaCha20(b, f.seed[:24], f.k.Kc[:], 1); err != nil || !bytes.Equal(a, b) {
		t.Fatalf("xchacha20 differs: %v", err)
	}
	goAESCTR(f, a)
	if err := AES256CTR(b, f.seed[24:], 1); err != nil || !bytes.Equal(a, b) {
		t.Fatalf("aes-256-ctr differs: %v", err)
	}
	// a is now the TA1 ciphertext of plain.
	var cTag [32]byte
	goTag := f.k.SectorTag(&f.cid, f.idx, &f.seed, a)
	if err := Tag(cTag[:], f.prefix, a, 1); err != nil || !bytes.Equal(goTag[:], cTag[:ta1.SectorTagSize]) {
		t.Fatalf("tag differs: %v", err)
	}
	dst := make([]byte, SectorSize)
	seed, tag, err := f.k.SealSector(&f.cid, f.idx, dst, f.plain, zeroReader{&f.seed})
	if err != nil || seed != f.seed || !bytes.Equal(dst, a) || tag != goTag {
		t.Fatalf("SealSector is not the composition measured: %v", err)
	}
	cdst := make([]byte, SectorSize)
	if err := Seal(cdst, f.plain, f.seed[:], f.k.Kc[:], f.prefix, cTag[:], 1); err != nil || !bytes.Equal(cdst, a) || !bytes.Equal(cTag[:24], tag[:]) {
		t.Fatalf("C seal differs: %v", err)
	}
	if err := Open(cdst, a, f.seed[:], f.k.Kc[:], f.prefix, tag[:], 1); err != nil || !bytes.Equal(cdst, f.plain) {
		t.Fatalf("C open: %v", err)
	}
	bad := tag
	bad[0] ^= 1
	if err := Open(cdst, a, f.seed[:], f.k.Kc[:], f.prefix, bad[:], 1); err == nil {
		t.Fatal("C open accepted a bad tag")
	}
	gk := argon2.IDKey([]byte("password"), argonSalt, argonT, argonMemKiB, 1, 32)
	ck := make([]byte, 32)
	if err := Argon2id(ck, "password", argonSalt, argonT, argonMemKiB, 1); err != nil || !bytes.Equal(gk, ck) {
		t.Fatalf("argon2id differs: %v", err)
	}
}

var sink byte

func timed(fn func(iters int) error) refbench.Timer {
	return func(iters int) (time.Duration, error) {
		t0 := time.Now()
		err := fn(iters)
		return time.Since(t0), err
	}
}

func cases(t testing.TB) []refbench.Case {
	f := newFixture(t)
	buf := bytes.Clone(f.plain)
	cbuf := bytes.Clone(f.plain)
	ct := make([]byte, SectorSize)
	seed, tag, _ := f.k.SealSector(&f.cid, f.idx, ct, f.plain, zeroReader{&f.seed})
	dst := make([]byte, SectorSize)
	out := make([]byte, 32)
	return []refbench.Case{
		{
			Name: "Sector/XChaCha20", Func: "Container.WriteAt",
			Reference: "libsodium crypto_stream_xchacha20_xor", Parity: refbench.ParityExact,
			Go: func(n int) {
				for range n {
					goXChaCha(f, buf)
				}
				sink ^= buf[0]
			},
			Ref: timed(func(n int) error { return XChaCha20(cbuf, f.seed[:24], f.k.Kc[:], n) }),
		},
		{
			Name: "Sector/AES-256-CTR", Func: "Container.WriteAt",
			Reference: "OpenSSL EVP aes-256-ctr (key schedule reused)", Parity: refbench.ParityExact,
			Go: func(n int) {
				for range n {
					goAESCTR(f, buf)
				}
				sink ^= buf[0]
			},
			Ref: timed(func(n int) error { return AES256CTR(cbuf, f.seed[24:], n) }),
		},
		{
			Name: "Sector/Tag (HMAC-SHA-256)", Func: "Container.WriteAt",
			Reference: "OpenSSL EVP_MAC HMAC-SHA256 (key reused)", Parity: refbench.ParityExact,
			Go: func(n int) {
				for range n {
					t := f.k.SectorTag(&f.cid, f.idx, &f.seed, ct)
					sink ^= t[0]
				}
			},
			Ref: timed(func(n int) error { return Tag(out, f.prefix, ct, n) }),
		},
		{
			Name: "Sector/Seal", Func: "Container.WriteAt",
			Reference: "libsodium + OpenSSL, same composition", Parity: refbench.ParityExact,
			Go: func(n int) {
				for range n {
					_, t, _ := f.k.SealSector(&f.cid, f.idx, dst, f.plain, zeroReader{&f.seed})
					sink ^= t[0]
				}
			},
			Ref: timed(func(n int) error { return Seal(dst, f.plain, f.seed[:], f.k.Kc[:], f.prefix, out, n) }),
		},
		{
			Name: "Sector/Open", Func: "Container.ReadAt",
			Reference: "libsodium + OpenSSL, same composition", Parity: refbench.ParityExact,
			Go: func(n int) {
				for range n {
					if f.k.OpenSector(&f.cid, f.idx, dst, ct, &seed, &tag) != nil {
						panic("open failed")
					}
				}
				sink ^= dst[0]
			},
			Ref: timed(func(n int) error { return Open(dst, ct, seed[:], f.k.Kc[:], f.prefix, tag[:], n) }),
		},
		{
			Name: "Argon2id/t3-m64MiB-p1", Func: "PasswordFactor",
			Reference: "libsodium crypto_pwhash ARGON2ID13", Parity: refbench.ParityExact,
			Go: func(n int) {
				for range n {
					k := argon2.IDKey([]byte("password"), argonSalt, argonT, argonMemKiB, 1, 32)
					sink ^= k[0]
				}
			},
			Ref: timed(func(n int) error { return Argon2id(out, "password", argonSalt, argonT, argonMemKiB, n) }),
		},
	}
}

func TestPerf(t *testing.T) {
	rbtest.Perf(t, refbench.CIConfig{Root: "..", Cases: cases(t)}, refbench.Options{
		Repo:        "go-theca/theca",
		RefVersions: Versions(),
	})
}
