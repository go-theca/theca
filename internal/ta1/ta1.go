// Package ta1 implements the Theca-A sector construction and the sealed
// object format of suite TA1 (docs/DESIGN.md sections 2, 4.3 and 9.3).
//
// No primitive is invented here. The keystream is the XOR of XChaCha20 and
// AES-256-CTR under independent keys, the tag is HMAC-SHA-256 under a third
// independent key, and the composition is Encrypt-then-MAC.
package ta1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20"
)

// Sizes, in bytes.
const (
	KeySize       = 32
	SeedSize      = 40 // 24-byte XChaCha20 nonce, 16-byte AES-CTR counter block
	SectorSize    = 4096
	SectorTagSize = 24
	SealTagSize   = 32
	// MaxObject bounds every sealed object, so a length derived from
	// untrusted bytes can never ask for a large allocation (DESIGN 10.1).
	MaxObject = 1 << 24
	// SealOverhead is what Seal adds to a plaintext.
	SealOverhead = SeedSize + SealTagSize
)

// Labels. Every one starts with the format version and suite (DESIGN 9.3).
// They are length-prefixed inside the MAC input, so no label is a prefix of
// another by construction.
const (
	LabelLeaf  = "theca/v1/TA1/leaf"
	LabelNode1 = "theca/v1/TA1/n1"
	LabelNode  = "theca/v1/TA1/n"
	LabelEmpty = "theca/v1/TA1/empty"
	// LabelUnwritten marks a never-written sector inside a written block.
	LabelUnwritten = "theca/v1/TA1/unwritten"
	LabelHeader    = "theca/v1/TA1/header"
	LabelSlot      = "theca/v1/TA1/slot"
	LabelJournal   = "theca/v1/TA1/journal"
	LabelCommit    = "theca/v1/TA1/commit"
)

// Errors. ErrAuth is the single answer to "this did not authenticate": a
// wrong key and a corrupted object are indistinguishable (DESIGN 13).
var (
	ErrAuth   = errors.New("ta1: authentication failed")
	ErrSize   = errors.New("ta1: object size out of range")
	ErrNoRand = errors.New("ta1: random source failed")
)

// Keys is the master secret MS = Kc || Ka || Km, three independent draws.
type Keys struct {
	Kc [KeySize]byte // XChaCha20
	Ka [KeySize]byte // AES-256-CTR
	Km [KeySize]byte // HMAC-SHA-256

	c *cache // keyed state built once, not per sector (go-theca/theca#8, #9)
}

// cache holds the AES key schedule and the keyed HMAC state, so a sector
// does not pay a key expansion and two pad compressions. It records the keys
// it was built from and is rebuilt when they differ: Keys is a value type,
// and a copy whose key is then changed shares the pointer.
//
// The expanded AES schedule and the HMAC pads live inside crypto/aes and
// crypto/hmac and cannot be wiped; Zeroize drops them for the GC. Before this
// cache, every sector left one more such copy behind.
type cache struct {
	mu    sync.Mutex
	ka    [KeySize]byte
	km    [KeySize]byte
	block cipher.Block
	mac   hash.Hash
	buf   [64]byte // tag header scratch: label, cid, index, seed
}

func newCache() *cache { return &cache{} }

// state locks the cache for k, rebuilding what no longer matches k's keys.
// The caller unlocks c.mu.
func (k *Keys) state() *cache {
	if k.c == nil {
		k.c = newCache() // only a Keys literal gets here (tests)
	}
	c := k.c
	c.mu.Lock()
	if c.block == nil || c.ka != k.Ka {
		c.block, _ = aes.NewCipher(k.Ka[:]) // fails only on a bad key length
		c.ka = k.Ka
	}
	if c.mac == nil || c.km != k.Km {
		c.mac = hmac.New(sha256.New, k.Km[:])
		c.km = k.Km
	}
	return c
}

// MSSize is the serialised size of Keys.
const MSSize = 3 * KeySize

// Generate draws three independent keys from r.
func Generate(r io.Reader) (*Keys, error) {
	k := Keys{c: newCache()}
	for _, p := range []*[KeySize]byte{&k.Kc, &k.Ka, &k.Km} {
		if _, err := io.ReadFull(r, p[:]); err != nil {
			k.Zeroize()
			return nil, fmt.Errorf("%w: %v", ErrNoRand, err)
		}
	}
	return &k, nil
}

// FromBytes parses a 96-byte master secret.
func FromBytes(b []byte) (*Keys, error) {
	if len(b) != MSSize {
		return nil, fmt.Errorf("ta1: master secret is %d bytes, want %d", len(b), MSSize)
	}
	k := Keys{c: newCache()}
	copy(k.Kc[:], b[:KeySize])
	copy(k.Ka[:], b[KeySize:2*KeySize])
	copy(k.Km[:], b[2*KeySize:])
	return &k, nil
}

// Bytes serialises the master secret.
func (k *Keys) Bytes() []byte {
	b := make([]byte, 0, MSSize)
	b = append(b, k.Kc[:]...)
	b = append(b, k.Ka[:]...)
	return append(b, k.Km[:]...)
}

// Zeroize overwrites the keys. Go's GC may have copied them (DESIGN 13).
func (k *Keys) Zeroize() {
	clear(k.Kc[:])
	clear(k.Ka[:])
	clear(k.Km[:])
	if c := k.c; c != nil {
		c.mu.Lock()
		clear(c.ka[:])
		clear(c.km[:])
		clear(c.buf[:])
		c.block, c.mac = nil, nil
		c.mu.Unlock()
		k.c = nil
	}
}

// Cascade sets dst = src XOR XChaCha20(Kc, seed[0:24]) XOR AES-256-CTR(Ka,
// seed[24:40]). dst and src must be the same slice or not overlap at all. len(dst) must be at least
// len(src).
func (k *Keys) Cascade(dst, src []byte, seed *[SeedSize]byte) error {
	if len(src) > MaxObject || len(dst) < len(src) {
		return ErrSize
	}
	k.cascade(dst, src, seed)
	return nil
}

// cascade is Cascade without the size check; callers have made it.
func (k *Keys) cascade(dst, src []byte, seed *[SeedSize]byte) {
	xchacha20(&k.Kc, (*[24]byte)(seed[:24]), dst[:len(src)], src)
	// The AES key schedule is built once per key, not per object (#8).
	c := k.state()
	cipher.NewCTR(c.block, seed[24:]).XORKeyStream(dst[:len(src)], dst[:len(src)])
	c.mu.Unlock()
}

// xchacha20 XORs src with the XChaCha20 keystream (counter 0). The
// constructor fails only on a bad key or nonce length, which the array types
// rule out, so its error is dropped on purpose.
func xchacha20(key *[32]byte, nonce *[24]byte, dst, src []byte) {
	c, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	c.XORKeyStream(dst, src)
}

// mac locks k's keyed HMAC state and resets it, which restores the
// precomputed pads instead of hashing them again (#9). Every macState must
// end with sum, which unlocks.
func (k *Keys) mac() macState {
	c := k.state()
	c.mac.Reset()
	return macState{c}
}

// macState writes into the cached HMAC. Small fixed fields are copied into
// the cache's scratch buffer before the write: a slice handed to an
// interface method escapes, so writing a caller's stack array directly
// would cost a heap allocation per tag.
type macState struct{ c *cache }

// small writes a field of at most len(buf) bytes through the scratch buffer.
func (m macState) small(b []byte) {
	n := copy(m.c.buf[:], b)
	m.c.mac.Write(m.c.buf[:n])
}

func (m macState) label(l string) {
	if len(l) >= len(m.c.buf) {
		m.c.mu.Unlock()
		panic("ta1: label longer than the scratch buffer: " + l) // labels are constants
	}
	m.c.buf[0] = byte(len(l))
	n := copy(m.c.buf[1:], l)
	m.c.mac.Write(m.c.buf[:1+n])
}

func (m macState) u64(v uint64) {
	binary.LittleEndian.PutUint64(m.c.buf[:8], v)
	m.c.mac.Write(m.c.buf[:8])
}

// write is for caller-owned data of any length (already on the heap).
func (m macState) write(b []byte) { m.c.mac.Write(b) }

// sum finishes the MAC and unlocks the cache.
func (m macState) sum() (out [32]byte) {
	copy(out[:], m.c.mac.Sum(m.c.buf[:0]))
	m.c.mu.Unlock()
	return out
}

// MAC returns HMAC-SHA-256(Km, u8(len(label)) || label || parts...).
// Parts are concatenated as given: callers pass fixed-width or
// length-prefixed fields.
//
// Only the tree labels are accepted. The leaf, header, slot, locator, journal
// and commit labels belong to SectorTag, Seal and their callers, whose inputs
// are framed differently; letting MAC use them would make tag namespaces
// overlap. Any other label panics: it is a programming error, not an input.
func (k *Keys) MAC(label string, parts ...[]byte) [32]byte {
	if label != LabelNode1 && label != LabelNode && label != LabelEmpty {
		panic("ta1: MAC label not allowed: " + label)
	}
	m := k.mac()
	m.label(label)
	for _, p := range parts {
		m.write(p)
	}
	return m.sum()
}

// SectorTag is t = HMAC-SHA-256(Km, label(leaf) || cid || u64(i) || r || C)[0:24].
func (k *Keys) SectorTag(cid *[16]byte, idx uint64, seed *[SeedSize]byte, ct []byte) [SectorTagSize]byte {
	return k.sectorTag(LabelLeaf, cid, idx, seed, ct)
}

// UnwrittenTag is the tag of a sector that was never written, inside a
// metadata block that exists. The entry (random seed, UnwrittenTag) looks
// like any written entry to anyone without Km, so the block does not reveal
// which of its 64 sectors hold data. A reader checks it first and returns
// zeros without touching the data area.
func (k *Keys) UnwrittenTag(cid *[16]byte, idx uint64, seed *[SeedSize]byte) [SectorTagSize]byte {
	return k.sectorTag(LabelUnwritten, cid, idx, seed, nil)
}

func (k *Keys) sectorTag(label string, cid *[16]byte, idx uint64, seed *[SeedSize]byte, ct []byte) [SectorTagSize]byte {
	m := k.mac()
	m.label(label)
	m.small(cid[:])
	m.u64(idx)
	m.small(seed[:])
	m.write(ct)
	full := m.sum()
	var t [SectorTagSize]byte
	copy(t[:], full[:SectorTagSize])
	return t
}

// SealSector encrypts one sector in place of dst (len(dst) >= len(plain)),
// with a fresh random seed (DESIGN 10.3), and returns the seed and tag.
func (k *Keys) SealSector(cid *[16]byte, idx uint64, dst, plain []byte, rng io.Reader) (seed [SeedSize]byte, tag [SectorTagSize]byte, err error) {
	if len(plain) != SectorSize || len(dst) != SectorSize {
		return seed, tag, ErrSize
	}
	if _, err = io.ReadFull(rng, seed[:]); err != nil {
		return seed, tag, fmt.Errorf("%w: %v", ErrNoRand, err)
	}
	k.cascade(dst, plain, &seed)
	tag = k.SectorTag(cid, idx, &seed, dst)
	return seed, tag, nil
}

// OpenSector verifies the tag first, then decrypts ct into dst.
func (k *Keys) OpenSector(cid *[16]byte, idx uint64, dst, ct []byte, seed *[SeedSize]byte, tag *[SectorTagSize]byte) error {
	want := k.SectorTag(cid, idx, seed, ct)
	if !hmac.Equal(want[:], tag[:]) {
		return ErrAuth
	}
	return k.Cascade(dst, ct, seed)
}

func (k *Keys) sealTag(label string, ad, seed, ct []byte) [32]byte {
	m := k.mac()
	m.label(label)
	m.u64(uint64(len(ad)))
	m.write(ad)
	m.write(seed)
	m.write(ct)
	return m.sum()
}

// Seal returns seed(40) || ciphertext || tag(32). The tag is the full
// 32-byte HMAC-SHA-256 and covers the label, the associated data, the seed
// and the ciphertext. Every key is exactly 32 bytes, which is what makes the
// construction key-committing (DESIGN 9.3).
func (k *Keys) Seal(label string, ad, plain []byte, rng io.Reader) ([]byte, error) {
	if len(plain) > MaxObject {
		return nil, ErrSize
	}
	out := make([]byte, SeedSize+len(plain)+SealTagSize)
	seed := (*[SeedSize]byte)(out[:SeedSize])
	if _, err := io.ReadFull(rng, seed[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRand, err)
	}
	ct := out[SeedSize : SeedSize+len(plain)]
	k.cascade(ct, plain, seed)
	t := k.sealTag(label, ad, seed[:], ct)
	copy(out[SeedSize+len(plain):], t[:])
	return out, nil
}

// Open verifies and decrypts an object made by Seal.
func (k *Keys) Open(label string, ad, blob []byte) ([]byte, error) {
	if len(blob) < SealOverhead || len(blob) > MaxObject+SealOverhead {
		return nil, ErrSize
	}
	n := len(blob) - SealOverhead
	seed := (*[SeedSize]byte)(blob[:SeedSize])
	ct := blob[SeedSize : SeedSize+n]
	want := k.sealTag(label, ad, seed[:], ct)
	if !hmac.Equal(want[:], blob[SeedSize+n:]) {
		return nil, ErrAuth
	}
	pt := make([]byte, n)
	k.cascade(pt, ct, seed)
	return pt, nil
}

// SealUntagged returns seed(40) || ciphertext with no tag, for objects that
// must not confirm a guess of the key on their own: Shamir share slots
// (decision D3 (a)), as the FIDO2 locator slots were before decision H2 was
// revised (DESIGN 19, I3 and I21; review finding R3). The caller must verify
// the result through another, tagged object.
func (k *Keys) SealUntagged(plain []byte, rng io.Reader) ([]byte, error) {
	if len(plain) > MaxObject {
		return nil, ErrSize
	}
	out := make([]byte, SeedSize+len(plain))
	seed := (*[SeedSize]byte)(out[:SeedSize])
	if _, err := io.ReadFull(rng, seed[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRand, err)
	}
	k.cascade(out[SeedSize:], plain, seed)
	return out, nil
}

// OpenUntagged decrypts an object made by SealUntagged. It cannot fail on a
// wrong key: it returns garbage instead.
func (k *Keys) OpenUntagged(blob []byte) ([]byte, error) {
	if len(blob) < SeedSize || len(blob) > MaxObject+SeedSize {
		return nil, ErrSize
	}
	pt := make([]byte, len(blob)-SeedSize)
	k.cascade(pt, blob[SeedSize:], (*[SeedSize]byte)(blob[:SeedSize]))
	return pt, nil
}
