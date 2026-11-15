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
	LabelLeaf    = "theca/v1/TA1/leaf"
	LabelNode1   = "theca/v1/TA1/n1"
	LabelNode    = "theca/v1/TA1/n"
	LabelEmpty   = "theca/v1/TA1/empty"
	LabelHeader  = "theca/v1/TA1/header"
	LabelSlot    = "theca/v1/TA1/slot"
	LabelLocator = "theca/v1/TA1/locator"
	LabelJournal = "theca/v1/TA1/journal"
	LabelCommit  = "theca/v1/TA1/commit"
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
}

// MSSize is the serialised size of Keys.
const MSSize = 3 * KeySize

// Generate draws three independent keys from r.
func Generate(r io.Reader) (*Keys, error) {
	var k Keys
	for _, p := range []*[KeySize]byte{&k.Kc, &k.Ka, &k.Km} {
		if _, err := io.ReadFull(r, p[:]); err != nil {
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
	var k Keys
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
	aes256ctr(&k.Ka, (*[16]byte)(seed[24:]), dst[:len(src)], dst[:len(src)])
}

// xchacha20 XORs src with the XChaCha20 keystream (counter 0). The
// constructor fails only on a bad key or nonce length, which the array types
// rule out, so its error is dropped on purpose.
func xchacha20(key *[32]byte, nonce *[24]byte, dst, src []byte) {
	c, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	c.XORKeyStream(dst, src)
}

// aes256ctr XORs src with the AES-256-CTR keystream whose first counter
// block is iv (big-endian increment over the whole block, as in SP 800-38A).
func aes256ctr(key *[32]byte, iv *[16]byte, dst, src []byte) {
	b, _ := aes.NewCipher(key[:])
	cipher.NewCTR(b, iv[:]).XORKeyStream(dst, src)
}

func (k *Keys) mac() *macState {
	return &macState{h: hmac.New(sha256.New, k.Km[:])}
}

type macState struct{ h hash.Hash }

func (m *macState) label(l string) {
	m.h.Write([]byte{byte(len(l))})
	m.h.Write([]byte(l))
}

func (m *macState) u64(v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	m.h.Write(b[:])
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
		m.h.Write(p)
	}
	var out [32]byte
	m.h.Sum(out[:0])
	return out
}

// SectorTag is t = HMAC-SHA-256(Km, label(leaf) || cid || u64(i) || r || C)[0:24].
func (k *Keys) SectorTag(cid *[16]byte, idx uint64, seed *[SeedSize]byte, ct []byte) [SectorTagSize]byte {
	m := k.mac()
	m.label(LabelLeaf)
	m.h.Write(cid[:])
	m.u64(idx)
	m.h.Write(seed[:])
	m.h.Write(ct)
	var full [32]byte
	m.h.Sum(full[:0])
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
	m.h.Write(ad)
	m.h.Write(seed)
	m.h.Write(ct)
	var t [32]byte
	m.h.Sum(t[:0])
	return t
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

// SealUntagged returns seed(40) || ciphertext with no tag. It exists for the
// FIDO2 locator slots, which must not confirm a guess of their partner
// factor on their own (DESIGN 6.2, review finding R3). The caller must verify
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
