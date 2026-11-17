// Package kdf holds Theca's key derivation: Argon2id with parameters from a
// fixed compiled-in table (DESIGN 6.1, decision D2) and HKDF-SHA-256 at the
// wrapping layer (DESIGN 2).
package kdf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/go-encryptions/argon2"
	"github.com/go-theca/theca/internal/ta1"
)

// Profile is one Argon2id parameter set (RFC 9106 section 4).
type Profile struct {
	Time    uint32 // passes
	MemKiB  uint32 // memory in KiB
	Threads uint8  // lanes
}

// Table is the fixed parameter table. The index is the user's hint (D2) and
// is never read from a container: a hostile header cannot ask for memory.
//
// 0: RFC 9106 FIRST recommended option (t=1, p=4, m=2 GiB)
// 1: RFC 9106 SECOND recommended option (t=3, p=4, m=64 MiB)
// 2: "paranoid" (t=3, p=4, m=4 GiB)
//
// Tests replace entries with small profiles; no production code writes it.
var Table = [3]Profile{
	{Time: 1, MemKiB: 2 << 20, Threads: 4},
	{Time: 3, MemKiB: 64 << 10, Threads: 4},
	{Time: 3, MemKiB: 4 << 20, Threads: 4},
}

// ErrProfile is returned for a hint outside the table.
var ErrProfile = errors.New("kdf: unknown Argon2id profile")

// SaltSize and KeySize are the RFC 9106 salt (128 bits is the minimum; we use
// 256) and the derived key length.
const (
	SaltSize = 32
	KeySize  = 32
)

// Lookup returns the profile for a hint.
func Lookup(hint int) (Profile, error) {
	if hint < 0 || hint >= len(Table) {
		return Profile{}, fmt.Errorf("%w: %d", ErrProfile, hint)
	}
	return Table[hint], nil
}

// Argon2id derives 32 bytes from the password with the hinted profile. The
// salt must be SaltSize bytes.
func Argon2id(hint int, password, salt []byte) ([]byte, error) {
	p, err := Lookup(hint)
	if err != nil {
		return nil, err
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("kdf: salt is %d bytes, want %d", len(salt), SaltSize)
	}
	// On a 32-bit target the profile may not fit in the address space:
	// refuse instead of crashing in the allocator.
	if uint64(p.MemKiB)*1024 > platformMax/2 {
		return nil, fmt.Errorf("%w: %d KiB does not fit this platform", ErrProfile, p.MemKiB)
	}
	return argon2.IDKey(password, salt, p.Time, p.MemKiB, p.Threads, KeySize), nil
}

// HKDF-SHA-256 info prefix for every key-encryption key.
const infoPrefix = "theca/v1/TA1/slot/"

// KEK derives a 32-byte key-encryption key from a factor's output. kind
// names the factor ("pw", "rc", "fido2", "tpm").
func KEK(secret []byte, kind string) [32]byte {
	// hkdf.Key fails only when the requested length exceeds 255 hashes.
	k, _ := hkdf.Key(sha256.New, secret, nil, infoPrefix+kind, 32)
	out := [32]byte(k)
	clear(k)
	return out
}

// FIDO2Salt is the hmac-secret salt a FIDO2 key is asked for when it pairs
// with the partner factor of the given kind (DESIGN 19, I21): HKDF-SHA-256
// of the partner's KEK, info "theca/v1/fido2/salt/<kind>". Nothing about the
// key is stored in the container. A wrong partner (a wrong password guess)
// gives another salt, so every guess needs a fresh, touch-gated question to
// the key: there is no offline test of the partner through the key's slot.
func FIDO2Salt(partner *[32]byte, kind string) [32]byte {
	k, _ := hkdf.Key(sha256.New, partner[:], nil, "theca/v1/fido2/salt/"+kind, 32)
	out := [32]byte(k)
	clear(k)
	return out
}

// Keys expands a 32-byte KEK into the three Theca-A keys that seal a slot
// (DESIGN 2): one HKDF-SHA-256 call of 96 bytes, so all three are always
// derived together.
func Keys(kek *[32]byte) *ta1.Keys {
	b, _ := hkdf.Key(sha256.New, kek[:], nil, infoPrefix+"keys", ta1.MSSize)
	k, _ := ta1.FromBytes(b)
	clear(b)
	return k
}

// platformMax is the largest int; a variable so a 64-bit test can exercise
// the 32-bit refusal.
var platformMax = uint64(^uint(0) >> 1)

// Pair derives the key-encryption key of a pairwise slot from two KEKs
// (DESIGN 6.2, construction (b)). The pairs are put into a fixed order by
// kind here, so the result does not depend on the argument order.
func Pair(a *[32]byte, kindA string, b *[32]byte, kindB string) [32]byte {
	if kindA > kindB {
		a, b, kindA, kindB = b, a, kindB, kindA
	}
	in := make([]byte, 0, 64)
	in = append(in, a[:]...)
	in = append(in, b[:]...)
	k, _ := hkdf.Key(sha256.New, in, nil, infoPrefix+"pair/"+kindA+"+"+kindB, 32)
	clear(in)
	out := [32]byte(k)
	clear(k)
	return out
}
