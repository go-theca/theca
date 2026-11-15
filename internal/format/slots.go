package format

import (
	"errors"
	"fmt"
	"io"

	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/internal/ta1"
)

const (
	wrapPlain    = SlotSize - ta1.SealOverhead // 1976: MS then zero padding
	locatorPlain = SlotSize - ta1.SeedSize     // 2008
	// MaxCredID is CTAP's maxCredentialIdLength on the YubiKey 5.7.4 capture.
	MaxCredID = 128
)

// ErrSlot is returned for malformed slot input.
var ErrSlot = errors.New("format: invalid slot")

// RandomSlot returns random filler for an unused slot.
func RandomSlot(rng io.Reader) ([]byte, error) {
	b := make([]byte, SlotSize)
	if _, err := io.ReadFull(rng, b); err != nil {
		return nil, fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
	}
	return b, nil
}

func slotAD(index int) []byte { return []byte{byte(index)} }

// SealWrap seals the master secret in slot `index` under a key-encryption
// key (single factor, or the pair key of kdf.Pair). The slot is sealed with
// TA1 itself, so both cipher families protect it (DESIGN 6.2).
func SealWrap(ms *ta1.Keys, kek *[32]byte, index int, rng io.Reader) ([]byte, error) {
	if index < 0 || index >= NumSlots {
		return nil, ErrSlot
	}
	plain := make([]byte, wrapPlain)
	copy(plain, ms.Bytes())
	wk := kdf.Keys(kek)
	defer wk.Zeroize()
	defer clear(plain)
	return wk.Seal(ta1.LabelSlot, slotAD(index), plain, rng)
}

// OpenWrap trial-opens slot `index` under a key-encryption key.
func OpenWrap(kek *[32]byte, index int, blob []byte) (*ta1.Keys, error) {
	if len(blob) != SlotSize || index < 0 || index >= NumSlots {
		return nil, ErrSlot
	}
	wk := kdf.Keys(kek)
	defer wk.Zeroize()
	plain, err := wk.Open(ta1.LabelSlot, slotAD(index), blob)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return ta1.FromBytes(plain[:ta1.MSSize])
}

// Locator is what a FIDO2 factor needs to be asked for its secret (DESIGN
// 6.3, HARDWARE-KEYS 5.1): the credential ID, the fixed 32-byte salt of the
// slot (decision H7) and a flags byte.
type Locator struct {
	CredID []byte
	Salt   [32]byte
	Flags  byte
}

// Locator flag bits.
const (
	LocUV   = 1 << 0 // user verification was required at enrolment
	LocPIN2 = 1 << 1 // PIN/UV protocol 2
	locMask = LocUV | LocPIN2
)

// SealLocator seals a locator, untagged, under the partner factor's KEK
// (decision H2 and DESIGN section 19, I3). Padding is random.
func SealLocator(partner *[32]byte, loc *Locator, rng io.Reader) ([]byte, error) {
	if len(loc.CredID) == 0 || len(loc.CredID) > MaxCredID || loc.Flags&^locMask != 0 {
		return nil, ErrSlot
	}
	plain := make([]byte, locatorPlain)
	if _, err := io.ReadFull(rng, plain); err != nil {
		return nil, fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
	}
	plain[0] = plain[0]&0x80 | byte(len(loc.CredID)-1) // the top bit is random padding
	copy(plain[1:], loc.CredID)
	copy(plain[1+MaxCredID:], loc.Salt[:])
	plain[1+MaxCredID+32] = loc.Flags
	wk := kdf.Keys(partner)
	defer wk.Zeroize()
	return wk.SealUntagged(plain, rng)
}

// OpenLocator decrypts a slot as a locator under the partner KEK. There is no
// tag and no shape check: a wrong key or a non-locator slot yields a
// plausible-looking locator, and ok is false only for a blob of the wrong
// size. The caller asks the key, which is the only verifier.
func OpenLocator(partner *[32]byte, blob []byte) (Locator, bool) {
	if len(blob) != SlotSize {
		return Locator{}, false
	}
	wk := kdf.Keys(partner)
	defer wk.Zeroize()
	plain, _ := wk.OpenUntagged(blob) // fails only on a bad size, checked above
	defer clear(plain)
	// Every string decodes to a locator: length = (b mod 128) + 1 and the
	// flag bits are masked. No shape test exists, so a wrong partner KEK
	// cannot be filtered out without asking the key (review of PR #4: a
	// shape test leaked about 3 bits of every password guess).
	n := int(plain[0]&0x7f) + 1
	flags := plain[1+MaxCredID+32] & locMask
	loc := Locator{CredID: append([]byte(nil), plain[1:1+n]...), Flags: flags}
	copy(loc.Salt[:], plain[1+MaxCredID:])
	return loc, true
}
