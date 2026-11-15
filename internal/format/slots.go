package format

import (
	"errors"
	"fmt"
	"io"

	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/internal/ta1"
)

// wrapPlain is a wrap slot's plaintext: MS then zero padding (1976 bytes).
const wrapPlain = SlotSize - ta1.SealOverhead

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
//
// There is no other kind of slot: a FIDO2 key needs nothing stored beside
// its pairwise wrap slot, because its credential is discoverable and its
// salt is derived from the partner factor (DESIGN 19, I21).
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
