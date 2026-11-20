package theca

import (
	"errors"
	"fmt"
	"slices"

	"github.com/go-theca/theca/internal/format"
)

// ErrLastWay is returned by RemoveFactors when no factor set the caller
// presented as the ones to keep would still open the container afterwards.
var ErrLastWay = errors.New("theca: refusing to remove the last way in: the factors to keep would not open any other slot")

// Slots returns the indexes of the slots the header records, in order. A slot
// holds nothing that says what opens it, so this is all the container knows;
// SlotsOf answers "which slots does this factor set open".
func (c *Container) Slots() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []int
	for i := 0; i < format.NumSlots; i++ {
		if c.body.SlotsUsed&(1<<i) != 0 {
			out = append(out, i)
		}
	}
	return out
}

// SlotsOf returns the indexes of the slots (recorded or not) that the factor
// set opens: one factor, or two that pair. It trial-opens all 16, as unlock
// does.
func (c *Container) SlotsOf(fs ...Factor) ([]int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return nil, err
	}
	return c.slotsOfLocked(fs)
}

// slotsOfSetsLocked is the union of the slots each set opens, ascending.
func (c *Container) slotsOfSetsLocked(sets [][]Factor) ([]int, error) {
	var out []int
	for _, fs := range sets {
		idx, err := c.slotsOfLocked(fs)
		if err != nil {
			return nil, err
		}
		for _, i := range idx {
			if !slices.Contains(out, i) {
				out = append(out, i)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func (c *Container) slotsOfLocked(fs []Factor) ([]int, error) {
	kek, err := slotKEK(fs)
	if err != nil {
		return nil, err
	}
	defer clear(kek[:])
	var out []int
	blob := make([]byte, format.SlotSize)
	for i := 0; i < format.NumSlots; i++ {
		if _, err := c.f.ReadAt(blob, int64(format.SlotsOff+i*format.SlotSize)); err != nil {
			return nil, err
		}
		if k, err := format.OpenWrap(&kek, i, blob); err == nil {
			k.Zeroize()
			out = append(out, i)
		}
	}
	return out, nil
}

// RemoveFactors removes the slot(s) the factor set `remove` opens ("the
// recovery code", "this key and this password"), and returns how many it
// removed. It does not need an index.
//
// `keep` is a DIFFERENT factor set that must still open the container
// afterwards: a slot holds nothing that says what opens it, so the container
// cannot count the ways in that would remain, and asks the caller to prove one.
// The proof is checked before anything is written. With none (no slot opens
// under `remove`) the answer is ErrNoMatch; with a `keep` that opens no slot
// outside the ones to remove, ErrLastWay. A power cut keeps RemoveSlot's order
// (overwrite first, then commit).
//
// Like RemoveSlot it only stops access to the CURRENT container: anyone with
// an older copy can still open it with the removed factor (DESIGN 2, R7).
func (c *Container) RemoveFactors(remove, keep []Factor) (int, error) {
	return c.RemoveFactorSets([][]Factor{remove}, [][]Factor{keep})
}

// RemoveFactorSets is RemoveFactors for a factor set that stands for SEVERAL
// slots: "the password with the key" is one pair per Theca credential the key
// holds (KeyPairs). A slot is removed when ANY set in `remove` opens it, and
// the container must still open under ANY set in `keep` through a slot that is
// not among those removed, else ErrLastWay. Nothing is written before both are
// known, and the writes are RemoveFactors's.
func (c *Container) RemoveFactorSets(remove, keep [][]Factor) (int, error) {
	if len(remove) == 0 || len(keep) == 0 {
		return 0, fmt.Errorf("%w: a removal needs factors to remove and factors to keep", ErrOption)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return 0, err
	}
	gone, err := c.slotsOfSetsLocked(remove)
	if err != nil {
		return 0, err
	}
	if len(gone) == 0 {
		return 0, fmt.Errorf("%w: no slot opens with the factors to remove", ErrNoMatch)
	}
	stay, err := c.slotsOfSetsLocked(keep)
	if err != nil {
		return 0, err
	}
	if !slices.ContainsFunc(stay, func(i int) bool { return !slices.Contains(gone, i) }) {
		return 0, ErrLastWay
	}
	for _, i := range gone {
		if err := c.removeSlotLocked(i); err != nil {
			return 0, err
		}
	}
	return len(gone), nil
}
