package theca

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/go-theca/theca/internal/format"
	"github.com/go-theca/theca/internal/journal"
	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/internal/merkle"
	"github.com/go-theca/theca/internal/ta1"
)

// collectFactors turns what the user presented into factors. A FIDO2 key is
// asked only after a partner factor is known, because its locator is sealed
// under the partner's KEK (decision H2): every slot is decrypted as a
// locator under each partner, and the key is asked about each candidate. The
// key, not a tag, says which one is real.
func collectFactors(ctx context.Context, u *Unlock, salt []byte, table [format.NumSlots][]byte) ([]Factor, error) {
	var fs []Factor
	if len(u.Password) > 0 {
		pw, err := PasswordFactor(u.Hint, u.Password, salt)
		if err != nil {
			return nil, err
		}
		fs = append(fs, pw)
	}
	if u.Recovery != "" {
		rc, err := RecoveryFactor(u.Recovery)
		if err != nil {
			return nil, err
		}
		fs = append(fs, rc)
	}
	if u.FIDO != nil {
		partners := append([]Factor(nil), fs...)
		seen := map[string]bool{}
		for _, p := range partners {
			for i := 0; i < format.NumSlots; i++ {
				loc, ok := format.OpenLocator(&p.KEK, table[i])
				if !ok {
					continue
				}
				secret, err := u.FIDO.Derive(ctx, loc)
				if errors.Is(err, ErrNoCredential) {
					continue
				}
				if err != nil {
					return nil, err
				}
				if k := string(secret); !seen[k] {
					seen[k] = true
					fs = append(fs, FIDO2Factor(secret))
				}
				clear(secret)
			}
		}
	}
	return fs, nil
}

// unlockSlots tries every candidate key-encryption key (each factor alone,
// each pair) against all 16 slots. It always does the same work whatever
// matches (DESIGN 9.2, finding R8) and returns the first master secret found.
func unlockSlots(fs []Factor, table [format.NumSlots][]byte) *ta1.Keys {
	var cands [][32]byte
	for i := range fs {
		cands = append(cands, fs[i].KEK)
		for j := i + 1; j < len(fs); j++ {
			cands = append(cands, kdf.Pair(&fs[i].KEK, fs[i].Kind, &fs[j].KEK, fs[j].Kind))
		}
	}
	var found *ta1.Keys
	for ci := range cands {
		for i := 0; i < format.NumSlots; i++ {
			k, err := format.OpenWrap(&cands[ci], i, table[i])
			if err != nil {
				continue
			}
			if found == nil {
				found = k
			} else {
				k.Zeroize()
			}
		}
		clear(cands[ci][:])
	}
	return found
}

// Open unlocks a container and brings it to its last committed state.
func Open(ctx context.Context, f Backing, u Unlock, o OpenOptions) (*Container, error) {
	size, err := f.Size()
	if err != nil {
		return nil, err
	}
	minSize := int64(format.HdrOff + 2*format.HeaderSize)
	if size < minSize {
		return nil, ErrNoMatch
	}
	salt := make([]byte, format.SaltSize)
	if _, err := f.ReadAt(salt, 0); err != nil {
		return nil, err
	}
	var table [format.NumSlots][]byte
	for i := range table {
		table[i] = make([]byte, format.SlotSize)
		if _, err := f.ReadAt(table[i], int64(format.SlotsOff+i*format.SlotSize)); err != nil {
			return nil, err
		}
	}
	fs, err := collectFactors(ctx, &u, salt, table)
	if err != nil {
		return nil, err
	}
	ms := unlockSlots(fs, table)
	for i := range fs {
		fs[i].Zeroize()
	}
	if ms == nil {
		return nil, ErrNoMatch
	}

	// Both header copies are always tried; the valid one with the higher
	// epoch wins.
	var body *format.Body
	var geo format.Geometry
	for _, off := range []int64{format.HdrOff, format.HdrOff + format.HeaderSize} {
		blob := make([]byte, format.HeaderSize)
		if _, err := f.ReadAt(blob, off); err != nil {
			return nil, err
		}
		b, g, err := format.OpenHeader(ms, blob, uint64(size))
		if err == nil && (body == nil || b.Epoch > body.Epoch) {
			body, geo = b, g
		}
	}
	if body == nil {
		ms.Zeroize()
		return nil, fmt.Errorf("%w: no header copy authenticates", ErrCorrupt)
	}

	c := &Container{f: f, rng: randOr(o.Rand), geo: geo, body: *body, k: ms,
		meta: map[uint64]*[4096]byte{}, dMeta: map[uint64]struct{}{}, dData: map[uint64][]byte{}}
	c.tree = merkle.New(ms, geo.Shape, body.Root, nodeStore{c})
	if err := c.recover(); err != nil {
		ms.Zeroize()
		return nil, err
	}
	if err := c.bindCounter(o); err != nil {
		ms.Zeroize()
		return nil, err
	}
	c.fillInfo()
	return c, nil
}

// recover replays a committed transaction for epoch+1, if the journal holds
// one, then checks that the tree root on disk is the one the commit entry
// carried before moving the header (DESIGN 5.3).
func (c *Container) recover() error {
	jr := region{c.f, int64(c.geo.JournalOff)}
	tx, err := journal.Recover(c.k, jr, c.body.JournalEntries, c.body.Epoch)
	if err != nil {
		return err
	}
	if tx == nil {
		return nil
	}
	if err := c.apply(tx); err != nil {
		return err
	}
	if err := c.f.Sync(); err != nil {
		return err
	}
	// A fresh tree rooted at the commit's root must verify its top node from
	// what the replay left on disk.
	probe := merkle.New(c.k, c.geo.Shape, tx.Root, nodeStore{c})
	if _, err := probe.Meta(0); err != nil {
		return fmt.Errorf("%w: replayed transaction does not match its root: %v", ErrCorrupt, err)
	}
	c.body.Epoch = tx.Epoch
	c.body.Root = tx.Root
	c.tree = merkle.New(c.k, c.geo.Shape, tx.Root, nodeStore{c})
	if err := c.writeHeader(); err != nil {
		return err
	}
	c.info.ReplayedTransation = true
	return c.f.Sync()
}

// bindCounter runs the mount protocol of DESIGN 5.4 against the hardware
// counter, if the header names one.
func (c *Container) bindCounter(o OpenOptions) error {
	b := c.body.Counter
	if b == nil {
		return nil // "rollback-unprotected": Info.RollbackProtected is false
	}
	ctr := o.Counter
	if ctr == nil || ctr.Handle() != b.Handle || !bytes.Equal(ctr.Name(), b.Name) {
		return ErrCounter
	}
	cur, err := ctr.Read()
	if err != nil {
		return err
	}
	switch {
	case b.Bound == cur+1:
		// Crash between the header write and the increment: finish it.
		return ctr.Increment()
	case b.Bound == cur:
	case o.AcceptRollback:
	default:
		return ErrRollback
	}
	c.body.Counter = &format.Counter{Handle: b.Handle, Name: b.Name, Bound: cur + 1}
	c.mu.Lock()
	err = c.commitLocked("bind counter")
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return ctr.Increment()
}
