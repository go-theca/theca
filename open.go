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
	"github.com/go-theca/theca/internal/pin"
	"github.com/go-theca/theca/internal/ta1"
)

// collectFactors turns what the user presented into candidate KEKs: each
// partner factor alone, the two partners as a pair, and, when a FIDO2 key is
// present, the pair {partner, key credential} for every Theca credential on
// the key (decision H2 revised, DESIGN 19, I21). The key is asked ONCE, with
// one salt per partner derived from that partner's KEK, so one touch serves
// every partner and every credential; nothing about the key is read from
// the container.
//
// The returned KEKs are the caller's to wipe; on error they are wiped here.
func collectFactors(ctx context.Context, u *Unlock, salt []byte) (cands [][32]byte, err error) {
	// The capacity is the most this can hold (two singles, one pair, one pair
	// per credential per partner), so append never moves the KEKs and leaves
	// an unwiped copy behind.
	cands = make([][32]byte, 0, 3+MaxFIDO2Credentials*MaxFIDO2Salts)
	var fs []Factor // the partners: at most 2, wiped on return
	defer func() {
		for i := range fs {
			fs[i].Zeroize()
		}
		if err != nil {
			for i := range cands {
				clear(cands[i][:])
			}
			cands = nil
		}
	}()
	fs = make([]Factor, 0, MaxFIDO2Salts)
	if len(u.Password) > 0 {
		pw, err := PasswordFactor(u.Hint, u.Password, salt)
		if err != nil {
			return nil, err
		}
		fs = append(fs, pw)
	}
	if len(u.Recovery) > 0 {
		rc, err := RecoveryFactor(u.Recovery)
		if err != nil {
			return nil, err
		}
		fs = append(fs, rc)
	}
	for i := range fs {
		cands = append(cands, fs[i].KEK)
	}
	if len(fs) == 2 {
		cands = append(cands, kdf.Pair(&fs[0].KEK, fs[0].Kind, &fs[1].KEK, fs[1].Kind))
	}
	// A key pairs with a partner; with no partner presented there is nothing
	// to ask it.
	if u.FIDO == nil || len(fs) == 0 {
		return cands, nil
	}
	// The salts are a function of the password: whoever reads one can test
	// password guesses offline (at Argon2id cost). They are wiped after use
	// and must never be logged (HARDWARE-KEYS 8.3).
	salts := fido2Salts(fs)
	defer clearSalts(salts)
	creds, err := u.FIDO.Derive(ctx, salts)
	defer func() {
		for _, cr := range creds {
			for _, o := range cr {
				clear(o)
			}
		}
	}()
	if errors.Is(err, ErrNoCredential) {
		return cands, nil
	}
	if err != nil {
		return cands, err
	}
	if len(creds) > MaxFIDO2Credentials {
		return cands, fmt.Errorf("%w: %d credentials (at most %d)", ErrAuthenticator, len(creds), MaxFIDO2Credentials)
	}
	for _, outs := range creds {
		if err := checkOutputs(outs, len(fs)); err != nil {
			return cands, err
		}
		for j := range fs {
			key := FIDO2Factor(outs[j])
			cands = append(cands, kdf.Pair(&fs[j].KEK, fs[j].Kind, &key.KEK, key.Kind))
			key.Zeroize()
		}
	}
	return cands, nil
}

// unlockSlots tries every candidate key-encryption key against all 16 slots
// and wipes each candidate after use. It always does the same work whatever
// matches (DESIGN 9.2, finding R8) and returns the first master secret found.
func unlockSlots(cands [][32]byte, table [format.NumSlots][]byte) *ta1.Keys {
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
	cands, err := collectFactors(ctx, &u, salt)
	if err != nil {
		return nil, err
	}
	ms := unlockSlots(cands, table)
	// unlockSlots reads a refusal to pin a key's pages as "this slot does not
	// open"; under --mlock=required that is the answer, not ErrNoMatch.
	if err := pin.Failed(); err != nil {
		if ms != nil {
			ms.Zeroize()
		}
		return nil, err
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
		dMeta: map[uint64]struct{}{}, dData: map[uint64][]byte{}}
	c.cacheBytes = o.CacheBytes
	c.newCaches(body.Root)
	// The counter decides BEFORE anything is written: a rolled-back image
	// must be refused untouched, not first moved forward by a journal replay
	// (review of PR #4, finding 4).
	gate, err := c.checkCounter(o)
	if err != nil {
		ms.Zeroize()
		return nil, err
	}
	if err := c.recover(); err != nil {
		ms.Zeroize()
		return nil, err
	}
	if err := c.bindCounter(gate); err != nil {
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
	c.tree.Wipe()
	c.newCaches(tx.Root)
	if err := c.writeHeader(); err != nil {
		return err
	}
	c.info.ReplayedTransaction = true
	return c.f.Sync()
}

// counterGate is the decision checkCounter took, applied by bindCounter.
type counterGate struct {
	bound   bool   // the header names a counter
	finish  bool   // b == c+1: an earlier mount crashed before its increment
	base    uint64 // the counter value once any unfinished increment is done
	ctr     Counter
	rebind  bool   // bind the header to a new counter (OpenOptions.RebindFor)
	id      []byte // rebind: the identity of the new counter's TPM, nil if it has none
	derived bool   // rebind: the new counter's authValue is derived from the master secret
}

// checkCounter runs the read-only half of the mount protocol of DESIGN 5.4:
// it identifies the counter, reads it and accepts or refuses. It writes
// nothing, to the backing or to the counter.
func (c *Container) checkCounter(o OpenOptions) (counterGate, error) {
	b := c.body.Counter
	if o.RebindFor != nil || o.RebindDerived != nil {
		var h uint32
		var n []byte
		if b != nil {
			h, n = b.Handle, b.Name
		}
		var ctr Counter
		var err error
		derived := o.RebindFor == nil
		if derived {
			auth := kdf.CounterAuth(c.k)
			ctr, err = o.RebindDerived(h, n, auth)
			clear(auth)
		} else {
			ctr, err = o.RebindFor(h, n)
		}
		if err != nil {
			return counterGate{}, err
		}
		// The new binding pins the identity of the TPM the new counter is on
		// (a counter that cannot say leaves the header unpinned).
		id, err := identityOf(ctr)
		if err != nil {
			return counterGate{}, err
		}
		return counterGate{bound: true, rebind: true, ctr: ctr, id: id, derived: derived}, nil
	}
	if b == nil {
		// Asking for a counter means requiring it: a header that names none,
		// opened by a caller that holds one, is a copy from before the counter
		// was bound (or never had one). The counter is not consulted, so
		// nothing could tell it is old.
		if o.Counter != nil || o.CounterFor != nil || o.CounterDerived != nil {
			return counterGate{}, ErrCounterRequired
		}
		return counterGate{}, nil // "rollback-unprotected": Info.RollbackProtected is false
	}
	ctr := o.Counter
	if ctr == nil && b.DerivedAuth && o.CounterDerived != nil {
		auth := kdf.CounterAuth(c.k)
		var err error
		ctr, err = o.CounterDerived(b.Handle, b.Name, auth)
		clear(auth)
		if err != nil {
			return counterGate{}, err
		}
	} else if ctr == nil && !b.DerivedAuth && o.CounterFor != nil {
		var err error
		if ctr, err = o.CounterFor(b.Handle, b.Name); err != nil {
			return counterGate{}, err
		}
	}
	if ctr == nil || ctr.Handle() != b.Handle || !bytes.Equal(ctr.Name(), b.Name) {
		return counterGate{}, ErrCounter
	}
	// Whose TPM is it? Asked before the value is read: a value read from
	// another TPM decides nothing (DESIGN 5.4.1).
	if err := checkIdentity(ctr, b.TPMID); err != nil {
		return counterGate{}, err
	}
	cur, err := ctr.Read()
	if err != nil {
		return counterGate{}, err
	}
	switch {
	case cur < ^uint64(0) && b.Bound == cur+1:
		return counterGate{bound: true, finish: true, base: cur + 1, ctr: ctr}, nil
	case b.Bound == cur, o.AcceptRollback:
		return counterGate{bound: true, base: cur, ctr: ctr}, nil
	}
	return counterGate{}, ErrRollback
}

// bindCounter runs the writing half of the mount protocol: finish an
// unfinished increment if there is one, then rebind the header to base+1
// and increment. The rebind is done in the b == c+1 case too (review of PR
// #4, finding 2): otherwise this session would leave the counter equal to
// the bound written by the crashed one, and an image copied during that
// crashed session would still be accepted at the next mount.
func (c *Container) bindCounter(g counterGate) error {
	if !g.bound {
		return nil
	}
	ctr := g.ctr
	if g.rebind {
		// Like Create: increment a fresh counter, read it, and bind to the
		// value read. The Name is read after the increment (it can change at the
		// first one). A crash between the two steps leaves the header on the
		// old counter, and the rebind can be run again.
		if err := ctr.Increment(); err != nil {
			return err
		}
		c0, err := ctr.Read()
		if err != nil {
			return err
		}
		c.body.Counter = &format.Counter{Handle: ctr.Handle(), Name: ctr.Name(), Bound: c0, TPMID: g.id, DerivedAuth: g.derived}
		c.mu.Lock()
		err = c.commitLocked("rebind counter")
		c.mu.Unlock()
		return err
	}
	if g.finish {
		if err := ctr.Increment(); err != nil {
			return err
		}
	}
	if g.base == ^uint64(0) {
		return fmt.Errorf("%w: counter exhausted", ErrCounter)
	}
	b := c.body.Counter
	c.body.Counter = &format.Counter{Handle: b.Handle, Name: b.Name, Bound: g.base + 1, TPMID: b.TPMID, DerivedAuth: b.DerivedAuth}
	c.mu.Lock()
	err := c.commitLocked("bind counter")
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return ctr.Increment()
}
