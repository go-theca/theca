package theca

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/go-theca/theca/internal/format"
)

// ErrResizeSame: the container already has the journal size asked for.
var ErrResizeSame = errors.New("theca: the container already has that journal size")

// ResizeOptions chooses the new journal size.
type ResizeOptions struct {
	// Entries is the new journal size in entries (the most one commit holds).
	// 0 means DefaultJournal(sectors). A value below what one sector write needs
	// is raised to that minimum, as in Create.
	Entries uint32
}

// ResizeInfo describes a finished resize.
type ResizeInfo struct {
	OldEntries uint32
	Entries    uint32
	Sectors    uint64
	// Epoch is the source's epoch after the unlock, which the copy carries.
	Epoch uint64
	// Size is the size of the new file in bytes.
	Size uint64
	// Hash is the SHA-256 of the whole volume, read through the source and,
	// again, through the reopened copy: Resize reports success only when both
	// agree.
	Hash [32]byte
}

// roCounter and roIdCounter pass a counter's reads through and swallow its
// increments: the verification reopen of the copy must not move the hardware
// counter (the caller's first real mount does).
type roCounter struct{ Counter }

func (roCounter) Increment() error { return nil }

type roIdCounter struct{ IdentifiedCounter }

func (roIdCounter) Increment() error { return nil }

func readOnlyCounter(c Counter) Counter {
	if ic, ok := c.(IdentifiedCounter); ok {
		return roIdCounter{ic}
	}
	return roCounter{c}
}

// volumeHash reads the whole volume through c, authenticating every sector on
// the way, and returns its SHA-256.
func volumeHash(c *Container) ([32]byte, error) {
	h := sha256.New()
	buf := make([]byte, 1<<20)
	size := c.Size()
	for off := int64(0); off < size; off += int64(len(buf)) {
		n := buf[:min(int64(len(buf)), size-off)]
		if _, err := c.ReadAt(n, off); err != nil {
			return [32]byte{}, err
		}
		h.Write(n)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return sum, nil
}

// copyRange copies n bytes from src at so to dst at do, 1 MiB at a time.
func copyRange(dst, src Backing, do, so, n uint64) error {
	buf := make([]byte, 1<<20)
	for done := uint64(0); done < n; {
		b := buf[:min(uint64(len(buf)), n-done)]
		if _, err := src.ReadAt(b, int64(so+done)); err != nil {
			return err
		}
		if _, err := dst.WriteAt(b, int64(do+done)); err != nil {
			return err
		}
		done += uint64(len(b))
	}
	return nil
}

// Resize writes a copy of the container in src, with a journal of a different
// size, to the empty backing dst. The journal size is part of the header and
// the layout is derived from it, so every area after the journal moves; the
// sectors, the tree and the key slots are copied byte for byte (a sector is
// sealed under the container id and its INDEX, never its offset), and the
// header is sealed again under the same master secret.
//
// src is unlocked like any mount: the factors open it, the counter is
// consulted and advanced, a committed transaction in its journal is replayed.
// That is the only thing written to it, and the copy is never written to src.
// dst is synced before the verification. The verification reopens dst with the
// counter's increments swallowed, checks the journal size, authenticates every
// sector, and compares the SHA-256 of the volume read through each.
//
// The copy carries the counter binding unchanged (handle, name, TPM identity,
// derived authValue, bound value, epoch). The first real mount of dst finishes
// the increment the verification left unfinished and advances the counter, and
// from then on src is refused as a rollback, like any older copy of the
// container.
func Resize(ctx context.Context, src Backing, u Unlock, o OpenOptions, dst Backing, ro ResizeOptions) (ResizeInfo, error) {
	if o.RebindFor != nil || o.RebindDerived != nil {
		return ResizeInfo{}, fmt.Errorf("%w: a resize does not rebind the counter", ErrOption)
	}
	if n, err := dst.Size(); err != nil {
		return ResizeInfo{}, err
	} else if n != 0 {
		return ResizeInfo{}, fmt.Errorf("%w: the destination holds %d bytes, it must be empty", ErrOption, n)
	}
	// Remember the counter the source was unlocked with, for the verification.
	var seen Counter
	so := o
	seen = o.Counter
	if f := o.CounterFor; f != nil {
		so.CounterFor = func(h uint32, name []byte) (Counter, error) {
			c, err := f(h, name)
			if err == nil {
				seen = c
			}
			return c, err
		}
	}
	if f := o.CounterDerived; f != nil {
		so.CounterDerived = func(h uint32, name, auth []byte) (Counter, error) {
			c, err := f(h, name, auth)
			if err == nil {
				seen = c
			}
			return c, err
		}
	}
	c, err := Open(ctx, src, u, so)
	if err != nil {
		return ResizeInfo{}, err
	}
	defer func() {
		if !c.closed {
			c.Close()
		}
	}()

	n := ro.Entries
	if n == 0 {
		n = DefaultJournal(c.body.Sectors)
	}
	n = max(n, format.MinJournal(c.geo.Shape))
	if n == c.body.JournalEntries {
		return ResizeInfo{}, fmt.Errorf("%w: %d entries", ErrResizeSame, n)
	}
	geo, err := format.NewGeometry(c.body.Sectors, n)
	if err != nil {
		return ResizeInfo{}, err
	}
	info := ResizeInfo{OldEntries: c.body.JournalEntries, Entries: n, Sectors: c.body.Sectors, Epoch: c.body.Epoch, Size: geo.End}
	if info.Hash, err = volumeHash(c); err != nil {
		return ResizeInfo{}, err
	}

	// Everything the copy does not overwrite is random: the unused header copy,
	// the journal, the padding and the tail (DESIGN 9.1).
	dataEnd := geo.DataOff + c.body.Sectors*SectorSize
	if err := fillRandomAt(dst, format.HdrOff, geo.MetaOff-format.HdrOff, c.rng); err != nil {
		return ResizeInfo{}, err
	}
	if err := fillRandomAt(dst, dataEnd, geo.End-dataEnd, c.rng); err != nil {
		return ResizeInfo{}, err
	}
	if err := copyRange(dst, src, 0, 0, format.HdrOff); err != nil { // salt and key slots
		return ResizeInfo{}, err
	}
	if err := copyRange(dst, src, geo.MetaOff, c.geo.MetaOff, dataEnd-geo.MetaOff); err != nil {
		return ResizeInfo{}, err
	}
	body := c.body
	body.JournalEntries = n
	blob, err := format.SealHeader(c.k, &body, c.rng)
	if err != nil {
		return ResizeInfo{}, err
	}
	if _, err := dst.WriteAt(blob, int64(geo.Header(body.Epoch))); err != nil {
		return ResizeInfo{}, err
	}
	if err := dst.Sync(); err != nil {
		return ResizeInfo{}, err
	}
	if err := verifyResized(ctx, dst, u, o, seen, info); err != nil {
		return ResizeInfo{}, err
	}
	return info, nil
}

// verifyResized reopens dst and compares it with what was meant.
func verifyResized(ctx context.Context, dst Backing, u Unlock, o OpenOptions, seen Counter, want ResizeInfo) error {
	vo := OpenOptions{CacheBytes: o.CacheBytes, Rand: o.Rand}
	if seen != nil {
		vo.Counter = readOnlyCounter(seen)
	}
	d, err := Open(ctx, dst, u, vo)
	if err != nil {
		return fmt.Errorf("theca: the copy does not open: %w", err)
	}
	if d.body.JournalEntries != want.Entries || d.body.Sectors != want.Sectors {
		d.Close()
		return fmt.Errorf("%w: the copy has %d entries and %d sectors, expected %d and %d", ErrCorrupt, d.body.JournalEntries, d.body.Sectors, want.Entries, want.Sectors)
	}
	if _, err := d.Verify(); err != nil {
		d.Close()
		return fmt.Errorf("theca: the copy does not verify: %w", err)
	}
	got, err := volumeHash(d)
	if err != nil {
		d.Close()
		return err
	}
	if got != want.Hash {
		d.Close()
		return fmt.Errorf("%w: the copy's content hash differs from the source's", ErrCorrupt)
	}
	// Nothing was written through d, so Close has nothing to commit and cannot
	// fail; what matters is that the bytes the check just read are on disk.
	d.Close()
	return dst.Sync()
}
