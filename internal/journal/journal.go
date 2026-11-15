// Package journal is Theca's write-ahead journal (DESIGN 5.3, review
// finding R1).
//
// A transaction is a run of sealed records followed by one sealed commit
// entry. Every entry's associated data binds the target epoch (header epoch
// + 1), the entry's position in the transaction and its kind; the commit
// entry additionally covers the record count, a hash of all the sealed
// records and the new tree root. Recovery accepts a transaction only when all
// of that checks out for exactly header epoch + 1, so an older genuine
// transaction copied into the journal, a record moved to another position, a
// dropped or spliced record and a changed root are all refused.
package journal

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/go-theca/theca/internal/ta1"
)

// Sizes.
const (
	BlockSize = 4096
	// EntrySize is one journal slot: a sealed record (1 + 8 + 4096 bytes of
	// plaintext plus the 72-byte seal overhead) padded with random bytes.
	EntrySize = 4352
	recPlain  = 1 + 8 + BlockSize
	recSealed = recPlain + ta1.SealOverhead
	comPlain  = 4 + 32 + 32
	comSealed = comPlain + ta1.SealOverhead
)

// Area says where a record's block goes.
type Area byte

const (
	AreaData Area = 1 // a data sector (ciphertext)
	AreaMeta Area = 2 // a level-1 metadata block
	AreaNode Area = 3 // an upper tree node, by ordinal
)

const (
	kindRecord = 1
	kindCommit = 2
)

// Errors.
var (
	ErrFull  = errors.New("journal: transaction does not fit the journal")
	ErrBlock = errors.New("journal: record block is not 4096 bytes")
)

// Record is one block to write at its destination after the commit.
type Record struct {
	Area  Area
	Index uint64
	Data  []byte
}

// Tx is a transaction: Epoch is the epoch it moves the container to.
type Tx struct {
	Epoch   uint64
	Records []Record
	Root    [32]byte
}

func ad(epoch uint64, seq uint32, kind byte) []byte {
	b := make([]byte, 0, 13)
	b = binary.LittleEndian.AppendUint64(b, epoch)
	b = binary.LittleEndian.AppendUint32(b, seq)
	return append(b, kind)
}

func pad(rng io.Reader, sealed []byte) ([]byte, error) {
	e := make([]byte, EntrySize)
	copy(e, sealed)
	if _, err := io.ReadFull(rng, e[len(sealed):]); err != nil {
		return nil, fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
	}
	return e, nil
}

// Write stores the transaction in the journal area (which holds entries
// slots), calling sync between the records and the commit entry and after
// the commit entry. A crash before the commit entry is durable leaves a
// transaction that recovery will not accept.
func Write(k *ta1.Keys, w io.WriterAt, entries uint32, tx *Tx, rng io.Reader, sync func() error) error {
	if uint64(len(tx.Records))+1 > uint64(entries) {
		return ErrFull
	}
	h := sha256.New()
	for i, r := range tx.Records {
		if len(r.Data) != BlockSize {
			return ErrBlock
		}
		p := make([]byte, 0, recPlain)
		p = append(p, byte(r.Area))
		p = binary.LittleEndian.AppendUint64(p, r.Index)
		p = append(p, r.Data...)
		sealed, err := k.Seal(ta1.LabelJournal, ad(tx.Epoch, uint32(i), kindRecord), p, rng)
		if err != nil {
			return err
		}
		h.Write(sealed)
		e, err := pad(rng, sealed)
		if err != nil {
			return err
		}
		if _, err := w.WriteAt(e, int64(i)*EntrySize); err != nil {
			return err
		}
	}
	if err := sync(); err != nil {
		return err
	}
	c := make([]byte, 0, comPlain)
	c = binary.LittleEndian.AppendUint32(c, uint32(len(tx.Records)))
	c = append(c, tx.Root[:]...)
	c = h.Sum(c)
	sealed, err := k.Seal(ta1.LabelCommit, ad(tx.Epoch, uint32(len(tx.Records)), kindCommit), c, rng)
	if err != nil {
		return err
	}
	e, err := pad(rng, sealed)
	if err != nil {
		return err
	}
	if _, err := w.WriteAt(e, int64(len(tx.Records))*EntrySize); err != nil {
		return err
	}
	return sync()
}

// Recover returns the committed transaction for epoch+1, or nil if the
// journal holds none. A wrong key, a torn write and an old transaction all
// yield nil: recovery never guesses.
func Recover(k *ta1.Keys, r io.ReaderAt, entries uint32, epoch uint64) (*Tx, error) {
	if epoch == ^uint64(0) {
		return nil, nil
	}
	target := epoch + 1
	tx := &Tx{Epoch: target}
	h := sha256.New()
	buf := make([]byte, EntrySize)
	for seq := uint32(0); seq < entries; seq++ {
		if _, err := r.ReadAt(buf, int64(seq)*EntrySize); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, nil
			}
			return nil, err
		}
		if p, err := k.Open(ta1.LabelJournal, ad(target, seq, kindRecord), buf[:recSealed]); err == nil {
			rec, ok := parseRecord(p)
			if !ok {
				return nil, nil
			}
			tx.Records = append(tx.Records, rec)
			h.Write(buf[:recSealed])
			continue
		}
		p, err := k.Open(ta1.LabelCommit, ad(target, seq, kindCommit), buf[:comSealed])
		if err != nil {
			return nil, nil
		}
		if binary.LittleEndian.Uint32(p) != seq {
			return nil, nil
		}
		copy(tx.Root[:], p[4:36])
		if string(h.Sum(nil)) != string(p[36:68]) {
			return nil, nil
		}
		return tx, nil
	}
	return nil, nil
}

func parseRecord(p []byte) (Record, bool) {
	// p is exactly recPlain bytes: Open was given exactly recSealed.
	a := Area(p[0])
	if a != AreaData && a != AreaMeta && a != AreaNode {
		return Record{}, false
	}
	return Record{Area: a, Index: binary.LittleEndian.Uint64(p[1:9]), Data: p[9:]}, true
}
