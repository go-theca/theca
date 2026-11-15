// Package format holds the on-disk layout of a Theca container: the
// geometry derived from the authenticated header, the header body, the
// keyslots and the recovery code (DESIGN 9).
//
// Nothing in a container is plaintext. Every size used here comes either from
// this package's constants or from the header body after it authenticated,
// and is range-checked before it is used (DESIGN 10.1).
package format

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/go-theca/theca/internal/journal"
	"github.com/go-theca/theca/internal/merkle"
	"github.com/go-theca/theca/internal/ta1"
)

// Fixed layout constants.
const (
	SaltSize   = 32
	NumSlots   = 16
	SlotSize   = 2048
	HeaderSize = 8192 // sealed header body, copies A and B
	BodySize   = HeaderSize - ta1.SealOverhead
	Align      = 4096
	TailAlign  = 1 << 20 // the file is rounded to the next MiB (DESIGN 9.1)

	SlotsOff = SaltSize
	HdrOff   = SlotsOff + NumSlots*SlotSize // 32800

	// MaxJournalBytes caps the journal at 1 GiB (DESIGN 10.1).
	MaxJournalBytes = 1 << 30
	MaxJournal      = MaxJournalBytes / journal.EntrySize
	// MaxCounterName bounds a TPM NV Name (hash alg id + 32-byte digest).
	MaxCounterName = 64
)

// Errors.
var (
	ErrGeometry = errors.New("format: geometry out of range")
	ErrBody     = errors.New("format: header body invalid")
)

// Geometry gives every area's byte offset. All arithmetic is uint64.
type Geometry struct {
	Sectors        uint64
	JournalEntries uint32
	Shape          merkle.Shape

	HdrA, HdrB uint64
	JournalOff uint64
	MetaOff    uint64
	TreeOff    uint64
	DataOff    uint64
	End        uint64 // total file size, a multiple of 1 MiB
}

func alignUp(v, a uint64) uint64 { return (v + a - 1) / a * a }

// MinJournal is the smallest journal that can hold one sector write: the
// data sector, its metadata block, the tree path and the commit entry.
func MinJournal(shape merkle.Shape) uint32 { return uint32(shape.Levels()) + 4 }

// NewGeometry computes the layout. It refuses anything that would not fit
// in an int64 file size.
func NewGeometry(sectors uint64, journalEntries uint32) (Geometry, error) {
	shape, err := merkle.NewShape(sectors)
	if err != nil {
		return Geometry{}, fmt.Errorf("%w: %v", ErrGeometry, err)
	}
	if journalEntries < MinJournal(shape) || journalEntries > MaxJournal {
		return Geometry{}, fmt.Errorf("%w: %d journal entries", ErrGeometry, journalEntries)
	}
	g := Geometry{Sectors: sectors, JournalEntries: journalEntries, Shape: shape}
	g.HdrA = HdrOff
	g.HdrB = g.HdrA + HeaderSize
	g.JournalOff = alignUp(g.HdrB+HeaderSize, Align)
	g.MetaOff = g.JournalOff + uint64(journalEntries)*journal.EntrySize
	g.MetaOff = alignUp(g.MetaOff, Align)
	g.TreeOff = g.MetaOff + shape.MetaBlocks*Align
	g.DataOff = g.TreeOff + shape.NodeCount()*Align
	g.End = alignUp(g.DataOff+sectors*Align, TailAlign)
	// The largest container is 2^40 sectors of 4 KiB plus a journal of at
	// most 1 GiB and the tree: below 2^53 bytes, far inside int64 and uint64.
	return g, nil
}

// Header returns the offset of header copy i (0 = A, 1 = B).
func (g Geometry) Header(i uint64) uint64 {
	if i%2 == 0 {
		return g.HdrA
	}
	return g.HdrB
}

// Counter is the rollback-counter binding recorded in the header (DESIGN
// 5.4): the NV index handle, its NV Name and the bound value b.
type Counter struct {
	Handle uint32
	Name   []byte
	Bound  uint64
}

// Body is the authenticated, encrypted header body.
type Body struct {
	CID            [16]byte
	Sectors        uint64
	JournalEntries uint32
	Epoch          uint64
	Root           [32]byte
	SlotsUsed      uint16 // bit i set: slot i holds a sealed object
	Counter        *Counter
}

const (
	version  = 1
	suiteTA1 = 1
	flagCtr  = 1
)

// Marshal returns exactly BodySize bytes.
func (b *Body) Marshal() []byte {
	p := make([]byte, BodySize)
	p[0], p[1] = version, suiteTA1
	copy(p[4:20], b.CID[:])
	binary.LittleEndian.PutUint64(p[20:], b.Sectors)
	binary.LittleEndian.PutUint32(p[28:], b.JournalEntries)
	binary.LittleEndian.PutUint64(p[32:], b.Epoch)
	copy(p[40:72], b.Root[:])
	binary.LittleEndian.PutUint16(p[72:], b.SlotsUsed)
	if c := b.Counter; c != nil {
		p[2] = flagCtr
		binary.LittleEndian.PutUint32(p[74:], c.Handle)
		p[78] = byte(len(c.Name))
		copy(p[79:143], c.Name)
		binary.LittleEndian.PutUint64(p[143:], c.Bound)
	}
	return p
}

// ParseBody validates an authenticated body against the file size.
func ParseBody(p []byte, fileSize uint64) (*Body, Geometry, error) {
	if len(p) != BodySize {
		return nil, Geometry{}, fmt.Errorf("%w: %d bytes", ErrBody, len(p))
	}
	if p[0] != version || p[1] != suiteTA1 || p[2]&^flagCtr != 0 || p[3] != 0 {
		return nil, Geometry{}, fmt.Errorf("%w: unknown version, suite or flags", ErrBody)
	}
	b := &Body{
		Sectors:        binary.LittleEndian.Uint64(p[20:]),
		JournalEntries: binary.LittleEndian.Uint32(p[28:]),
		Epoch:          binary.LittleEndian.Uint64(p[32:]),
		SlotsUsed:      binary.LittleEndian.Uint16(p[72:]),
	}
	copy(b.CID[:], p[4:20])
	copy(b.Root[:], p[40:72])
	if p[2]&flagCtr != 0 {
		n := int(p[78])
		if n == 0 || n > MaxCounterName {
			return nil, Geometry{}, fmt.Errorf("%w: counter name length %d", ErrBody, n)
		}
		b.Counter = &Counter{
			Handle: binary.LittleEndian.Uint32(p[74:]),
			Name:   append([]byte(nil), p[79:79+n]...),
			Bound:  binary.LittleEndian.Uint64(p[143:]),
		}
	}
	for _, v := range p[151:] {
		if v != 0 {
			return nil, Geometry{}, fmt.Errorf("%w: non-zero padding", ErrBody)
		}
	}
	if p[2]&flagCtr == 0 && (binary.LittleEndian.Uint32(p[74:]) != 0 || p[78] != 0 ||
		binary.LittleEndian.Uint64(p[143:]) != 0) {
		return nil, Geometry{}, fmt.Errorf("%w: counter fields without the flag", ErrBody)
	}
	g, err := NewGeometry(b.Sectors, b.JournalEntries)
	if err != nil {
		return nil, Geometry{}, err
	}
	if g.End > fileSize {
		return nil, Geometry{}, fmt.Errorf("%w: header describes %d bytes, file has %d", ErrBody, g.End, fileSize)
	}
	return b, g, nil
}

// SealHeader seals a body with TA1 under the master secret.
func SealHeader(k *ta1.Keys, b *Body, rng io.Reader) ([]byte, error) {
	return k.Seal(ta1.LabelHeader, nil, b.Marshal(), rng)
}

// OpenHeader authenticates and parses a header copy.
func OpenHeader(k *ta1.Keys, blob []byte, fileSize uint64) (*Body, Geometry, error) {
	p, err := k.Open(ta1.LabelHeader, nil, blob)
	if err != nil {
		return nil, Geometry{}, err
	}
	return ParseBody(p, fileSize)
}
