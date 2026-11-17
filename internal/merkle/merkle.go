// Package merkle implements Theca's integrity tree (DESIGN 5.2).
//
// Level 1 is the metadata block itself: 64 (seed, tag) pairs of 64 bytes. Its
// value is N1 = HMAC(Km, n1 || block). Levels >= 2 are 128-ary 4 KiB nodes
// holding 128 child values of 32 bytes each. A node that was never written
// has the constant value D(l), so it is never read and never stored: a
// parent records D(l) for an untouched child.
package merkle

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"github.com/go-theca/theca/internal/lru"
	"slices"

	"github.com/go-theca/theca/internal/ta1"
)

// Geometry constants.
const (
	NodeSize     = 4096
	ChildSize    = 32
	Fanout       = NodeSize / ChildSize // 128
	MetaPerBlock = 64                   // sectors per level-1 block
	// MaxSectors bounds a container (DESIGN 10.1): 2^40 sectors of 4 KiB.
	MaxSectors = 1 << 40
)

// Errors.
var (
	ErrTamper = errors.New("merkle: node does not match its parent")
	ErrRange  = errors.New("merkle: index out of range")
	ErrShape  = errors.New("merkle: invalid sector count")
)

// Shape is the tree geometry derived from the sector count. All arithmetic
// is uint64 (DESIGN 10.4).
type Shape struct {
	Sectors    uint64
	MetaBlocks uint64
	counts     []uint64 // counts[i] = nodes at level i+2
	base       []uint64 // base[i] = first ordinal of level i+2
}

// NewShape computes the geometry. Sectors must be in [1, MaxSectors].
func NewShape(sectors uint64) (Shape, error) {
	if sectors == 0 || sectors > MaxSectors {
		return Shape{}, fmt.Errorf("%w: %d", ErrShape, sectors)
	}
	s := Shape{Sectors: sectors, MetaBlocks: (sectors + MetaPerBlock - 1) / MetaPerBlock}
	n := (s.MetaBlocks + Fanout - 1) / Fanout
	var total uint64
	for {
		s.counts = append(s.counts, n)
		s.base = append(s.base, total)
		total += n
		if n == 1 {
			return s, nil
		}
		n = (n + Fanout - 1) / Fanout
	}
}

// Levels is the number of upper levels (>= 1). The root node is at level
// Levels()+1.
func (s Shape) Levels() int { return len(s.counts) }

// NodeCount is the number of upper nodes in the tree area.
func (s Shape) NodeCount() uint64 {
	last := len(s.counts) - 1
	return s.base[last] + s.counts[last]
}

// Ordinal maps (level >= 2, index) to a linear node number.
func (s Shape) Ordinal(level int, idx uint64) (uint64, error) {
	i := level - 2
	if i < 0 || i >= len(s.counts) || idx >= s.counts[i] {
		return 0, ErrRange
	}
	return s.base[i] + idx, nil
}

// Locate is the inverse of Ordinal.
func (s Shape) Locate(ord uint64) (level int, idx uint64, err error) {
	for i := range s.counts {
		if ord < s.base[i]+s.counts[i] {
			return i + 2, ord - s.base[i], nil
		}
	}
	return 0, 0, ErrRange
}

// NodeStore reads a stored node by ordinal. It returns exactly NodeSize
// bytes.
type NodeStore interface {
	LoadNode(ord uint64) ([]byte, error)
}

// N1 is the value of a level-1 (metadata) block.
func N1(k *ta1.Keys, block []byte) [32]byte { return k.MAC(ta1.LabelNode1, block) }

func nodeValue(k *ta1.Keys, level int, children []byte) [32]byte {
	return k.MAC(ta1.LabelNode, []byte{byte(level)}, children)
}

// Tree is the in-memory view of the upper levels. Nodes are loaded lazily,
// each verified against its parent slot (and the root against the header),
// then cached. Mutations mark nodes dirty until the caller clears them.
type Tree struct {
	k     *ta1.Keys
	shape Shape
	store NodeStore
	def   [][32]byte // def[l] = D(l), l >= 1
	root  [32]byte
	// nodes holds the verified nodes: a bounded LRU of clean ones. A dirty node
	// is part of the transaction under construction and is never evicted, nor
	// is a node of the path SetMeta is updating. An evicted node is wiped and,
	// if needed again, read and verified against its parent again.
	nodes *lru.Cache[*[NodeSize]byte]
	dirty map[uint64]struct{}
	pins  map[uint64]struct{}
}

// DefaultCacheNodes bounds the clean nodes a tree keeps (4 KiB each: 32 MiB).
const DefaultCacheNodes = 8192

// New builds a tree whose authenticated root is root.
func New(k *ta1.Keys, shape Shape, root [32]byte, store NodeStore) *Tree {
	t := &Tree{k: k, shape: shape, store: store, root: root,
		dirty: map[uint64]struct{}{}, pins: map[uint64]struct{}{}}
	t.nodes = lru.New(DefaultCacheNodes, func(ord uint64) bool {
		_, d := t.dirty[ord]
		_, p := t.pins[ord]
		return d || p
	}, func(n *[NodeSize]byte) { clear(n[:]) })
	t.def = make([][32]byte, shape.Levels()+2)
	t.def[1] = k.MAC(ta1.LabelEmpty)
	for l := 2; l < len(t.def); l++ {
		var full [NodeSize]byte
		for i := 0; i < Fanout; i++ {
			copy(full[i*ChildSize:], t.def[l-1][:])
		}
		t.def[l] = nodeValue(k, l, full[:])
	}
	return t
}

// EmptyRoot is the root of a tree with nothing written.
func EmptyRoot(k *ta1.Keys, shape Shape) [32]byte {
	return New(k, shape, [32]byte{}, nil).def[shape.Levels()+1]
}

// Default returns D(1), the value of a never-written metadata block.
func (t *Tree) Default() [32]byte { return t.def[1] }

// Root returns the current root.
func (t *Tree) Root() [32]byte { return t.root }

func (t *Tree) top() int { return t.shape.Levels() + 1 }

// node returns the verified node (level, idx), loading it if needed.
func (t *Tree) node(level int, idx uint64) (*[NodeSize]byte, error) {
	// Callers only pass levels and indexes derived from a checked metadata
	// index, so the ordinal is in range by construction.
	ord := t.shape.base[level-2] + idx
	if n, ok := t.nodes.Get(ord); ok {
		return n, nil
	}
	var want [32]byte
	if level == t.top() {
		want = t.root
	} else {
		p, err := t.node(level+1, idx/Fanout)
		if err != nil {
			return nil, err
		}
		copy(want[:], p[(idx%Fanout)*ChildSize:])
	}
	n := new([NodeSize]byte)
	if want == t.def[level] {
		for i := 0; i < Fanout; i++ {
			copy(n[i*ChildSize:], t.def[level-1][:])
		}
	} else {
		raw, err := t.store.LoadNode(ord)
		if err != nil {
			return nil, err
		}
		if len(raw) != NodeSize {
			return nil, fmt.Errorf("%w: level %d node %d has %d bytes", ErrTamper, level, idx, len(raw))
		}
		if got := nodeValue(t.k, level, raw); !hmac.Equal(got[:], want[:]) {
			return nil, fmt.Errorf("%w: level %d node %d", ErrTamper, level, idx)
		}
		copy(n[:], raw)
	}
	t.nodes.Put(ord, n)
	return n, nil
}

// Meta returns the verified recorded value of metadata block m. It equals
// Default() for a block that was never written.
func (t *Tree) Meta(m uint64) ([32]byte, error) {
	if m >= t.shape.MetaBlocks {
		return [32]byte{}, ErrRange
	}
	n, err := t.node(2, m/Fanout)
	if err != nil {
		return [32]byte{}, err
	}
	var v [32]byte
	copy(v[:], n[(m%Fanout)*ChildSize:])
	return v, nil
}

// SetMeta records v as the value of metadata block m and recomputes the path
// to the root. The whole path is loaded and verified before anything
// changes, so a tampered node can never be blessed by an update.
func (t *Tree) SetMeta(m uint64, v [32]byte) error {
	if m >= t.shape.MetaBlocks {
		return ErrRange
	}
	path := make([]*[NodeSize]byte, 0, t.top())
	idxs := make([]uint64, 0, t.top())
	// The path is held while it is loaded and rewritten: pin it, so loading
	// one node can never evict (and wipe) another.
	defer clear(t.pins)
	for l, i := 2, m/Fanout; l <= t.top(); l, i = l+1, i/Fanout {
		n, err := t.node(l, i)
		if err != nil {
			return err
		}
		ord, _ := t.shape.Ordinal(l, i)
		t.pins[ord] = struct{}{}
		path = append(path, n)
		idxs = append(idxs, i)
	}
	val, slot := v, m%Fanout
	for j, n := range path {
		copy(n[slot*ChildSize:], val[:])
		ord, _ := t.shape.Ordinal(j+2, idxs[j])
		t.dirty[ord] = struct{}{}
		val = nodeValue(t.k, j+2, n[:])
		slot = idxs[j] % Fanout
	}
	t.root = val
	return nil
}

// Dirty lists the ordinals changed since the last ClearDirty.
func (t *Tree) Dirty() []uint64 {
	out := make([]uint64, 0, len(t.dirty))
	for o := range t.dirty {
		out = append(out, o)
	}
	sortU64(out)
	return out
}

// DirtyCount is len(Dirty()).
func (t *Tree) DirtyCount() int { return len(t.dirty) }

// Bytes returns the current content of a loaded node, or nil if it is not
// cached. A dirty node is always cached.
func (t *Tree) Bytes(ord uint64) []byte {
	n, ok := t.nodes.Peek(ord)
	if !ok {
		return nil
	}
	return n[:]
}

// SetCacheLimit bounds the clean nodes kept to n, but never below the nodes of
// one path (the tree's height plus a few), so a path can always be held.
func (t *Tree) SetCacheLimit(n int) { t.nodes.SetMax(max(n, t.top()+4)) }

// CacheLen is the number of nodes held, and CachePeak the most it has held.
func (t *Tree) CacheLen() int  { return t.nodes.Len() }
func (t *Tree) CachePeak() int { return t.nodes.Peak() }

// Wipe clears and forgets every cached node (the container is closing).
func (t *Tree) Wipe() { t.nodes.Clear() }

// ClearDirty forgets the dirty set after the nodes were committed.
func (t *Tree) ClearDirty() { clear(t.dirty) }

func sortU64(a []uint64) { slices.Sort(a) }
