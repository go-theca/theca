package merkle

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-theca/theca/internal/ta1"
)

type memStore struct {
	nodes map[uint64][]byte
	reads int
}

func (m *memStore) LoadNode(ord uint64) ([]byte, error) {
	m.reads++
	b, ok := m.nodes[ord]
	if !ok {
		return nil, errors.New("no such node")
	}
	return b, nil
}

func hm(key []byte, parts ...[]byte) [32]byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	var o [32]byte
	h.Sum(o[:0])
	return o
}

func lab(l string) []byte { return append([]byte{byte(len(l))}, l...) }

// naiveRoot recomputes the root from the metadata blocks alone, level by
// level over the whole virtual tree, with HMAC built directly from the
// specification text (DESIGN 5.2) and none of the package's code.
func naiveRoot(km []byte, metaBlocks uint64, blocks map[uint64][]byte) [32]byte {
	d := hm(km, lab(ta1.LabelEmpty))
	values := make([][32]byte, metaBlocks)
	for i := range values {
		if b, ok := blocks[uint64(i)]; ok {
			values[i] = hm(km, lab(ta1.LabelNode1), b)
		} else {
			values[i] = d
		}
	}
	level := 2
	for {
		next := (len(values) + 127) / 128
		out := make([][32]byte, next)
		for n := range out {
			var children []byte
			for c := 0; c < 128; c++ {
				i := n*128 + c
				if i < len(values) {
					children = append(children, values[i][:]...)
				} else {
					children = append(children, d[:]...)
				}
			}
			out[n] = hm(km, lab(ta1.LabelNode), []byte{byte(level)}, children)
		}
		if next == 1 {
			return out[0]
		}
		// A virtual child beyond the real count is the default of the level
		// below, i.e. the value of an all-default node of that level.
		d = hm(km, lab(ta1.LabelNode), []byte{byte(level)}, bytes.Repeat(d[:], 128))
		values = out
		level++
	}
}

func keys(t testing.TB) *ta1.Keys {
	k, err := ta1.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestShape(t *testing.T) {
	for _, c := range []struct {
		sectors uint64
		levels  int
		nodes   uint64
	}{
		{1, 1, 1},
		{64 * 128, 1, 1},
		{64*128 + 1, 2, 3},
		{64 * 128 * 128, 2, 129},
		{MaxSectors, 5, 1<<27 + 1<<20 + 1<<13 + 1<<6 + 1},
	} {
		s, err := NewShape(c.sectors)
		if err != nil {
			t.Fatal(err)
		}
		if s.Levels() != c.levels || s.NodeCount() != c.nodes {
			t.Errorf("%d sectors: levels=%d nodes=%d, want %d, %d", c.sectors, s.Levels(), s.NodeCount(), c.levels, c.nodes)
		}
		for ord := uint64(0); ord < s.NodeCount() && ord < 300; ord++ {
			l, i, err := s.Locate(ord)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := s.Ordinal(l, i); err != nil || back != ord {
				t.Fatalf("ordinal round trip: %d -> (%d,%d) -> %d, %v", ord, l, i, back, err)
			}
		}
		if _, _, err := s.Locate(s.NodeCount()); !errors.Is(err, ErrRange) {
			t.Error("Locate accepted an ordinal past the end")
		}
	}
	for _, n := range []uint64{0, MaxSectors + 1, ^uint64(0)} {
		if _, err := NewShape(n); !errors.Is(err, ErrShape) {
			t.Errorf("NewShape(%d): %v", n, err)
		}
	}
	s, _ := NewShape(100)
	if _, err := s.Ordinal(1, 0); !errors.Is(err, ErrRange) {
		t.Error("level 1 is not an upper node")
	}
	if _, err := s.Ordinal(2, 1); !errors.Is(err, ErrRange) {
		t.Error("index past the level")
	}
	if _, err := s.Ordinal(9, 0); !errors.Is(err, ErrRange) {
		t.Error("level past the root")
	}
}

// commit flushes a tree's dirty nodes into the store, as the container does.
func commit(tr *Tree, st *memStore) {
	for _, o := range tr.Dirty() {
		st.nodes[o] = append([]byte(nil), tr.Bytes(o)...)
	}
	tr.ClearDirty()
}

func TestRootAgainstNaive(t *testing.T) {
	k := keys(t)
	sh, _ := NewShape(64 * 300) // 300 metadata blocks, 3 level-2 nodes, 2 levels
	if sh.Levels() != 2 {
		t.Fatalf("levels = %d", sh.Levels())
	}
	st := &memStore{nodes: map[uint64][]byte{}}
	blocks := map[uint64][]byte{}
	if EmptyRoot(k, sh) != naiveRoot(k.Km[:], sh.MetaBlocks, blocks) {
		t.Fatal("empty root differs from the naive reference")
	}
	tr := New(k, sh, EmptyRoot(k, sh), st)
	for round := 0; round < 40; round++ {
		var idb [1]byte
		rand.Read(idb[:])
		m := uint64(idb[0]) % sh.MetaBlocks
		if round%7 == 0 {
			m = sh.MetaBlocks - 1
		}
		blk := make([]byte, 4096)
		rand.Read(blk)
		blocks[m] = blk
		if err := tr.SetMeta(m, N1(k, blk)); err != nil {
			t.Fatal(err)
		}
		if tr.Root() != naiveRoot(k.Km[:], sh.MetaBlocks, blocks) {
			t.Fatalf("round %d: root differs from the naive reference", round)
		}
		if round%5 == 0 {
			commit(tr, st)
		}
	}
	commit(tr, st)

	// A fresh tree over the same store and root reads back every value.
	fresh := New(k, sh, tr.Root(), st)
	for m := uint64(0); m < sh.MetaBlocks; m++ {
		v, err := fresh.Meta(m)
		if err != nil {
			t.Fatal(err)
		}
		want := fresh.Default()
		if b, ok := blocks[m]; ok {
			want = N1(k, b)
		}
		if v != want {
			t.Fatalf("meta %d: wrong value", m)
		}
	}
}

func TestDeepTreeAgainstNaive(t *testing.T) {
	k := keys(t)
	sh, _ := NewShape(64 * 128 * 130) // 16640 metadata blocks: three upper levels
	if sh.Levels() != 3 {
		t.Fatalf("levels = %d", sh.Levels())
	}
	st := &memStore{nodes: map[uint64][]byte{}}
	tr := New(k, sh, EmptyRoot(k, sh), st)
	blocks := map[uint64][]byte{}
	for _, m := range []uint64{0, 127, 128, 16383, 16384, sh.MetaBlocks - 1} {
		blk := make([]byte, 4096)
		rand.Read(blk)
		blocks[m] = blk
		if err := tr.SetMeta(m, N1(k, blk)); err != nil {
			t.Fatal(err)
		}
	}
	if tr.Root() != naiveRoot(k.Km[:], sh.MetaBlocks, blocks) {
		t.Fatal("deep root differs from the naive reference")
	}
}

func TestDefaultsAreNeverRead(t *testing.T) {
	k := keys(t)
	sh, _ := NewShape(64 * 300)
	st := &memStore{nodes: map[uint64][]byte{}}
	tr := New(k, sh, EmptyRoot(k, sh), st)
	v, err := tr.Meta(299)
	if err != nil || v != tr.Default() || st.reads != 0 {
		t.Fatalf("v=%x err=%v reads=%d", v, err, st.reads)
	}
}

// TestTamperEveryNode: any change to a stored node, and any change of the
// root, is detected when the node is read.
func TestTamperEveryNode(t *testing.T) {
	k := keys(t)
	sh, _ := NewShape(64 * 300)
	st := &memStore{nodes: map[uint64][]byte{}}
	tr := New(k, sh, EmptyRoot(k, sh), st)
	for _, m := range []uint64{3, 140, 299} {
		blk := make([]byte, 4096)
		rand.Read(blk)
		tr.SetMeta(m, N1(k, blk))
	}
	commit(tr, st)
	root := tr.Root()

	for ord := range st.nodes {
		orig := st.nodes[ord]
		for _, pos := range []int{0, 31, 32, 2048, 4095} {
			bad := append([]byte(nil), orig...)
			bad[pos] ^= 1
			st.nodes[ord] = bad
			fresh := New(k, sh, root, st)
			var failed bool
			for m := uint64(0); m < sh.MetaBlocks; m++ {
				if _, err := fresh.Meta(m); err != nil {
					if !errors.Is(err, ErrTamper) {
						t.Fatalf("unexpected error %v", err)
					}
					failed = true
				}
			}
			if !failed {
				t.Fatalf("node %d byte %d: tamper not detected", ord, pos)
			}
		}
		st.nodes[ord] = orig
	}
	// A wrong root: the top node no longer matches.
	badRoot := root
	badRoot[0] ^= 1
	if _, err := New(k, sh, badRoot, st).Meta(3); !errors.Is(err, ErrTamper) {
		t.Fatalf("wrong root: %v", err)
	}
	// A wrong-length node.
	for o := range st.nodes {
		st.nodes[o] = st.nodes[o][:10]
		break
	}
	if _, err := New(k, sh, root, st).Meta(3); err == nil {
		// might hit a different node; scan them all
		var ok bool
		for m := uint64(0); m < sh.MetaBlocks; m++ {
			if _, err := New(k, sh, root, st).Meta(m); err != nil {
				ok = true
			}
		}
		if !ok {
			t.Fatal("short node accepted")
		}
	}
}

func TestSetMetaDoesNotBlessTamperedNode(t *testing.T) {
	k := keys(t)
	sh, _ := NewShape(64 * 300)
	st := &memStore{nodes: map[uint64][]byte{}}
	tr := New(k, sh, EmptyRoot(k, sh), st)
	blk := make([]byte, 4096)
	tr.SetMeta(5, N1(k, blk))
	commit(tr, st)
	root := tr.Root()
	for o := range st.nodes {
		st.nodes[o][100] ^= 1
	}
	fresh := New(k, sh, root, st)
	if err := fresh.SetMeta(6, N1(k, blk)); !errors.Is(err, ErrTamper) {
		t.Fatalf("update over a tampered path: %v", err)
	}
	if fresh.Root() != root {
		t.Fatal("root moved although the update was refused")
	}
}

func TestRangeAndStoreErrors(t *testing.T) {
	k := keys(t)
	sh, _ := NewShape(64 * 2)
	st := &memStore{nodes: map[uint64][]byte{}}
	tr := New(k, sh, EmptyRoot(k, sh), st)
	if _, err := tr.Meta(2); !errors.Is(err, ErrRange) {
		t.Fatal(err)
	}
	if err := tr.SetMeta(2, [32]byte{}); !errors.Is(err, ErrRange) {
		t.Fatal(err)
	}
	// A root that claims content the store does not have.
	tr2 := New(k, sh, [32]byte{1}, st)
	if _, err := tr2.Meta(0); err == nil || errors.Is(err, ErrTamper) {
		t.Fatalf("store error not surfaced: %v", err)
	}
	if err := tr2.SetMeta(0, [32]byte{}); err == nil {
		t.Fatal("update over an unreadable path")
	}
	// Parent unreadable: two-level tree whose level-3 node is missing.
	sh3, _ := NewShape(64 * 128 * 2)
	tr3 := New(k, sh3, [32]byte{1}, st)
	if _, err := tr3.Meta(0); err == nil {
		t.Fatal("missing parent accepted")
	}
}

func TestDirty(t *testing.T) {
	k := keys(t)
	sh, _ := NewShape(64 * 300)
	tr := New(k, sh, EmptyRoot(k, sh), &memStore{})
	tr.SetMeta(200, [32]byte{1})
	tr.SetMeta(1, [32]byte{2})
	d := tr.Dirty()
	if len(d) != 3 || tr.DirtyCount() != 3 || d[0] > d[1] || d[1] > d[2] {
		t.Fatalf("dirty = %v", d)
	}
	tr.ClearDirty()
	if tr.DirtyCount() != 0 {
		t.Fatal("not cleared")
	}
}
