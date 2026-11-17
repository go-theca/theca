package lru

import "testing"

func TestEvictsLeastRecentlyUsed(t *testing.T) {
	var evicted []int
	c := New[int](3, nil, func(v int) { evicted = append(evicted, v) })
	for i := uint64(0); i < 3; i++ {
		c.Put(i, int(i))
	}
	c.Get(0)    // 0 is now the most recent; 1 the least
	c.Put(3, 3) // evicts 1
	if len(evicted) != 1 || evicted[0] != 1 || c.Len() != 3 {
		t.Fatalf("evicted %v, len %d", evicted, c.Len())
	}
	if _, ok := c.Get(1); ok {
		t.Fatal("an evicted entry is still there")
	}
	if v, ok := c.Peek(2); !ok || v != 2 {
		t.Fatalf("Peek(2) = %d %v", v, ok)
	}
	if _, ok := c.Peek(1); ok {
		t.Fatal("Peek found an evicted entry")
	}
	if c.Peak() != 3 {
		t.Fatalf("peak %d", c.Peak())
	}
}

func TestPeekDoesNotTouch(t *testing.T) {
	c := New[int](2, nil, nil)
	c.Put(0, 0)
	c.Put(1, 1)
	c.Peek(0) // must not save 0
	c.Put(2, 2)
	if _, ok := c.Peek(0); ok {
		t.Fatal("Peek refreshed the entry")
	}
}

func TestPinnedAreNeverEvicted(t *testing.T) {
	pin := map[uint64]bool{0: true, 1: true}
	var evicted []int
	c := New[int](2, func(k uint64) bool { return pin[k] }, func(v int) { evicted = append(evicted, v) })
	for i := uint64(0); i < 6; i++ {
		c.Put(i, int(i))
	}
	// 0 and 1 are pinned; the newest is never evicted by its own Put.
	if _, ok := c.Peek(0); !ok {
		t.Fatal("a pinned entry was evicted")
	}
	if _, ok := c.Peek(1); !ok {
		t.Fatal("a pinned entry was evicted")
	}
	if _, ok := c.Peek(5); !ok {
		t.Fatal("the entry just stored was evicted")
	}
	// Everything pinned: the cache may exceed its bound rather than drop one.
	pin[2], pin[3], pin[4], pin[5] = true, true, true, true
	c.Put(6, 6)
	if c.Len() < 3 {
		t.Fatalf("len %d", c.Len())
	}
	// Unpinned, the next Put brings it back to the bound.
	clear(pin)
	c.Put(7, 7)
	if c.Len() != 2 {
		t.Fatalf("len %d after unpinning", c.Len())
	}
}

func TestPutReplacesAndWipesTheOld(t *testing.T) {
	var evicted []int
	c := New[int](4, nil, func(v int) { evicted = append(evicted, v) })
	c.Put(1, 10)
	c.Put(1, 11)
	if v, _ := c.Get(1); v != 11 || len(evicted) != 1 || evicted[0] != 10 || c.Len() != 1 {
		t.Fatalf("got %d, evicted %v", v, evicted)
	}
}

func TestSetMaxShrinksAtTheNextPut(t *testing.T) {
	c := New[int](5, nil, nil)
	for i := uint64(0); i < 5; i++ {
		c.Put(i, 0)
	}
	c.SetMax(2)
	c.Put(5, 0)
	if c.Len() != 2 {
		t.Fatalf("len %d", c.Len())
	}
}

func TestClearEvictsEverythingEvenPinned(t *testing.T) {
	n := 0
	c := New[int](4, func(uint64) bool { return true }, func(int) { n++ })
	c.Put(1, 1)
	c.Put(2, 2)
	c.Clear()
	if c.Len() != 0 || n != 2 {
		t.Fatalf("len %d, wiped %d", c.Len(), n)
	}
}

func TestNilCallbacksAndMissingKeys(t *testing.T) {
	c := New[int](1, nil, nil)
	if _, ok := c.Get(9); ok {
		t.Fatal("found a missing key")
	}
	c.Put(1, 1)
	c.Put(1, 2) // replace with no onEvict
	c.Put(2, 3) // evict with no onEvict
	c.Clear()
}
