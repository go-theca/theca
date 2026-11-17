// Package lru is a bounded cache keyed by uint64 for the verified clean
// entries of an open container (go-theca/theca#6). It never decides what is
// safe to drop: the owner says which entries are pinned (dirty, or in use), and
// a pinned entry is never evicted. An evicted entry is handed to onEvict, which
// wipes it, and is simply read and authenticated again if it is needed again.
package lru

import "container/list"

type entry[V any] struct {
	key uint64
	val V
}

// Cache is a least-recently-used cache. It is not safe for concurrent use; the
// container's lock covers it.
type Cache[V any] struct {
	max     int
	pinned  func(key uint64) bool
	onEvict func(V)
	order   *list.List // front: most recently used
	items   map[uint64]*list.Element
	peak    int
}

// New returns a cache holding at most max entries, not counting pinned ones
// that cannot be evicted. pinned and onEvict may be nil.
func New[V any](max int, pinned func(uint64) bool, onEvict func(V)) *Cache[V] {
	return &Cache[V]{max: max, pinned: pinned, onEvict: onEvict,
		order: list.New(), items: map[uint64]*list.Element{}}
}

// SetMax changes the bound; the cache shrinks at the next Put.
func (c *Cache[V]) SetMax(max int) { c.max = max }

// Len is the number of entries held.
func (c *Cache[V]) Len() int { return len(c.items) }

// Peak is the most entries the cache has held at the end of a Put.
func (c *Cache[V]) Peak() int { return c.peak }

// Get returns the entry and marks it most recently used.
func (c *Cache[V]) Get(key uint64) (V, bool) {
	e, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(e)
	return e.Value.(*entry[V]).val, true
}

// Peek returns the entry without touching its recency.
func (c *Cache[V]) Peek(key uint64) (V, bool) {
	e, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	return e.Value.(*entry[V]).val, true
}

// Put stores the entry as most recently used, handing a replaced value to
// onEvict, then evicts the least recently used unpinned entries until the
// bound holds.
func (c *Cache[V]) Put(key uint64, val V) {
	if e, ok := c.items[key]; ok {
		en := e.Value.(*entry[V])
		if c.onEvict != nil {
			c.onEvict(en.val)
		}
		en.val = val
		c.order.MoveToFront(e)
	} else {
		c.items[key] = c.order.PushFront(&entry[V]{key, val})
	}
	for e := c.order.Back(); e != nil && len(c.items) > c.max; {
		prev := e.Prev()
		en := e.Value.(*entry[V])
		if en.key != key && (c.pinned == nil || !c.pinned(en.key)) {
			c.remove(e)
		}
		e = prev
	}
	c.peak = max(c.peak, len(c.items))
}

func (c *Cache[V]) remove(e *list.Element) {
	en := e.Value.(*entry[V])
	c.order.Remove(e)
	delete(c.items, en.key)
	if c.onEvict != nil {
		c.onEvict(en.val)
	}
}

// Clear evicts everything, pinned or not (the container is closing).
func (c *Cache[V]) Clear() {
	for e := c.order.Back(); e != nil; e = c.order.Back() {
		c.remove(e)
	}
}
