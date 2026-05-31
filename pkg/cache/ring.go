package cache

import (
	"context"
	"sync"
	"time"
)

type ringEntry[K comparable, V any] struct {
	key       K
	value     V
	expiresAt time.Time
	occupied  bool
}

// RingCache is a fixed-size, allocation-free, circular buffer cache.
// New entries overwrite the oldest slot. There is no eviction callback.
// Look-ups use the index map and are O(1) on average.
type RingCache[K comparable, V any] struct {
	mu         sync.RWMutex
	buf        []ringEntry[K, V]
	index      map[K]int // key → slot position
	head       int       // next write position
	defaultTTL time.Duration
}

// NewRingCache constructs a fixed-capacity ring-buffer cache. New entries overwrite the oldest slot.
func NewRingCache[K comparable, V any](capacity int, defaultTTL time.Duration) *RingCache[K, V] {
	if capacity <= 0 {
		capacity = 256
	}
	return &RingCache[K, V]{
		buf:        make([]ringEntry[K, V], capacity),
		index:      make(map[K]int, capacity),
		defaultTTL: defaultTTL,
	}
}

// Get implements Cache.
func (c *RingCache[K, V]) Get(_ context.Context, key K) (V, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pos, ok := c.index[key]
	if !ok {
		var zero V
		return zero, ErrNotFound
	}

	entry := &c.buf[pos]
	if !entry.occupied {
		var zero V
		return zero, ErrNotFound
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		var zero V
		return zero, ErrNotFound
	}
	return entry.value, nil
}

// Set implements Cache.
func (c *RingCache[K, V]) Set(_ context.Context, key K, value V, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If the key already exists, update in place.
	if pos, ok := c.index[key]; ok {
		c.buf[pos] = ringEntry[K, V]{
			key: key, value: value, expiresAt: expiresAt, occupied: true,
		}
		return nil
	}

	// Overwrite the slot at head.
	old := &c.buf[c.head]
	if old.occupied {
		delete(c.index, old.key)
	}
	c.buf[c.head] = ringEntry[K, V]{
		key: key, value: value, expiresAt: expiresAt, occupied: true,
	}
	c.index[key] = c.head

	c.head = (c.head + 1) % len(c.buf)
	return nil
}

// Del implements Cache.
func (c *RingCache[K, V]) Del(_ context.Context, key K) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	pos, ok := c.index[key]
	if !ok {
		return nil
	}
	c.buf[pos].occupied = false
	delete(c.index, key)
	return nil
}

// Has implements Cache.
func (c *RingCache[K, V]) Has(_ context.Context, key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pos, ok := c.index[key]
	if !ok {
		return false
	}
	entry := &c.buf[pos]
	if !entry.occupied {
		return false
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		return false
	}
	return true
}

// Len implements Cache.
func (c *RingCache[K, V]) Len(_ context.Context) int {
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := 0
	for _, pos := range c.index {
		entry := &c.buf[pos]
		if entry.occupied && (entry.expiresAt.IsZero() || now.Before(entry.expiresAt)) {
			n++
		}
	}
	return n
}

// Flush implements Cache.
func (c *RingCache[K, V]) Flush(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.buf {
		c.buf[i].occupied = false
	}
	c.index = make(map[K]int, len(c.buf))
	c.head = 0
	return nil
}

// Close implements Cache.
func (c *RingCache[K, V]) Close() error {
	return c.Flush(context.Background())
}

// Cap returns the fixed capacity of the ring buffer.
func (c *RingCache[K, V]) Cap() int {
	return len(c.buf)
}

// Range implements Ranger. It snapshots all live entries under the read lock,
// releases the lock, then calls fn on the snapshot. This keeps the lock hold
// time minimal and prevents fn from blocking concurrent Set/Del calls.
// Return false from fn to stop early.
func (c *RingCache[K, V]) Range(_ context.Context, fn func(K, V) bool) {
	now := time.Now()
	type kv struct {
		k K
		v V
	}
	c.mu.RLock()
	snap := make([]kv, 0, len(c.index))
	for _, pos := range c.index {
		e := &c.buf[pos]
		if e.occupied && (e.expiresAt.IsZero() || now.Before(e.expiresAt)) {
			snap = append(snap, kv{e.key, e.value})
		}
	}
	c.mu.RUnlock()
	for _, item := range snap {
		if !fn(item.k, item.v) {
			return
		}
	}
}
