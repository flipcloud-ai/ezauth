package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"sync"
	"time"

	"github.com/flipcloud-ai/ezauth/log"
)

// DefaultMemoryShards is the default shard count when callers don't specify one.
const DefaultMemoryShards = 16

type memEntry[K comparable, V any] struct {
	key        K
	value      V
	expiresAt  time.Time
	prev, next *memEntry[K, V]
}

// memoryShard is a single LRU shard with its own lock and intrusive linked list.
// capacity is the per-shard entry limit.
type memoryShard[K comparable, V any] struct {
	mu         sync.RWMutex
	capacity   int
	defaultTTL time.Duration
	items      map[K]*memEntry[K, V]
	head       memEntry[K, V] // sentinel
	len        int
}

func newMemoryShard[K comparable, V any](capacity int, defaultTTL time.Duration) *memoryShard[K, V] {
	if capacity <= 0 {
		capacity = 64
	}
	s := &memoryShard[K, V]{
		capacity:   capacity,
		defaultTTL: defaultTTL,
		items:      make(map[K]*memEntry[K, V], capacity),
	}
	s.head.next = &s.head
	s.head.prev = &s.head
	return s
}

func (c *memoryShard[K, V]) Get(_ context.Context, key K) (V, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok {
		var zero V
		return zero, ErrNotFound
	}

	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.removeEntry(entry)
		var zero V
		return zero, ErrNotFound
	}

	c.moveToFront(entry)
	return entry.value, nil
}

func (c *memoryShard[K, V]) Set(_ context.Context, key K, value V, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		c.moveToFront(entry)
		entry.value = value
		entry.expiresAt = expiresAt
		return nil
	}

	entry := &memEntry[K, V]{key: key, value: value, expiresAt: expiresAt}
	c.pushFront(entry)
	c.items[key] = entry

	if c.len > c.capacity {
		c.removeOldest()
	}

	return nil
}

func (c *memoryShard[K, V]) Del(_ context.Context, key K) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		c.removeEntry(entry)
	}
	return nil
}

func (c *memoryShard[K, V]) Has(_ context.Context, key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.items[key]
	if !ok {
		return false
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		return false
	}
	return true
}

func (c *memoryShard[K, V]) Len(_ context.Context) int {
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := 0
	for _, entry := range c.items {
		if entry.expiresAt.IsZero() || now.Before(entry.expiresAt) {
			n++
		}
	}
	return n
}

func (c *memoryShard[K, V]) Flush(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[K]*memEntry[K, V], c.capacity)
	c.head.next = &c.head
	c.head.prev = &c.head
	c.len = 0
	return nil
}

func (c *memoryShard[K, V]) Close() error {
	return c.Flush(context.Background())
}

func (c *memoryShard[K, V]) moveToFront(e *memEntry[K, V]) {
	if c.head.next == e {
		return
	}
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev = &c.head
	e.next = c.head.next
	c.head.next.prev = e
	c.head.next = e
}

func (c *memoryShard[K, V]) pushFront(e *memEntry[K, V]) {
	e.prev = &c.head
	e.next = c.head.next
	c.head.next.prev = e
	c.head.next = e
	c.len++
}

func (c *memoryShard[K, V]) removeOldest() {
	e := c.head.prev
	if e != &c.head {
		c.removeEntry(e)
	}
}

func (c *memoryShard[K, V]) removeEntry(e *memEntry[K, V]) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil
	e.prev = nil
	delete(c.items, e.key)
	c.len--
}

// MemoryCache is a sharded, thread-safe, generic, in-memory LRU cache with per-key TTL.
// Keys are distributed across independent shards via maphash to minimize lock contention
// under concurrent access.
//
// A background sweep goroutine periodically removes expired entries so that keys with
// short TTLs that are never accessed again after expiry do not cause memory bloat.
type MemoryCache[K comparable, V any] struct {
	shards        []*memoryShard[K, V]
	mask          uint64
	seed          maphash.Seed
	stopCh        chan struct{}
	doneCh        chan struct{}
	sweepInterval time.Duration
	closeOnce     sync.Once
}

// NewMemoryCache creates a sharded in-memory LRU cache sized to hold `size`
// total entries. It uses DefaultMemoryShards for shard count; use
// NewMemoryCacheWithShards to tune the shard count. Use WithLogger to route
// shard-collapse warnings to a structured logger.
func NewMemoryCache[K comparable, V any](size int, defaultTTL time.Duration, opts ...Option) *MemoryCache[K, V] {
	return NewMemoryCacheWithShards[K, V](size, DefaultMemoryShards, defaultTTL, opts...)
}

// NewMemoryCacheWithShards creates a sharded in-memory LRU cache with an
// explicit shard count. `size` is the total number of entries the cache can
// hold. Per-shard capacity is ceil(size / shards); because every shard holds
// at least one entry, the effective total may slightly exceed `size` when
// size is not a multiple of shards. When size is small relative to shards,
// shard count is collapsed so per-shard capacity stays meaningful — without
// this, two keys hashing to the same shard would evict each other even when
// size says they should fit. Use WithLogger to route the collapse warning
// to a structured logger.
func NewMemoryCacheWithShards[K comparable, V any](size, shards int, defaultTTL time.Duration, opts ...Option) *MemoryCache[K, V] {
	co := buildCtorOptions(opts)
	if size <= 0 {
		size = 1024
	}
	if shards <= 0 {
		shards = DefaultMemoryShards
	}
	const minPerShard = 16
	requested := nextPow2(shards)
	n := requested
	for n > 1 && size/n < minPerShard {
		n >>= 1
	}
	if n != requested {
		co.logger.Warn("MemoryCache collapsed shards to keep per-shard capacity at or above floor",
			log.Int("requested_shards", requested),
			log.Int("effective_shards", n),
			log.Int("floor_entries_per_shard", minPerShard),
			log.Int("size", size),
		)
	}
	// Round up so shards * perShard >= size (integer division would otherwise
	// silently lose capacity, e.g. size=10, n=8 -> perShard=1 total=8).
	perShard := (size + n - 1) / n
	ss := make([]*memoryShard[K, V], n)
	for i := range ss {
		ss[i] = newMemoryShard[K, V](perShard, defaultTTL)
	}
	mc := &MemoryCache[K, V]{
		shards:        ss,
		mask:          uint64(n - 1), //nolint:gosec // n is always a positive power-of-two, overflow impossible
		seed:          maphash.MakeSeed(),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		sweepInterval: computeSweepInterval(defaultTTL),
	}
	mc.startSweeper()
	return mc
}

func (c *MemoryCache[K, V]) shard(key K) *memoryShard[K, V] {
	return c.shards[maphash.Comparable(c.seed, key)&c.mask]
}

// Get implements Cache.
func (c *MemoryCache[K, V]) Get(ctx context.Context, key K) (V, error) {
	return c.shard(key).Get(ctx, key)
}

// Set implements Cache.
func (c *MemoryCache[K, V]) Set(ctx context.Context, key K, val V, ttl time.Duration) error {
	return c.shard(key).Set(ctx, key, val, ttl)
}

// Del implements Cache.
func (c *MemoryCache[K, V]) Del(ctx context.Context, key K) error { return c.shard(key).Del(ctx, key) }

// Has implements Cache.
func (c *MemoryCache[K, V]) Has(ctx context.Context, key K) bool { return c.shard(key).Has(ctx, key) }

// Increment atomically increments the uint64 counter stored at key within a
// single shard lock, preventing TOCTOU races between concurrent callers.
// The counter value is stored as 8-byte big-endian in the V slot.
// Only valid when V = []byte; panics otherwise.
//
// Semantics:
//   - count >= limit: no-op, returns current count (preserves existing TTL).
//   - count < limit: count += delta; if new count >= limit use blockTTL;
//     else keep existing TTL when the entry already exists, otherwise windowTTL.
func (c *MemoryCache[K, V]) Increment(ctx context.Context, key K, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	var count uint64
	var existingTTL time.Time

	if entry, ok := s.items[key]; ok && (entry.expiresAt.IsZero() || now.Before(entry.expiresAt)) {
		raw, ok := any(entry.value).([]byte)
		if !ok {
			return 0, fmt.Errorf("cache: Increment called on non-[]byte MemoryCache[%T]", entry.value)
		}
		if len(raw) == 8 {
			count = binary.BigEndian.Uint64(raw)
		}
		existingTTL = entry.expiresAt
	}

	if count >= limit {
		return count, nil
	}

	count += delta

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, count)
	val, ok := any(buf).(V)
	if !ok {
		return 0, fmt.Errorf("cache: Increment called on non-[]byte MemoryCache")
	}

	var expiresAt time.Time
	if count >= limit {
		ttl := blockTTL
		if ttl == 0 {
			ttl = s.defaultTTL
		}
		if ttl > 0 {
			expiresAt = now.Add(ttl)
		}
	} else if !existingTTL.IsZero() {
		expiresAt = existingTTL
	} else if windowTTL > 0 {
		expiresAt = now.Add(windowTTL)
	}

	if entry, ok := s.items[key]; ok {
		s.moveToFront(entry)
		entry.value = val
		entry.expiresAt = expiresAt
	} else {
		entry := &memEntry[K, V]{key: key, value: val, expiresAt: expiresAt}
		s.pushFront(entry)
		s.items[key] = entry
		if s.len > s.capacity {
			s.removeOldest()
		}
	}

	return count, nil
}

// Len implements Cache.
func (c *MemoryCache[K, V]) Len(ctx context.Context) int {
	n := 0
	for _, s := range c.shards {
		n += s.Len(ctx)
	}
	return n
}

// Shards returns the effective shard count. Always a power of two; may
// be lower than the requested shard count when the cache collapsed
// shards to keep per-shard capacity at or above minPerShard.
func (c *MemoryCache[K, V]) Shards() int { return len(c.shards) }

// Range implements Ranger. It snapshots each shard under a read lock, releases
// the lock, then calls fn on the snapshot. This prevents fn from blocking
// concurrent writes and avoids the deadlock that would occur if fn called
// Get (which acquires a write lock for LRU promotion) on the same shard.
// Return false from fn to stop early.
func (c *MemoryCache[K, V]) Range(_ context.Context, fn func(K, V) bool) {
	now := time.Now()
	type kv struct {
		k K
		v V
	}
	for _, s := range c.shards {
		var snap []kv
		func() {
			s.mu.RLock()
			defer s.mu.RUnlock()
			for _, e := range s.items {
				if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
					snap = append(snap, kv{e.key, e.value})
				}
			}
		}()
		for _, item := range snap {
			if !fn(item.k, item.v) {
				return
			}
		}
	}
}

// Flush implements Cache.
func (c *MemoryCache[K, V]) Flush(ctx context.Context) error {
	for _, s := range c.shards {
		if err := s.Flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close stops the background sweep goroutine and removes all entries.
// Safe to call multiple times.
func (c *MemoryCache[K, V]) Close() error {
	c.closeOnce.Do(func() {
		close(c.stopCh)
		<-c.doneCh
	})
	return c.Flush(context.Background())
}

// computeSweepInterval returns the ticker interval for the expiry sweep.
// Derived from defaultTTL so that short-TTL caches are swept often enough
// without hammering the CPU. When defaultTTL is zero (no expiry), returns
// the minimum interval so the goroutine is still live for Close() but
// effectively a no-op.
func computeSweepInterval(defaultTTL time.Duration) time.Duration {
	const (
		minInterval = 30 * time.Second
		maxInterval = 5 * time.Minute
	)
	return min(max(defaultTTL/2, minInterval), maxInterval)
}

// startSweeper launches the background goroutine that periodically removes
// expired entries from all shards.
func (c *MemoryCache[K, V]) startSweeper() {
	go func() {
		ticker := time.NewTicker(c.sweepInterval)
		defer ticker.Stop()
		defer close(c.doneCh)

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.sweep()
			}
		}
	}()
}

// sweep iterates all shards and removes expired entries from each.
// The per-shard lock is acquired and released one shard at a time so that
// no single shard blocks another's I/O for longer than necessary.
func (c *MemoryCache[K, V]) sweep() {
	for _, s := range c.shards {
		s.removeExpired()
	}
}

// removeExpired acquires the shard lock and removes every entry whose
// expiresAt is in the past. Entries with a zero-value expiresAt (no TTL)
// are never evicted.
func (s *memoryShard[K, V]) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, entry := range s.items {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			s.removeEntry(entry)
		}
	}
}
