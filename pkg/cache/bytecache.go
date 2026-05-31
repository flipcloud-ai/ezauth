package cache

import (
	"context"
	"encoding/binary"
	"hash/maphash"
	"sync"
	"time"

	"github.com/flipcloud-ai/ezauth/log"
)

// DefaultByteShards is the default shard count when callers don't specify one.
const DefaultByteShards = 16

type byteEntry struct {
	key        string
	value      []byte
	expiresAt  time.Time
	size       int64 // key len + value len
	prev, next *byteEntry
}

// byteShard is a single byte-budget LRU shard with its own lock and intrusive linked list.
type byteShard struct {
	mu         sync.RWMutex
	capacity   int64
	used       int64
	defaultTTL time.Duration
	items      map[string]*byteEntry
	head       byteEntry // sentinel
	len        int
}

func newByteShard(capacity int64, defaultTTL time.Duration) *byteShard {
	if capacity <= 0 {
		capacity = 1
	}
	s := &byteShard{
		capacity:   capacity,
		defaultTTL: defaultTTL,
		items:      make(map[string]*byteEntry),
	}
	s.head.next = &s.head
	s.head.prev = &s.head
	return s
}

func entrySize(key string, value []byte) int64 {
	return int64(len(key)) + int64(len(value))
}

func (c *byteShard) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok {
		return nil, ErrNotFound
	}

	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.removeEntry(entry)
		return nil, ErrNotFound
	}

	c.moveToFront(entry)
	cp := make([]byte, len(entry.value))
	copy(cp, entry.value)
	return cp, nil
}

func (c *byteShard) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	newSize := entrySize(key, value)
	if newSize > c.capacity {
		return ErrValueTooLarge
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cp := make([]byte, len(value))
	copy(cp, value)

	if entry, ok := c.items[key]; ok {
		c.moveToFront(entry)
		c.used -= entry.size
		entry.value = cp
		entry.expiresAt = expiresAt
		entry.size = newSize
		c.used += newSize
		c.evictUntilFit()
		return nil
	}

	entry := &byteEntry{key: key, value: cp, expiresAt: expiresAt, size: newSize}
	c.pushFront(entry)
	c.items[key] = entry
	c.used += newSize

	c.evictUntilFit()
	return nil
}

func (c *byteShard) Del(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		c.removeEntry(entry)
	}
	return nil
}

func (c *byteShard) Has(_ context.Context, key string) bool {
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

func (c *byteShard) Len(_ context.Context) int {
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

func (c *byteShard) Used() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.used
}

func (c *byteShard) Capacity() int64 {
	return c.capacity
}

func (c *byteShard) Flush(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*byteEntry)
	c.head.next = &c.head
	c.head.prev = &c.head
	c.used = 0
	c.len = 0
	return nil
}

func (c *byteShard) Close() error { return c.Flush(context.Background()) }

// startSweeper launches the background goroutine that periodically removes
// expired entries from all shards.
func (c *ByteCache) startSweeper() {
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
func (c *ByteCache) sweep() {
	for _, s := range c.shards {
		s.removeExpired()
	}
}

// removeExpired acquires the shard lock and removes every entry whose
// expiresAt is in the past. Entries with a zero-value expiresAt (no TTL)
// are never evicted.
func (s *byteShard) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, entry := range s.items {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			s.removeEntry(entry)
		}
	}
}

func (c *byteShard) moveToFront(e *byteEntry) {
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

func (c *byteShard) pushFront(e *byteEntry) {
	e.prev = &c.head
	e.next = c.head.next
	c.head.next.prev = e
	c.head.next = e
	c.len++
}

func (c *byteShard) evictUntilFit() {
	for c.used > c.capacity && c.len > 0 {
		e := c.head.prev
		if e == &c.head {
			break
		}
		c.removeEntry(e)
	}
}

func (c *byteShard) removeEntry(e *byteEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil
	e.prev = nil
	c.used -= e.size
	delete(c.items, e.key)
	c.len--
}

// ByteCache is a sharded, thread-safe, byte-budget LRU cache for []byte values.
// Keys are distributed across independent shards via maphash to minimize lock contention.
//
// A background sweep goroutine periodically removes expired entries so that keys with
// short TTLs that are never accessed again after expiry do not cause memory bloat.
type ByteCache struct {
	shards        []*byteShard
	mask          uint64
	seed          maphash.Seed
	stopCh        chan struct{}
	doneCh        chan struct{}
	sweepInterval time.Duration
	closeOnce     sync.Once
}

// minBytesPerShard is the target per-shard byte budget. Below this, a
// value that fits the total capacity may still be rejected by the shard
// it hashes to, so NewByteCache picks a shard count that keeps per-shard
// budget at or above this floor. Callers that pass an explicit shard
// count via NewByteCacheWithShards are honored exactly — useful for
// distributed-cache topologies where shard count maps to node count —
// with a warning log if the resulting per-shard budget is below the
// floor.
const minBytesPerShard int64 = 4 * 1024

// NewByteCache creates a sharded byte-budget LRU cache of the given total
// capacity in bytes, automatically picking a shard count that keeps
// per-shard budget at or above minBytesPerShard. Any value that fits the
// total capacity will fit in its assigned shard. Use
// NewByteCacheWithShards to pin the shard count explicitly. Use
// WithLogger to route shard-budget-floor warnings to a structured logger.
func NewByteCache(capacity int64, defaultTTL time.Duration, opts ...Option) *ByteCache {
	if capacity <= 0 {
		capacity = 200 * 1024 * 1024 // 200 MB default
	}
	// Pick the largest power-of-two shard count (up to DefaultByteShards)
	// whose per-shard budget is still at or above the 4 KiB floor. Halve
	// from the default until capacity/n >= minBytesPerShard or we hit 1.
	shards := DefaultByteShards
	for shards > 1 && capacity/int64(shards) < minBytesPerShard {
		shards >>= 1
	}
	return newByteCache(capacity, shards, defaultTTL, opts...)
}

// NewByteCacheWithShards creates a sharded byte-budget LRU cache with an
// explicit shard count. capacity is the total byte budget, distributed
// as ceil(capacity / shards) per shard (shards rounded up to the next
// power of two). Shard count is honored exactly — no silent collapse —
// so callers targeting a distributed-cache topology can trust their
// partitioning. If the resulting per-shard budget is below
// minBytesPerShard, a warning is logged; it is the caller's
// responsibility to ensure individual entries fit per-shard capacity.
// Use WithLogger to route the warning to a structured logger.
func NewByteCacheWithShards(capacity int64, shards int, defaultTTL time.Duration, opts ...Option) *ByteCache {
	if capacity <= 0 {
		capacity = 200 * 1024 * 1024 // 200 MB default
	}
	if shards <= 0 {
		shards = DefaultByteShards
	}
	return newByteCache(capacity, shards, defaultTTL, opts...)
}

func newByteCache(capacity int64, shards int, defaultTTL time.Duration, opts ...Option) *ByteCache {
	co := buildCtorOptions(opts)
	n := nextPow2(shards)
	perShard := (capacity + int64(n) - 1) / int64(n)
	if perShard < minBytesPerShard {
		co.logger.Warn("ByteCache per-shard budget is below floor; entries larger than per-shard budget will be rejected",
			log.Int64("per_shard_bytes", perShard),
			log.Int64("floor_bytes", minBytesPerShard),
			log.Int64("capacity", capacity),
			log.Int("shards", n),
		)
	}
	ss := make([]*byteShard, n)
	for i := range ss {
		ss[i] = newByteShard(perShard, defaultTTL)
	}
	bc := &ByteCache{
		shards:        ss,
		mask:          uint64(n - 1), //nolint:gosec // n is always a positive power-of-two, overflow impossible
		seed:          maphash.MakeSeed(),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		sweepInterval: computeSweepInterval(defaultTTL),
	}
	bc.startSweeper()
	return bc
}

func (c *ByteCache) shard(key string) *byteShard {
	return c.shards[maphash.Comparable(c.seed, key)&c.mask]
}

// Increment atomically increments the uint64 counter stored at key within a
// single shard lock, preventing TOCTOU races between concurrent callers.
// The counter value is stored as 8 bytes big-endian in entry.value.
//
// Semantics:
//   - count >= limit: no-op, returns current count (preserves existing TTL).
//   - count < limit: count += delta; if new count >= limit use blockTTL
//     (falls back to shard defaultTTL when blockTTL is 0); else keep the
//     existing TTL when the entry already exists, otherwise use windowTTL.
func (c *ByteCache) Increment(ctx context.Context, key string, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error) {
	return c.shard(key).increment(ctx, key, delta, limit, windowTTL, blockTTL)
}

func (s *byteShard) increment(_ context.Context, key string, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	var count uint64
	var existingTTL time.Time

	if entry, ok := s.items[key]; ok && (entry.expiresAt.IsZero() || now.Before(entry.expiresAt)) {
		if len(entry.value) == 8 {
			count = binary.BigEndian.Uint64(entry.value)
		}
		existingTTL = entry.expiresAt
	}

	if count >= limit {
		return count, nil
	}

	count += delta

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, count)

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
		s.used -= entry.size
		entry.value = buf
		entry.expiresAt = expiresAt
		entry.size = entrySize(key, buf)
		s.used += entry.size
		s.evictUntilFit()
	} else {
		newSize := entrySize(key, buf)
		entry := &byteEntry{key: key, value: buf, expiresAt: expiresAt, size: newSize}
		s.pushFront(entry)
		s.items[key] = entry
		s.used += newSize
		s.evictUntilFit()
	}

	return count, nil
}

// Get implements Cache.
func (c *ByteCache) Get(ctx context.Context, key string) ([]byte, error) {
	return c.shard(key).Get(ctx, key)
}

// Set implements Cache.
func (c *ByteCache) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return c.shard(key).Set(ctx, key, val, ttl)
}

// Del implements Cache.
func (c *ByteCache) Del(ctx context.Context, key string) error { return c.shard(key).Del(ctx, key) }

// Has implements Cache.
func (c *ByteCache) Has(ctx context.Context, key string) bool { return c.shard(key).Has(ctx, key) }

// Len implements Cache.
func (c *ByteCache) Len(ctx context.Context) int {
	n := 0
	for _, s := range c.shards {
		n += s.Len(ctx)
	}
	return n
}

// Used returns the total byte usage across all shards.
func (c *ByteCache) Used() int64 {
	var n int64
	for _, s := range c.shards {
		n += s.Used()
	}
	return n
}

// Capacity returns the total byte budget across all shards.
func (c *ByteCache) Capacity() int64 {
	var n int64
	for _, s := range c.shards {
		n += s.Capacity()
	}
	return n
}

// Shards returns the effective shard count. Always a power of two.
func (c *ByteCache) Shards() int { return len(c.shards) }

// Flush implements Cache.
func (c *ByteCache) Flush(ctx context.Context) error {
	for _, s := range c.shards {
		if err := s.Flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close stops the background sweep goroutine and removes all entries.
// Safe to call multiple times.
func (c *ByteCache) Close() error {
	c.closeOnce.Do(func() {
		close(c.stopCh)
		<-c.doneCh
	})
	return c.Flush(context.Background())
}
