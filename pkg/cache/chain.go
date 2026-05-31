package cache

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ChainCache implements a two-level cache: an L1 (typically in-memory) cache
// that falls back to an L2 (typically Redis) cache on miss.
// On L2 hit, the value is promoted into L1 with the given promoteTTL.
type ChainCache[K comparable, V any] struct {
	l1         Cache[K, V]
	l2         Cache[K, V]
	promoteTTL time.Duration
}

// NewChainCache constructs a two-level ChainCache. Values found in l2 are
// promoted to l1 with the given promoteTTL.
func NewChainCache[K comparable, V any](l1, l2 Cache[K, V], promoteTTL time.Duration) *ChainCache[K, V] {
	return &ChainCache[K, V]{
		l1:         l1,
		l2:         l2,
		promoteTTL: promoteTTL,
	}
}

// Get implements Cache. Tries L1 first; on miss falls back to L2 and promotes the result.
func (c *ChainCache[K, V]) Get(ctx context.Context, key K) (V, error) {
	// Try L1 first.
	val, err := c.l1.Get(ctx, key)
	if err == nil {
		return val, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return val, err
	}

	// L1 miss — try L2.
	val, err = c.l2.Get(ctx, key)
	if err != nil {
		return val, err
	}

	// Promote into L1.
	_ = c.l1.Set(ctx, key, val, c.promoteTTL)
	return val, nil
}

// Set implements Cache. Writes through to both L1 and L2.
func (c *ChainCache[K, V]) Set(ctx context.Context, key K, value V, ttl time.Duration) error {
	// Write-through: set both levels.
	if err := c.l1.Set(ctx, key, value, ttl); err != nil {
		return err
	}
	return c.l2.Set(ctx, key, value, ttl)
}

// Del implements Cache. Deletes from both L1 and L2.
func (c *ChainCache[K, V]) Del(ctx context.Context, key K) error {
	// Delete from both levels. Report L2 errors (the durable store).
	_ = c.l1.Del(ctx, key)
	return c.l2.Del(ctx, key)
}

// Has implements Cache.
func (c *ChainCache[K, V]) Has(ctx context.Context, key K) bool {
	return c.l1.Has(ctx, key) || c.l2.Has(ctx, key)
}

// Len implements Cache. Returns L2 count (source of truth).
func (c *ChainCache[K, V]) Len(ctx context.Context) int {
	// L2 is the source of truth for total count.
	return c.l2.Len(ctx)
}

// Flush implements Cache. Flushes both L1 and L2.
func (c *ChainCache[K, V]) Flush(ctx context.Context) error {
	_ = c.l1.Flush(ctx)
	return c.l2.Flush(ctx)
}

// Close implements Cache. Closes both L1 and L2.
func (c *ChainCache[K, V]) Close() error {
	err1 := c.l1.Close()
	err2 := c.l2.Close()
	return errors.Join(err1, err2)
}

// Increment atomically increments the uint64 counter in L2 (the durable layer)
// and then writes the resulting 8-byte big-endian value into L1 so that
// subsequent Get calls (e.g. from checkLimit) can read the counter without
// hitting L2.
//
// Atomicity is guaranteed by L2, which must implement the local
// atomicIncrementer interface. This ensures correctness in horizontal-scaling
// deployments where multiple instances share a single Redis backend.
//
// Returns an error if L2 does not implement atomicIncrementer.
func (c *ChainCache[K, V]) Increment(ctx context.Context, key K, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error) {
	// Local interface assertion avoids a cross-package import cycle between
	// pkg/cache and pkg/middleware where AtomicIncrementer is defined.
	type atomicIncrementer interface {
		Increment(ctx context.Context, key K, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error)
	}
	ai, ok := c.l2.(atomicIncrementer)
	if !ok {
		return 0, fmt.Errorf("cache: ChainCache L2 does not implement Increment")
	}
	count, err := ai.Increment(ctx, key, delta, limit, windowTTL, blockTTL)
	if err != nil {
		return 0, err
	}

	// Invalidate L1 so that subsequent Get calls fall through to L2 (the atomic
	// source of truth) and repopulate L1 with the correct count. Writing L1 here
	// would race with concurrent Increment callers because L2.Increment is the
	// only serialisation point — L1.Set calls from different goroutines have no
	// ordering guarantee, so the last writer may put a stale count into L1.
	// Deletion is idempotent under concurrency and the next Get will promote.
	_ = c.l1.Del(ctx, key)

	return count, nil
}
