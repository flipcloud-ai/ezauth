package cache

import (
	"context"
	"errors"
	"time"

	"github.com/flipcloud-ai/ezauth/log"
)

// Sentinel errors returned by cache operations.
var (
	// ErrNotFound is returned by Get when the key does not exist or has expired.
	ErrNotFound = errors.New("cache: key not found")
	// ErrClosed is returned when the cache has been closed.
	ErrClosed = errors.New("cache: store closed")
	// ErrKeyTooLong is returned when the key exceeds the implementation's limit.
	ErrKeyTooLong = errors.New("cache: key too long")
	// ErrValueTooLarge is returned when the value exceeds the per-entry budget.
	ErrValueTooLarge = errors.New("cache: value too large for cache")
)

// ctorOptions collects the optional knobs accepted by cache constructors.
// Kept small and cache-agnostic — only the logger lives here today.
type ctorOptions struct {
	logger log.Logger
}

// Option configures a cache at construction time. Pass via the variadic tail
// of NewByteCache/NewMemoryCache/NewFromConfig etc.
type Option func(*ctorOptions)

// WithLogger routes cache-internal warnings (shard-budget floor, collapse)
// through the given zap logger. When unset, constructors use a no-op — the
// package produces no output on its own.
func WithLogger(l log.Logger) Option {
	return func(o *ctorOptions) { o.logger = l }
}

func buildCtorOptions(opts []Option) ctorOptions {
	co := ctorOptions{logger: log.NewNop()}
	for _, o := range opts {
		if o != nil {
			o(&co)
		}
	}
	if co.logger == nil {
		co.logger = log.NewNop()
	}
	return co
}

// Cache is the unified, generic, thread-safe cache interface.
// Implementations must be safe for concurrent use.
type Cache[K comparable, V any] interface {
	// Get returns the value for the given key.
	// Returns ErrNotFound if the key does not exist or has expired.
	Get(ctx context.Context, key K) (V, error)

	// Set stores a value with an optional per-key TTL.
	// If ttl is 0, the store's default TTL is used.
	Set(ctx context.Context, key K, value V, ttl time.Duration) error

	// Del removes the key from the cache.
	// Returns silently if the key does not exist.
	Del(ctx context.Context, key K) error

	// Has reports whether the key exists and has not expired.
	Has(ctx context.Context, key K) bool

	// Len returns the number of items currently in the cache.
	Len(ctx context.Context) int

	// Flush removes all entries from the cache.
	Flush(ctx context.Context) error

	// Close releases any resources held by the cache store.
	Close() error
}

// Ranger is an optional interface implemented by cache backends that support
// iterating over live entries. Range calls fn for each non-expired entry in
// an unspecified order; returning false from fn stops the iteration early.
// Implementations snapshot entries under the internal lock and release it
// before invoking fn, so fn may safely call any cache method on the same
// instance without risking deadlock or lock contention.
// The snapshot reflects the cache state at the moment Range is called;
// writes that arrive during iteration may or may not be visible.
type Ranger[K comparable, V any] interface {
	Range(ctx context.Context, fn func(key K, value V) bool)
}

// nextPow2 rounds v up to the nearest power of two.
func nextPow2(v int) int {
	if v <= 1 {
		return 1
	}
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	return v + 1
}
