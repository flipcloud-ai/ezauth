package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vmihailenco/msgpack/v5"
)

// RedisCache is a generic cache backed by Redis, using msgpack for serialization.
type RedisCache[K ~string, V any] struct {
	client     redis.Cmdable
	defaultTTL time.Duration
	prefix     string
	closeOnce  sync.Once
}

// RedisCacheOption is a functional option for RedisCache construction.
type RedisCacheOption[K ~string, V any] func(*RedisCache[K, V])

// WithPrefix sets a key prefix for all cache entries, enabling namespace isolation.
func WithPrefix[K ~string, V any](prefix string) RedisCacheOption[K, V] {
	return func(c *RedisCache[K, V]) {
		c.prefix = prefix
	}
}

// NewRedisCache constructs a Redis-backed Cache. All keys are serialized with msgpack.
func NewRedisCache[K ~string, V any](client redis.Cmdable, defaultTTL time.Duration, opts ...RedisCacheOption[K, V]) *RedisCache[K, V] {
	c := &RedisCache[K, V]{
		client:     client,
		defaultTTL: defaultTTL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *RedisCache[K, V]) redisKey(key K) string {
	return c.prefix + string(key)
}

// Get implements Cache.
func (c *RedisCache[K, V]) Get(ctx context.Context, key K) (V, error) {
	var zero V
	data, err := c.client.Get(ctx, c.redisKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return zero, ErrNotFound
		}
		return zero, fmt.Errorf("redis get: %w", err)
	}
	var val V
	if err := msgpack.Unmarshal(data, &val); err != nil {
		return zero, fmt.Errorf("unmarshal cached value: %w", err)
	}
	return val, nil
}

// Set implements Cache.
func (c *RedisCache[K, V]) Set(ctx context.Context, key K, value V, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}
	data, err := msgpack.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal cache value: %w", err)
	}
	if err := c.client.Set(ctx, c.redisKey(key), data, ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}

// Del implements Cache.
func (c *RedisCache[K, V]) Del(ctx context.Context, key K) error {
	if err := c.client.Del(ctx, c.redisKey(key)).Err(); err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	return nil
}

// Has implements Cache.
func (c *RedisCache[K, V]) Has(ctx context.Context, key K) bool {
	n, err := c.client.Exists(ctx, c.redisKey(key)).Result()
	return err == nil && n > 0
}

// Len implements Cache.
func (c *RedisCache[K, V]) Len(ctx context.Context) int {
	if c.prefix == "" {
		n, err := c.client.DBSize(ctx).Result()
		if err != nil {
			return 0
		}
		return int(n)
	}

	var count int
	var cursor uint64
	match := c.prefix + "*"
	for {
		keys, next, err := c.client.Scan(ctx, cursor, match, 100).Result()
		if err != nil {
			return count
		}
		count += len(keys)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return count
}

// Flush implements Cache.
func (c *RedisCache[K, V]) Flush(ctx context.Context) error {
	if c.prefix == "" {
		if err := c.client.FlushDB(ctx).Err(); err != nil {
			return fmt.Errorf("redis flushdb: %w", err)
		}
		return nil
	}

	match := c.prefix + "*"
	var cursor uint64
	for {
		keys, next, err := c.client.Scan(ctx, cursor, match, 100).Result()
		if err != nil {
			return fmt.Errorf("redis scan: %w", err)
		}
		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("redis del keys: %w", err)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return nil
}

// Increment atomically increments the uint64 counter stored at key using a
// Lua script executed on the Redis server. The counter is stored as 8-byte
// big-endian so that the on-wire representation matches MemoryCache and
// ByteCache, and checkLimit can read it from any backend without branching.
//
// Semantics mirror MemoryCache.Increment:
//   - count >= limit: no-op, returns current count (preserves existing TTL).
//   - count < limit: count += delta; if new count >= limit use blockTTL;
//     if first write use windowTTL; otherwise KEEPTTL preserves the existing TTL.
func (c *RedisCache[K, V]) Increment(ctx context.Context, key K, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error) {
	// language=lua
	// ARGV[1]=limit ARGV[2]=delta ARGV[3]=blockTTL(ms) ARGV[4]=windowTTL(ms)
	// Uses EXISTS before the write so that "first write" detection is
	// correct for any delta value, not just delta==1.
	const script = `
local isNew = redis.call("EXISTS", KEYS[1]) == 0
local cur = redis.call("GET", KEYS[1])
local count = 0
if cur then
  -- New format: msgpack binary 8 (0xc4 0x08 + 8 bytes big-endian)
  if #cur >= 2 and string.byte(cur, 1) == 0xc4 and string.byte(cur, 2) == 0x08 then
    for i = 3, 10 do
      count = count * 256 + string.byte(cur, i)
    end
  else
    -- Old format: text integer (backwards-compatible)
    count = tonumber(cur) or 0
  end
end
if count >= tonumber(ARGV[1]) then return count end
count = count + tonumber(ARGV[2])
local packed = string.char(
  math.floor(count / 72057594037927936) % 256,
  math.floor(count / 281474976710656) % 256,
  math.floor(count / 1099511627776) % 256,
  math.floor(count / 4294967296) % 256,
  math.floor(count / 16777216) % 256,
  math.floor(count / 65536) % 256,
  math.floor(count / 256) % 256,
  count % 256
)
-- Store as msgpack binary 8 so RedisCache.Get can unmarshal back to []byte.
redis.call("SET", KEYS[1], string.char(0xc4, 0x08) .. packed, "KEEPTTL")
if count >= tonumber(ARGV[1]) then
  redis.call("PEXPIRE", KEYS[1], ARGV[3])
elseif isNew and tonumber(ARGV[4]) > 0 then
  redis.call("PEXPIRE", KEYS[1], ARGV[4])
end
return count
`
	if blockTTL == 0 {
		blockTTL = c.defaultTTL
	}
	blockMS := blockTTL.Milliseconds()
	windowMS := windowTTL.Milliseconds()

	res, err := c.client.Eval(ctx, script, []string{c.redisKey(key)},
		limit, delta, blockMS, windowMS,
	).Int64()
	if err != nil {
		return 0, fmt.Errorf("redis increment: %w", err)
	}
	if res < 0 {
		return 0, nil
	}
	return uint64(res), nil //nolint:gosec // res is a small rate-limit counter, always non-negative
}

// Close implements Cache. Safe to call multiple times.
func (c *RedisCache[K, V]) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if cl, ok := c.client.(io.Closer); ok {
			if closeErr := cl.Close(); closeErr != nil {
				err = fmt.Errorf("close redis client: %w", closeErr)
			}
		}
	})
	return err
}
