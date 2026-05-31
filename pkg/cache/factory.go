package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
)

// NewFromConfig builds a Cache[string, []byte] from the application config.
//
// Behavior:
//   - If Redis addr is configured: creates a ChainCache (memory L1 → Redis L2).
//   - Otherwise: creates a standalone ByteCache.
//
// Options forwarded via opts apply to the L1 in-memory cache only. The
// Redis L2 and ChainCache layers have no warning paths today; if that
// changes, extend this factory to forward opts to them as well.
func NewFromConfig(cfg ezcfg.StoreCacheConfig, opts ...Option) (Cache[string, []byte], error) {
	var size int64
	if cfg.Memory.Size != "" {
		var err error
		size, err = ezcfg.ParseSize(cfg.Memory.Size)
		if err != nil {
			return nil, fmt.Errorf("cache: invalid memory size %q: %w", cfg.Memory.Size, err)
		}
	}

	mem := NewByteCacheWithShards(size, cfg.Memory.Shards, cfg.Memory.TTL, opts...)

	if cfg.Redis.Addr == "" {
		return mem, nil
	}

	redisOpts := &redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	if cfg.Redis.TLS {
		redisOpts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(redisOpts)
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		return nil, fmt.Errorf("cache: redis ping %s failed: %w", cfg.Redis.Addr, err)
	}
	rc := NewRedisCache(client, cfg.Redis.TTL, WithPrefix[string, []byte](cfg.Redis.Prefix))

	promoteTTL := cfg.Memory.TTL
	if promoteTTL == 0 {
		promoteTTL = 5 * time.Minute
	}

	return NewChainCache(mem, rc, promoteTTL), nil
}
