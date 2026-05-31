package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MemoryCacheConfig configures the in-process memory cache (size string + TTL).
type MemoryCacheConfig struct {
	Size   string        `mapstructure:"size" default:"200m"`
	TTL    time.Duration `mapstructure:"ttl" default:"5m"`
	Shards int           `mapstructure:"shards" default:"16"`
}

// RedisConfig holds connection and cache settings for Redis-backed stores.
type RedisConfig struct {
	Addr          string        `mapstructure:"addr" default:""`
	Password      string        `mapstructure:"password"`
	DB            int           `mapstructure:"db" default:"0"`
	TTL           time.Duration `mapstructure:"ttl" default:"10m"`
	Prefix        string        `mapstructure:"prefix" default:"ezauth::"`
	EncryptSecret SecretRef     `mapstructure:"encrypt_secret" json:"-"`
	TLS           bool          `mapstructure:"tls" default:"false"`
}

// StoreCacheConfig groups the memory and Redis cache configurations used by the session store.
type StoreCacheConfig struct {
	Memory MemoryCacheConfig `mapstructure:"memory"`
	Redis  RedisConfig       `mapstructure:"redis"`
}

// ParseSize parses a human-readable size string into bytes (decimal units).
// Supported suffixes (case-insensitive): k (KB, 1000), m (MB, 1000^2), g (GB, 1000^3).
// A plain integer is treated as raw bytes.
func ParseSize(s string) (int64, error) {
	raw := s
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	s = strings.ToLower(s)
	multiplier := int64(1)

	switch {
	case strings.HasSuffix(s, "g"):
		multiplier = 1000 * 1000 * 1000
		s = strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "m"):
		multiplier = 1000 * 1000
		s = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "k"):
		multiplier = 1000
		s = strings.TrimSuffix(s, "k")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", raw, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size %q", raw)
	}

	return n * multiplier, nil
}
