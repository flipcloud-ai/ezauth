package config

import (
	"time"
)

// CacheConfig holds settings for an in-process LRU cache.
// Provider cache entries are permanent (no TTL); they are evicted only by
// explicit API mutations (update/delete) or on server restart.
type CacheConfig struct {
	Size            int           `mapstructure:"size" default:"30"`
	Shards          int           `mapstructure:"shards" default:"16"`
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`
}

// JWTConfig holds JWT signing and validation settings.
type JWTConfig struct {
	SecretKey      SecretRef     `mapstructure:"secret_key" json:"-"`
	TokenIssuer    string        `mapstructure:"token_issuer"`
	Audience       string        `mapstructure:"audience"`
	KeyPath        string        `mapstructure:"key_path" default:"/opt/ezauth"`
	ExpireDuration time.Duration `mapstructure:"cookie_expire" default:"24h"`
	SigningMethod  string        `mapstructure:"signingmethod" default:"hs256"`
}

// RateLimitConfig controls per-IP and optional per-username rate limiting.
// CountMode "failures" counts only >=400 responses (login brute-force);
// CountMode "all" counts every request (flood prevention for OAuth endpoints).
type RateLimitConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	IPLimit       int           `mapstructure:"ip_limit" default:"20"`
	UsernameLimit int           `mapstructure:"username_limit" default:"5"`
	Window        time.Duration `mapstructure:"window" default:"1m"`
	BlockDuration time.Duration `mapstructure:"block_duration" default:"15m"`
	CountMode     string        `mapstructure:"count_mode" default:"failures"`
}

// OpaqueTokenConfig holds settings for opaque (Personal Access Token) generation.
type OpaqueTokenConfig struct {
	Prefix string `mapstructure:"prefix" default:"ezauth_"`
}

// AuthConfig groups all authentication-related configuration under the auth block.
type AuthConfig struct {
	Proxy          AuthProxyConfig   `mapstructure:"proxy"`
	Provider       []*ProviderConfig `mapstructure:"providers"`
	Session        Session           `mapstructure:"session"`
	JWT            JWTConfig         `mapstructure:"jwt"`
	Static         []PasswordConfig  `mapstructure:"static"`
	ProviderCache  CacheConfig       `mapstructure:"provider_cache"`
	LoginRateLimit RateLimitConfig   `mapstructure:"login_rate_limit"`
	OAuthRateLimit RateLimitConfig   `mapstructure:"oauth_rate_limit"`
	OpaqueToken    OpaqueTokenConfig `mapstructure:"opaque_token"`
}

// PasswordConfig holds a static username/password credential entry.
type PasswordConfig struct {
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}
