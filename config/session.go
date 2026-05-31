package config

import (
	"time"
)

// CookieSession is the store type identifier for cookie-backed sessions.
var CookieSession = "cookie"

// RedisSession is the store type identifier for Redis-backed sessions.
var RedisSession = "redis"

// CSRFConfig contains the user-tunable settings for the CSRF middleware.
// Cookie scope attributes (Path, Domains) and transport attributes (Secure,
// HTTPOnly, SameSite) are intentionally omitted — those are inherited from
// the session cookie config so the CSRF cookie stays consistent with the
// session it protects. This also keeps the config meaningful for non-cookie
// session stores (e.g. Redis), where Name becomes the key, MaxAge becomes the
// TTL, and Secret is an optional HMAC over the stored payload.
type CSRFConfig struct {
	Enabled         bool          `mapstructure:"enabled" default:"false" json:"enabled"`
	TrustedOrigins  []string      `mapstructure:"trusted_origins" json:"trusted_origins"`
	ExcludePrefixes []string      `mapstructure:"exclude_prefixes" json:"exclude_prefixes"`
	Name            string        `mapstructure:"cookie_name" default:"_xw_csrf" json:"name"`
	HeaderName      string        `mapstructure:"request_header" default:"X-CSRF-Token" json:"header_name"`
	Secret          SecretRef     `mapstructure:"cookie_secret" json:"-"`
	Expire          time.Duration `mapstructure:"cookie_expire" json:"expire"`
	MaxAge          time.Duration `mapstructure:"cookie_max_age" default:"12h" json:"max_age"`
}

// Session holds session store selection and per-store configuration.
type Session struct {
	StoreType     string             `mapstructure:"store_type"`
	Cookie        CookieStoreOptions `mapstructure:"cookie"`
	Redis         RedisConfig        `mapstructure:"redis"`
	CSRF          CSRFConfig         `mapstructure:"csrf"`
	RefreshPeriod time.Duration      `mapstructure:"refresh_period" default:"15m"`
}

// CookieStoreOptions configures the cookie-based session store.
type CookieStoreOptions struct {
	Minimal  bool          `mapstructure:"session_cookie_minimal" default:"false"`
	Name     string        `mapstructure:"cookie_name" default:"_ez_proxy" json:"name"`
	Secret   SecretRef     `mapstructure:"cookie_secret" json:"-"`
	Domains  []string      `mapstructure:"cookie_domains" json:"domains"`
	Path     string        `mapstructure:"cookie_path" default:"/" json:"path"`
	Expire   time.Duration `mapstructure:"cookie_expire" default:"24h" json:"expire"`
	Refresh  time.Duration `mapstructure:"cookie_refresh" default:"0s" json:"refresh"`
	Secure   bool          `mapstructure:"cookie_secure" default:"false" json:"secure"`
	MaxAge   time.Duration `mapstructure:"cookie_max_age" default:"0s" json:"max_age"`
	HTTPOnly *bool         `mapstructure:"cookie_httponly" default:"true" json:"http_only"`
	SameSite string        `mapstructure:"cookie_samesite" default:"lax" json:"same_site"`
}
