//go:build e2e

package shared

import (
	"path/filepath"
	"time"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"
)

// EmptyConfig returns the absolute minimum options needed to start a server.
// No static users, no cache, no CSRF, no database — just server + JWT + session cookie.
// Every other config helper builds on top of this.
func EmptyConfig() ezcfg.Options {
	httpOnly := true
	return ezcfg.Options{
		Server: ezcfg.ServerConfig{
			Hostname:     "localhost",
			Port:         e2eutils.FreePort(),
			AuthPrefix:   "/ezauth",
			StaticPrefix: "/static",
		},
		Auth: ezcfg.AuthConfig{
			JWT: ezcfg.JWTConfig{
				SigningMethod: "hs512",
				SecretKey:     ezcfg.NewResolvedSecretRef([]byte("test-jwt-secret-key-for-32bytes!!")),
			},
			Session: ezcfg.Session{
				Cookie: ezcfg.CookieStoreOptions{
					Name:     "_ez_proxy",
					Secret:   ezcfg.NewResolvedSecretRef([]byte("test-secret-for-tests-32-bytes!!")),
					Path:     "/",
					HTTPOnly: &httpOnly,
				},
			},
		},
	}
}

// WithMemoryCache adds an in-memory cache config to opts.
func WithMemoryCache(opts ezcfg.Options, size string) ezcfg.Options {
	opts.Cache.Memory = ezcfg.MemoryCacheConfig{
		Size:   size,
		Shards: 16,
		TTL:    600 * time.Second,
	}
	return opts
}

// WithStaticUser adds a static user credential to opts.
func WithStaticUser(opts ezcfg.Options, user, password string) ezcfg.Options {
	opts.Auth.Static = append(opts.Auth.Static, ezcfg.PasswordConfig{
		User:     user,
		Password: password,
	})
	return opts
}

// WithDatabase adds a PostgreSQL database config to opts.
func WithDatabase(opts ezcfg.Options, db ezcfg.DatabaseConfig) ezcfg.Options {
	opts.Database = db
	return opts
}

// WithBootstrap adds a bootstrap secret file path under dir to opts.
func WithBootstrap(opts ezcfg.Options, dir string) ezcfg.Options {
	opts.Access.Bootstrap.SecretFile = filepath.Join(dir, "root_secret")
	return opts
}

// WithTLS configures TLS using the test certificate pair from test/config/tls/.
func WithTLS(opts ezcfg.Options) ezcfg.Options {
	tlsDir := filepath.Join(e2eutils.RepoRoot(), "test", "config", "tls")
	opts.Server.TLS = ezcfg.TLSConfig{
		Enabled:  true,
		CertPath: filepath.Join(tlsDir, "cert.crt"),
		KeyPath:  filepath.Join(tlsDir, "key.pem"),
	}
	opts.Auth.Session.Cookie.Secure = true
	return opts
}

// WithRBAC enables the RBAC engine and sets the system admin group.
func WithRBAC(opts ezcfg.Options) ezcfg.Options {
	opts.Access.RBAC.Enabled = true
	if opts.Access.SystemAdminGroup == "" {
		opts.Access.SystemAdminGroup = "system-admins"
	}
	return opts
}

// WithPortal enables the self-service portal.
func WithPortal(opts ezcfg.Options) ezcfg.Options {
	opts.Server.Portal.Enabled = true
	return opts
}

// WithProviderCache sets the provider LRU cache size and refresh interval.
func WithProviderCache(opts ezcfg.Options, size int) ezcfg.Options {
	opts.Auth.ProviderCache = ezcfg.CacheConfig{
		Size:            size,
		RefreshInterval: 2 * time.Second,
	}
	return opts
}

// WithCSRF enables the CSRF middleware with a test secret and the server URL
// as the sole trusted origin.
func WithCSRF(opts ezcfg.Options) ezcfg.Options {
	opts.Auth.Session.CSRF = ezcfg.CSRFConfig{
		Enabled:        true,
		TrustedOrigins: []string{"http://localhost", "https://localhost"},
		Secret:         ezcfg.NewResolvedSecretRef([]byte("test-csrf-tests-32-bytes-secure!")),
	}
	// Add a static user so the login page renders the CSRF token form.
	// Without a DB or static user, CustomLogin is false and the login
	// form (with csrf_token hidden input) is not included in the template.
	opts.Auth.Static = append(opts.Auth.Static, ezcfg.PasswordConfig{
		User:     "test-csrf-user",
		Password: "test-csrf-password",
	})
	return opts
}

// WithLoginRateLimitCustom enables login rate limiting with caller-supplied values.
// Use small values (e.g. limit=3, window=10s) in tests that trigger blocking.
func WithLoginRateLimitCustom(opts ezcfg.Options, ipLimit int, window, blockDuration time.Duration) ezcfg.Options {
	opts.Auth.LoginRateLimit = ezcfg.RateLimitConfig{
		Enabled:       true,
		IPLimit:       ipLimit,
		UsernameLimit: ipLimit,
		Window:        window,
		BlockDuration: blockDuration,
		CountMode:     "failures",
	}
	return opts
}

// WithDebugLog switches the log level to debug and format to console.
func WithDebugLog(opts ezcfg.Options) ezcfg.Options {
	opts.Log.Level = "debug"
	opts.Log.Format = "console"
	return opts
}

// WithRedisSession switches the session store to Redis and wires the address
// and an encrypt secret for the session cipher.
func WithRedisSession(opts ezcfg.Options, addr string) ezcfg.Options {
	opts.Auth.Session.StoreType = "redis"
	opts.Auth.Session.Redis = ezcfg.RedisConfig{
		Addr:          addr,
		EncryptSecret: ezcfg.NewResolvedSecretRef(make([]byte, 32)),
	}
	return opts
}

// BaseDBConfig returns a config with memory cache, PostgreSQL, and bootstrap
// already wired. Suites layer additional options (TLS, RBAC, Portal, etc.) on top.
func BaseDBConfig(db ezcfg.DatabaseConfig, dir string) ezcfg.Options {
	opts := EmptyConfig()
	opts = WithMemoryCache(opts, "10m")
	opts = WithDatabase(opts, db)
	opts = WithBootstrap(opts, dir)
	return opts
}
