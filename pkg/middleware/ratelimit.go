package middleware

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
)

// RateLimit returns a mux.MiddlewareFunc that limits requests per client IP
// and optionally per username. When CountMode is "failures" only responses
// with status >= 400 are counted (suitable for login endpoints). When
// CountMode is "all" every completed request increments the counter
// (suitable for OAuth start/callback flooding prevention).
// When Enabled is false the middleware is a no-op pass-through.
// When the cache is unavailable the middleware fails open.
// trustHeaders controls whether X-Forwarded-For / X-Real-IP headers are used
// for client IP detection. Disable when not behind a trusted reverse proxy.
func RateLimit(keyPrefix string, cfg *ezcfg.RateLimitConfig, store ezcache.Cache[string, []byte], trustHeaders bool) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		failureMode := cfg.CountMode == "failures"
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			logger := ezlog.FromContext(ctx)

			ip := clientIP(r, trustHeaders)
			ipKey := fmt.Sprintf("%s:ip:%s", keyPrefix, ip)
			if blocked, err := checkLimit(ctx, store, ipKey, cfg.IPLimit); err != nil {
				logger.Warn("rate limit cache error for IP, failing open",
					ezlog.Str("ip", ip), ezlog.Err(err))
			} else if blocked {
				logger.Warn("rate limit blocked request",
					ezlog.Str("key", ipKey), ezlog.Str("ip", ip))
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(cfg.BlockDuration.Seconds())))
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}

			var username string
			if failureMode {
				if err := r.ParseForm(); err != nil {
					next.ServeHTTP(w, r)
					return
				}
				username = strings.ToLower(r.FormValue("username"))
				if username != "" && cfg.UsernameLimit > 0 {
					userKey := fmt.Sprintf("%s:user:%s", keyPrefix, username)
					if blocked, err := checkLimit(ctx, store, userKey, cfg.UsernameLimit); err != nil {
						logger.Warn("rate limit cache error for username, failing open",
							ezlog.Str("username", username), ezlog.Err(err))
					} else if blocked {
						logger.Warn("rate limit blocked request",
							ezlog.Str("key", userKey), ezlog.Str("username", username))
						// Still count towards the IP limit — the IP made a
						// malicious attempt even though the username was
						// already blocked.
						if err := incrementCounter(ctx, store, ipKey, cfg.IPLimit, cfg.Window, cfg.BlockDuration); err != nil {
							logger.Warn("rate limit counter error for IP", ezlog.Str("ip", ip), ezlog.Err(err))
						}
						w.Header().Set("Retry-After", fmt.Sprintf("%d", int(cfg.BlockDuration.Seconds())))
						http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
						return
					}
				}
			}

			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			if failureMode && rw.status < http.StatusBadRequest {
				return
			}
			if err := incrementCounter(ctx, store, ipKey, cfg.IPLimit, cfg.Window, cfg.BlockDuration); err != nil {
				logger.Warn("rate limit counter error for IP", ezlog.Str("ip", ip), ezlog.Err(err))
			}
			if failureMode && username != "" {
				userKey := fmt.Sprintf("%s:user:%s", keyPrefix, username)
				if err := incrementCounter(ctx, store, userKey, cfg.UsernameLimit, cfg.Window, cfg.BlockDuration); err != nil {
					logger.Warn("rate limit counter error for username", ezlog.Str("username", username), ezlog.Err(err))
				}
			}
		})
	}
}

// statusRecorder wraps http.ResponseWriter to capture the written status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// checkLimit reads the current failure count and returns true if it is at or
// above limit. Returns (false, nil) when the key does not exist yet.
func checkLimit(ctx context.Context, store ezcache.Cache[string, []byte], key string, limit int) (bool, error) {
	raw, err := store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ezcache.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("checkLimit get %q: %w", key, err)
	}
	if len(raw) != 8 {
		return false, nil
	}
	return binary.BigEndian.Uint64(raw) >= uint64(limit), nil //nolint:gosec // limit is always a small positive config value
}

// AtomicIncrementer is implemented by cache backends that can atomically
// read-increment-write a uint64 counter in a single critical section.
type AtomicIncrementer interface {
	Increment(ctx context.Context, key string, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error)
}

// incrementCounter increments the failure counter for key. On the first write
// it uses window as TTL so the counter expires naturally. Once the count
// reaches limit it switches to blockDuration. If the counter is already at or
// above limit the TTL is not reset, preventing indefinite lockout extension by
// repeated requests.
//
// When the store implements AtomicIncrementer the operation is delegated to a
// single atomic read-modify-write, eliminating the TOCTOU race present in the
// fallback Get+Set path.
func incrementCounter(ctx context.Context, store ezcache.Cache[string, []byte], key string, limit int, window, blockDuration time.Duration) error {
	if ai, ok := store.(AtomicIncrementer); ok {
		return incrementAtomic(ctx, ai, key, limit, window, blockDuration)
	}

	raw, err := store.Get(ctx, key)
	if err != nil && !errors.Is(err, ezcache.ErrNotFound) {
		return fmt.Errorf("incrementCounter get %q: %w", key, err)
	}

	var count uint64
	if err == nil && len(raw) == 8 {
		count = binary.BigEndian.Uint64(raw)
	}

	// Already at the limit — do not reset the TTL.
	if int(count) >= limit { //nolint:gosec // count is a small rate-limit counter, overflow impossible in practice
		return nil
	}

	count++
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, count)

	ttl := window
	if int(count) >= limit { //nolint:gosec // count is a small rate-limit counter, overflow impossible in practice
		ttl = blockDuration
	}
	if err := store.Set(ctx, key, buf, ttl); err != nil {
		return fmt.Errorf("incrementCounter set %q: %w", key, err)
	}
	return nil
}

// incrementAtomic delegates to ai.Increment, which guarantees atomicity.
func incrementAtomic(ctx context.Context, ai AtomicIncrementer, key string, limit int, window, blockDuration time.Duration) error {
	if _, err := ai.Increment(ctx, key, 1, uint64(limit), window, blockDuration); err != nil { //nolint:gosec // limit is a small positive config value
		return fmt.Errorf("incrementCounter atomic %q: %w", key, err)
	}
	return nil
}

// clientIP extracts the real client IP from the request. When trustHeaders is
// true, it prefers X-Real-IP and the first entry in X-Forwarded-For; otherwise
// it uses RemoteAddr directly, preventing IP spoofing via header forgery.
func clientIP(req *http.Request, trustHeaders bool) string {
	if trustHeaders {
		if ip := req.Header.Get("X-Real-IP"); ip != "" {
			return strings.TrimSpace(ip)
		}
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			return strings.TrimSpace(parts[0])
		}
	}
	addr := req.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
