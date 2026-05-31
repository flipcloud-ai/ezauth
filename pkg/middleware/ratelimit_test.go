package middleware

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
)

// failingAtomicIncrementer implements AtomicIncrementer but always returns an error.
type failingAtomicIncrementer struct{}

func (f *failingAtomicIncrementer) Increment(_ context.Context, _ string, _, _ uint64, _, _ time.Duration) (uint64, error) {
	return 0, errors.New("atomic increment failed")
}

func newTestCache() ezcache.Cache[string, []byte] {
	return ezcache.NewMemoryCache[string, []byte](100, time.Minute)
}

// newProductionLikeCache mirrors the no-Redis production path: a ByteCache
// with the same capacity and TTL that NewFromConfig builds when Redis is absent.
func newProductionLikeCache() ezcache.Cache[string, []byte] {
	return ezcache.NewByteCache(10*1024*1024, time.Minute)
}

// errorCache always returns an error from Get and Set to simulate a broken cache backend.
type errorCache struct{}

func (e *errorCache) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, ezcache.ErrClosed
}
func (e *errorCache) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return ezcache.ErrClosed
}
func (e *errorCache) Del(_ context.Context, _ string) error { return nil }
func (e *errorCache) Has(_ context.Context, _ string) bool  { return false }
func (e *errorCache) Len(_ context.Context) int             { return 0 }
func (e *errorCache) Flush(_ context.Context) error         { return nil }
func (e *errorCache) Close() error                          { return nil }

func failureCfg(ipLimit, userLimit int) *ezcfg.RateLimitConfig {
	return &ezcfg.RateLimitConfig{
		Enabled:       true,
		IPLimit:       ipLimit,
		UsernameLimit: userLimit,
		Window:        time.Minute,
		BlockDuration: 15 * time.Minute,
		CountMode:     "failures",
	}
}

func allRequestsCfg() *ezcfg.RateLimitConfig {
	return &ezcfg.RateLimitConfig{
		Enabled:       true,
		IPLimit:       3,
		Window:        time.Minute,
		BlockDuration: 5 * time.Minute,
		CountMode:     "all",
	}
}

func postLogin(handler http.Handler, ip, username string) *httptest.ResponseRecorder {
	body := strings.NewReader("username=" + username + "&password=secret")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func makeHandler(downstreamStatus int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(downstreamStatus)
	})
}

func getLogin(handler http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

var _ = Describe("RateLimit middleware", func() {
	When("rate limiting is disabled", func() {
		It("should pass all requests through", func() {
			cfg := &ezcfg.RateLimitConfig{Enabled: false}
			handler := RateLimit("rl:login", cfg, newTestCache(), false)(makeHandler(http.StatusOK))
			for i := 0; i < 100; i++ {
				rec := postLogin(handler, "10.0.0.1", "alice")
				Expect(rec.Code).To(Equal(http.StatusOK))
			}
		})
	})

	When("count mode failures", func() {
		Context("IP-based limiting", func() {
			It("should allow requests under the IP limit", func() {
				store := newTestCache()
				cfg := failureCfg(3, 2)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))
				for i := 0; i < cfg.IPLimit-1; i++ {
					rec := postLogin(handler, "10.0.0.2", "")
					Expect(rec.Code).To(Equal(http.StatusUnauthorized))
				}
			})

			It("should block requests over the IP limit with 429", func() {
				store := newTestCache()
				cfg := failureCfg(3, 2)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))
				for i := 0; i < cfg.IPLimit; i++ {
					postLogin(handler, "10.0.0.3", "")
				}
				rec := postLogin(handler, "10.0.0.3", "")
				Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
				Expect(rec.Header().Get("Retry-After")).NotTo(BeEmpty())
			})

			It("should not count successful logins against the limit", func() {
				store := newTestCache()
				cfg := failureCfg(3, 2)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusOK))
				for i := 0; i < cfg.IPLimit+5; i++ {
					rec := postLogin(handler, "10.0.0.4", "alice")
					Expect(rec.Code).To(Equal(http.StatusOK))
				}
			})

			It("should count 4xx non-401 responses against the limit", func() {
				store := newTestCache()
				cfg := failureCfg(3, 0)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusForbidden))
				for i := 0; i < cfg.IPLimit; i++ {
					postLogin(handler, "10.0.0.7", "")
				}
				rec := postLogin(handler, "10.0.0.7", "")
				Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
			})
		})

		Context("username-based limiting", func() {
			It("should allow requests under the username limit", func() {
				store := newTestCache()
				cfg := failureCfg(10, 2)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))
				for i := 0; i < cfg.UsernameLimit-1; i++ {
					rec := postLogin(handler, "10.0.0.5", "bob")
					Expect(rec.Code).To(Equal(http.StatusUnauthorized))
				}
			})

			It("should block requests over the username limit with 429 and Retry-After", func() {
				store := newTestCache()
				cfg := failureCfg(100, 2)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))
				for i := 0; i < cfg.UsernameLimit; i++ {
					postLogin(handler, fmt.Sprintf("10.1.0.%d", i+1), "carol")
				}
				rec := postLogin(handler, "10.1.0.99", "carol")
				Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
				Expect(rec.Header().Get("Retry-After")).NotTo(BeEmpty())
			})

			It("should treat usernames case-insensitively", func() {
				store := newTestCache()
				cfg := failureCfg(100, 2)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))
				postLogin(handler, "10.2.0.1", "Dave")
				postLogin(handler, "10.2.0.2", "DAVE")
				rec := postLogin(handler, "10.2.0.3", "dave")
				Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
			})

			It("should still increment the IP counter when the username is blocked", func() {
				store := newTestCache()
				cfg := failureCfg(3, 2)
				handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))

				// Exhaust username "frank" from two different IPs.
				postLogin(handler, "10.5.0.1", "frank")
				postLogin(handler, "10.5.0.2", "frank")

				// A new IP tries "frank" — blocked by username limit.
				rec := postLogin(handler, "10.5.0.3", "frank")
				Expect(rec.Code).To(Equal(http.StatusTooManyRequests))

				// The IP counter must have been incremented even though
				// the request was blocked by the username check.
				// Two more failures from the same IP (with different
				// usernames) should push the IP to its limit.
				postLogin(handler, "10.5.0.3", "george")
				postLogin(handler, "10.5.0.3", "harry")

				// IP 10.5.0.3 should now be at limit 3 (1 from the
				// blocked username attempt + 2 above).
				rec = postLogin(handler, "10.5.0.3", "iris")
				Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
			})
		})

		Context("cache failure", func() {
			It("should fail open when cache returns error", func() {
				handler := RateLimit("rl:login", failureCfg(3, 2), &errorCache{}, false)(makeHandler(http.StatusOK))
				for i := 0; i < 10; i++ {
					rec := postLogin(handler, "10.3.0.1", "eve")
					Expect(rec.Code).To(Equal(http.StatusOK))
				}
			})
		})
	})

	When("count mode all", func() {
		It("should pass requests under the limit", func() {
			store := newTestCache()
			cfg := allRequestsCfg()
			handler := RateLimit("rl:oauth", cfg, store, false)(makeHandler(http.StatusOK))
			for i := 0; i < cfg.IPLimit; i++ {
				rec := getLogin(handler)
				Expect(rec.Code).To(Equal(http.StatusOK))
			}
		})

		It("should block requests over the limit with 429 and Retry-After", func() {
			store := newTestCache()
			cfg := allRequestsCfg()
			handler := RateLimit("rl:oauth", cfg, store, false)(makeHandler(http.StatusOK))
			for i := 0; i < cfg.IPLimit; i++ {
				getLogin(handler)
			}
			rec := getLogin(handler)
			Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
			Expect(rec.Header().Get("Retry-After")).NotTo(BeEmpty())
		})

		It("should count all requests regardless of status", func() {
			store := newTestCache()
			cfg := allRequestsCfg()
			handler := RateLimit("rl:oauth", cfg, store, false)(makeHandler(http.StatusInternalServerError))
			for i := 0; i < cfg.IPLimit; i++ {
				getLogin(handler)
			}
			rec := getLogin(handler)
			Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
		})

		It("should be a no-op when disabled", func() {
			cfg := &ezcfg.RateLimitConfig{Enabled: false, CountMode: "all"}
			handler := RateLimit("rl:oauth", cfg, newTestCache(), false)(makeHandler(http.StatusOK))
			for i := 0; i < 100; i++ {
				rec := getLogin(handler)
				Expect(rec.Code).To(Equal(http.StatusOK))
			}
		})

		It("should be a no-op when cfg is nil", func() {
			handler := RateLimit("", nil, newTestCache(), false)(makeHandler(http.StatusOK))
			for i := 0; i < 100; i++ {
				rec := getLogin(handler)
				Expect(rec.Code).To(Equal(http.StatusOK))
			}
		})

		It("should fail open when cache returns error", func() {
			handler := RateLimit("rl:oauth", allRequestsCfg(), &errorCache{}, false)(makeHandler(http.StatusOK))
			for i := 0; i < 10; i++ {
				rec := getLogin(handler)
				Expect(rec.Code).To(Equal(http.StatusOK))
			}
		})
	})

	It("should isolate counters by KeyPrefix", func() {
		store := newTestCache()
		loginCfg := failureCfg(3, 0)
		oauthCfg := allRequestsCfg()

		loginHandler := RateLimit("rl:login", loginCfg, store, false)(makeHandler(http.StatusUnauthorized))
		oauthHandler := RateLimit("rl:oauth", oauthCfg, store, false)(makeHandler(http.StatusOK))

		// Exhaust login IP limit.
		for i := 0; i < loginCfg.IPLimit; i++ {
			postLogin(loginHandler, "10.9.9.9", "")
		}
		rec := postLogin(loginHandler, "10.9.9.9", "")
		Expect(rec.Code).To(Equal(http.StatusTooManyRequests))

		// Same IP via oauth handler should be unaffected — different KeyPrefix.
		for i := 0; i < oauthCfg.IPLimit-1; i++ {
			rec := getLogin(oauthHandler)
			Expect(rec.Code).To(Equal(http.StatusOK))
		}
	})

	Describe("production no-Redis path (ByteCache)", func() {
		It("should be race-free under concurrent increments with ByteCache", func() {
			// Mirrors the MemoryCache race test but uses ByteCache, which is the
			// actual store wired by NewFromConfig when Redis is absent.
			const goroutines = 50
			const limit = goroutines + 1

			store := ezcache.NewByteCache(10*1024*1024, time.Minute)
			defer func() { _ = store.Close() }()

			ctx := context.Background()
			key := "rl:race:bytecache:5.6.7.8"

			var wg sync.WaitGroup
			wg.Add(goroutines)
			for range goroutines {
				go func() {
					defer wg.Done()
					Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
				}()
			}
			wg.Wait()

			raw, err := store.Get(ctx, key)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(raw)).To(Equal(8))
			count := binary.BigEndian.Uint64(raw)
			Expect(count).To(BeEquivalentTo(goroutines))
		})

		It("should correctly block after limit with ByteCache", func() {
			store := ezcache.NewByteCache(10*1024*1024, time.Minute)
			defer func() { _ = store.Close() }()

			ctx := context.Background()
			key := "rl:block:bytecache:6.7.8.9"
			const limit = 3
			for range limit {
				Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			// Counter is at limit; checkLimit must report blocked.
			blocked, err := checkLimit(ctx, store, key, limit)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeTrue())
		})

		It("should block via full RateLimit middleware with ByteCache", func() {
			cfg := failureCfg(3, 0)
			store := newProductionLikeCache()
			defer func() { _ = store.Close() }()
			handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))

			for i := 0; i < cfg.IPLimit; i++ {
				postLogin(handler, "10.20.0.1", "")
			}
			rec := postLogin(handler, "10.20.0.1", "")
			Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
			Expect(rec.Header().Get("Retry-After")).NotTo(BeEmpty())
		})
	})

	Describe("production Redis path (ChainCache ByteCache L1 + RedisCache L2)", func() {
		var mr *miniredis.Miniredis

		BeforeEach(func() {
			var err error
			mr, err = miniredis.Run()
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			mr.Close()
		})

		newChainStore := func() ezcache.Cache[string, []byte] {
			l1 := ezcache.NewByteCache(10*1024*1024, time.Minute)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			l2 := ezcache.NewRedisCache[string, []byte](client, time.Minute)
			return ezcache.NewChainCache(l1, l2, time.Minute)
		}

		It("should be race-free under concurrent increments with ChainCache (ByteCache+Redis)", func() {
			const goroutines = 50
			const limit = goroutines + 1

			store := newChainStore()
			defer func() { _ = store.Close() }()

			ctx := context.Background()
			key := "rl:race:chain:5.6.7.8"

			var wg sync.WaitGroup
			wg.Add(goroutines)
			for range goroutines {
				go func() {
					defer wg.Done()
					Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
				}()
			}
			wg.Wait()

			raw, err := store.Get(ctx, key)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(raw)).To(Equal(8))
			count := binary.BigEndian.Uint64(raw)
			Expect(count).To(BeEquivalentTo(goroutines))
		})

		It("should correctly block after limit with ChainCache", func() {
			store := newChainStore()
			defer func() { _ = store.Close() }()

			ctx := context.Background()
			key := "rl:block:chain:6.7.8.9"
			const limit = 3
			for range limit {
				Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			blocked, err := checkLimit(ctx, store, key, limit)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeTrue())
		})

		It("should block via full RateLimit middleware with ChainCache", func() {
			cfg := failureCfg(3, 0)
			store := newChainStore()
			defer func() { _ = store.Close() }()
			handler := RateLimit("rl:login", cfg, store, false)(makeHandler(http.StatusUnauthorized))

			for i := 0; i < cfg.IPLimit; i++ {
				postLogin(handler, "10.21.0.1", "")
			}
			rec := postLogin(handler, "10.21.0.1", "")
			Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
			Expect(rec.Header().Get("Retry-After")).NotTo(BeEmpty())
		})
	})

	Describe("clientIP", func() {
		It("should prefer X-Real-IP", func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Real-IP", "1.2.3.4")
			req.Header.Set("X-Forwarded-For", "5.6.7.8")
			req.RemoteAddr = "9.10.11.12:1234"
			Expect(clientIP(req, true)).To(Equal("1.2.3.4"))
		})

		It("should fall back to first X-Forwarded-For entry", func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Forwarded-For", "5.6.7.8, 9.10.11.12")
			req.RemoteAddr = "13.14.15.16:1234"
			Expect(clientIP(req, true)).To(Equal("5.6.7.8"))
		})

		It("should fall back to RemoteAddr", func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "13.14.15.16:1234"
			Expect(clientIP(req, true)).To(Equal("13.14.15.16"))
		})
	})

	Describe("checkLimit", func() {
		It("should return false when key does not exist", func() {
			store := newTestCache()
			blocked, err := checkLimit(context.Background(), store, "rl:login:ip:1.2.3.4", 5)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeFalse())
		})

		It("should return true when count is at or above limit", func() {
			store := newTestCache()
			ctx := context.Background()
			key := "rl:login:ip:2.3.4.5"
			limit := 3
			for i := 0; i < limit; i++ {
				Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			blocked, err := checkLimit(ctx, store, key, limit)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeTrue())
		})
	})

	Describe("checkLimit cache error", func() {
		It("should return error when cache returns non-ErrNotFound error", func() {
			blocked, err := checkLimit(context.Background(), &errorCache{}, "some-key", 5)
			Expect(err).To(HaveOccurred())
			Expect(blocked).To(BeFalse())
		})
	})

	Describe("incrementCounter non-atomic fallback path", func() {
		// nonAtomicCache wraps errorCache but does NOT implement AtomicIncrementer,
		// so incrementCounter falls through to the Get+Set path.
		type nonAtomicCache struct {
			ezcache.Cache[string, []byte]
		}

		It("should use Get+Set fallback when cache does not implement AtomicIncrementer", func() {
			// Use MemoryCache which does implement AtomicIncrementer, but wrap it
			// to strip the interface — forcing the non-atomic path.
			inner := ezcache.NewMemoryCache[string, []byte](100, time.Minute)
			defer func() { _ = inner.Close() }()
			wrapped := &nonAtomicCache{inner}

			ctx := context.Background()
			key := "rl:fallback:ip:1.2.3.4"
			Expect(incrementCounter(ctx, wrapped, key, 5, time.Minute, 15*time.Minute)).To(Succeed())

			raw, err := wrapped.Get(ctx, key)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(raw)).To(Equal(8))
		})

		It("should return error when Get fails with non-ErrNotFound on fallback path", func() {
			wrapped := &nonAtomicCache{&errorCache{}}
			err := incrementCounter(context.Background(), wrapped, "key", 5, time.Minute, 15*time.Minute)
			Expect(err).To(HaveOccurred())
		})

		It("should switch to blockDuration TTL when count reaches limit", func() {
			inner := ezcache.NewMemoryCache[string, []byte](100, time.Minute)
			defer func() { _ = inner.Close() }()
			wrapped := &nonAtomicCache{inner}

			ctx := context.Background()
			key := "rl:fallback:block:2.3.4.5"
			const limit = 2
			for i := 0; i < limit; i++ {
				Expect(incrementCounter(ctx, wrapped, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			blocked, err := checkLimit(ctx, wrapped, key, limit)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeTrue())
		})

		It("should be a no-op when count already at limit (fallback path)", func() {
			inner := ezcache.NewMemoryCache[string, []byte](100, time.Minute)
			defer func() { _ = inner.Close() }()
			wrapped := &nonAtomicCache{inner}

			ctx := context.Background()
			key := "rl:fallback:noop:3.4.5.6"
			const limit = 2
			for i := 0; i < limit; i++ {
				Expect(incrementCounter(ctx, wrapped, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			// Already at limit — should be no-op
			Expect(incrementCounter(ctx, wrapped, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			blocked, err := checkLimit(ctx, wrapped, key, limit)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeTrue())
		})
	})

	Describe("incrementAtomic error path", func() {
		It("should return error when AtomicIncrementer.Increment fails", func() {
			// errorCache does not implement AtomicIncrementer; use a dedicated stub.
			type failAtomic struct {
				ezcache.Cache[string, []byte]
			}
			_ = failAtomic{}

			// Directly call incrementAtomic with a stub that returns an error.
			type atomicStub struct{}
			_ = atomicStub{}

			// Use a custom AtomicIncrementer that always errors.
			err := incrementAtomic(context.Background(), &failingAtomicIncrementer{}, "key", 5, time.Minute, 15*time.Minute)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("incrementCounter", func() {
		It("should not reset TTL once limit is reached", func() {
			store := newTestCache()
			ctx := context.Background()
			key := "rl:login:ip:3.4.5.6"
			limit := 2
			for i := 0; i < limit; i++ {
				Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			// Calling again should be a no-op (counter stays at limit, TTL not reset).
			Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			blocked, err := checkLimit(ctx, store, key, limit)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeTrue())
		})

		It("should be race-free under concurrent increments with MemoryCache", func() {
			// N goroutines all call incrementCounter simultaneously for the same key.
			// With the atomic path, the final counter must equal exactly N (no lost updates).
			const goroutines = 50
			const limit = goroutines + 1 // keep limit above N so no call is a no-op

			store := ezcache.NewMemoryCache[string, []byte](100, time.Minute)
			defer func() { _ = store.Close() }()

			ctx := context.Background()
			key := "rl:race:ip:5.6.7.8"

			var wg sync.WaitGroup
			wg.Add(goroutines)
			for range goroutines {
				go func() {
					defer wg.Done()
					Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
				}()
			}
			wg.Wait()

			raw, err := store.Get(ctx, key)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(raw)).To(Equal(8))
			count := binary.BigEndian.Uint64(raw)
			Expect(count).To(BeEquivalentTo(goroutines))
		})

		It("should not reset TTL once limit is reached via atomic path", func() {
			// Verifies the "already at limit" no-op semantic through the AtomicIncrementer path.
			store := ezcache.NewMemoryCache[string, []byte](100, time.Minute)
			defer func() { _ = store.Close() }()

			ctx := context.Background()
			key := "rl:atomic:ip:6.7.8.9"
			limit := 3
			for range limit {
				Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			// Counter is now at limit; further calls must be no-ops.
			for range 5 {
				Expect(incrementCounter(ctx, store, key, limit, time.Minute, 15*time.Minute)).To(Succeed())
			}
			blocked, err := checkLimit(ctx, store, key, limit)
			Expect(err).ToNot(HaveOccurred())
			Expect(blocked).To(BeTrue())
		})
	})
})
