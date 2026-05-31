package sessions_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/alicebob/miniredis/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

func testCookieOpts() *config.CookieStoreOptions {
	return &config.CookieStoreOptions{
		Name:     "_xw_session",
		Secret:   config.NewResolvedSecretRef([]byte("redissecret012345")),
		Path:     "/",
		Secure:   false,
		HTTPOnly: testutils.BoolPtr(true),
		SameSite: "lax",
	}
}

func newTestRedisStore(mr *miniredis.Miniredis) sessions.SessionStore {
	cookieOpts := testCookieOpts()
	cookieOpts.Refresh = 30 * time.Minute
	redisCfg := &config.RedisConfig{
		Addr:   mr.Addr(),
		Prefix: "test::",
		TTL:    1 * time.Hour,
	}
	store, err := sessions.NewRedisStore(cookieOpts, redisCfg, 30*time.Minute)
	Expect(err).To(BeNil())
	return store
}

func newTestSession() *ezapi.Session {
	s := &ezapi.Session{
		Profile: ezapi.Profile{
			Email: "test@example.com",
			User:  "testuser",
		},
	}
	s.CreatedAtNow()
	s.ExpiresIn(1 * time.Hour)
	return s
}

var _ = Describe("RedisStore", func() {
	var mr *miniredis.Miniredis

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		mr.Close()
	})

	Describe("Save and Load", func() {
		It("should round-trip a session via Redis", func() {
			store := newTestRedisStore(mr)
			session := newTestSession()

			// Save
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err := store.Save(rec, req, session)
			Expect(err).To(BeNil())

			// Extract cookie from response
			resp := rec.Result()
			cookies := resp.Cookies()
			Expect(cookies).To(HaveLen(1))
			Expect(cookies[0].Name).To(Equal("_xw_session"))

			// Load via a new request carrying the cookie
			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			loaded, err := store.Load(req2)
			Expect(err).To(BeNil())
			Expect(loaded.Email).To(Equal("test@example.com"))
			Expect(loaded.User).To(Equal("testuser"))
		})

		It("should return ErrNoCookie when no session cookie is present", func() {
			store := newTestRedisStore(mr)
			req := httptest.NewRequest("GET", "/", nil)
			_, err := store.Load(req)
			Expect(err).To(MatchError(http.ErrNoCookie))
		})

		It("should return ErrNoCookie when session is not found in Redis", func() {
			store := newTestRedisStore(mr)
			session := newTestSession()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err := store.Save(rec, req, session)
			Expect(err).To(BeNil())

			resp := rec.Result()
			cookies := resp.Cookies()

			// Flush Redis
			mr.FlushAll()

			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			_, err = store.Load(req2)
			Expect(err).To(MatchError(http.ErrNoCookie))
		})

		It("should reject a tampered session cookie", func() {
			store := newTestRedisStore(mr)
			session := newTestSession()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err := store.Save(rec, req, session)
			Expect(err).To(BeNil())

			resp := rec.Result()
			cookies := resp.Cookies()

			// Tamper with the cookie value
			cookies[0].Value = "tampered_value"

			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			_, err = store.Load(req2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("validation failed"))
		})
	})

	Describe("Clear", func() {
		It("should delete the session from Redis and emit a clearing cookie", func() {
			store := newTestRedisStore(mr)
			session := newTestSession()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err := store.Save(rec, req, session)
			Expect(err).To(BeNil())

			resp := rec.Result()
			cookies := resp.Cookies()

			// Verify key exists in Redis
			keys := mr.Keys()
			Expect(keys).To(HaveLen(1))

			// Clear
			rec2 := httptest.NewRecorder()
			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			err = store.Clear(rec2, req2)
			Expect(err).To(BeNil())

			// Redis key should be deleted
			keys = mr.Keys()
			Expect(keys).To(HaveLen(0))

			// Response should have a clearing cookie (MaxAge=-1)
			resp2 := rec2.Result()
			clearCookies := resp2.Cookies()
			Expect(clearCookies).To(HaveLen(1))
			Expect(clearCookies[0].MaxAge).To(Equal(-1))
		})

		It("should succeed when no session cookie is present", func() {
			store := newTestRedisStore(mr)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err := store.Clear(rec, req)
			Expect(err).To(BeNil())
		})
	})

	Describe("NeedsRefresh", func() {
		It("should return NeedsRefresh when session age exceeds refresh period", func() {
			store := newTestRedisStore(mr)
			session := newTestSession()

			// Simulate an old session
			session.CreatedAt = time.Now().Add(-1 * time.Hour).Unix()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err := store.Save(rec, req, session)
			Expect(err).To(BeNil())

			resp := rec.Result()
			cookies := resp.Cookies()

			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			loaded, err := store.Load(req2)
			Expect(err).To(MatchError(sessions.ErrNeedsRefresh))
			Expect(loaded).ToNot(BeNil())
		})
	})

	Describe("VerifyConnection", func() {
		It("should ping Redis successfully", func() {
			store := newTestRedisStore(mr)
			err := store.VerifyConnection(context.Background())
			Expect(err).To(BeNil())
		})

		It("should fail when Redis is unreachable", func() {
			store := newTestRedisStore(mr)
			mr.Close()
			err := store.VerifyConnection(context.Background())
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("TTL expiry", func() {
		It("should expire session after TTL", func() {
			cookieOpts := testCookieOpts()
			redisCfg := &config.RedisConfig{
				Addr:   mr.Addr(),
				Prefix: "test::",
				TTL:    100 * time.Millisecond,
			}
			store, err := sessions.NewRedisStore(cookieOpts, redisCfg, 30*time.Minute)
			Expect(err).To(BeNil())

			session := newTestSession()
			// Override ExpiresOn to force use of config TTL
			session.ExpiresOn = 0

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err = store.Save(rec, req, session)
			Expect(err).To(BeNil())

			resp := rec.Result()
			cookies := resp.Cookies()

			// Fast-forward past TTL
			mr.FastForward(200 * time.Millisecond)

			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			_, err = store.Load(req2)
			Expect(err).To(MatchError(http.ErrNoCookie))
		})
	})

	Describe("Encryption", func() {
		It("should round-trip when encryption is enabled", func() {
			cookieOpts := testCookieOpts()
			redisCfg := &config.RedisConfig{
				Addr:          mr.Addr(),
				Prefix:        "test::",
				TTL:           1 * time.Hour,
				EncryptSecret: config.NewResolvedSecretRef([]byte("abcdefghijklmnopqrstuvwxyz123456")),
			}
			store, err := sessions.NewRedisStore(cookieOpts, redisCfg, 30*time.Minute)
			Expect(err).To(BeNil())

			session := newTestSession()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err = store.Save(rec, req, session)
			Expect(err).To(BeNil())

			resp := rec.Result()
			cookies := resp.Cookies()

			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			loaded, err := store.Load(req2)
			Expect(err).To(BeNil())
			Expect(loaded.Email).To(Equal("test@example.com"))
		})

		It("should fail to load when encryption secret differs", func() {
			cookieOpts := testCookieOpts()
			redisCfg := &config.RedisConfig{
				Addr:          mr.Addr(),
				Prefix:        "test::",
				TTL:           1 * time.Hour,
				EncryptSecret: config.NewResolvedSecretRef([]byte("abcdefghijklmnopqrstuvwxyz123456")),
			}
			store, err := sessions.NewRedisStore(cookieOpts, redisCfg, 30*time.Minute)
			Expect(err).To(BeNil())

			session := newTestSession()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err = store.Save(rec, req, session)
			Expect(err).To(BeNil())

			// Create a second store with a different encryption secret
			redisCfg2 := &config.RedisConfig{
				Addr:          mr.Addr(),
				Prefix:        "test::",
				TTL:           1 * time.Hour,
				EncryptSecret: config.NewResolvedSecretRef([]byte("zyxwvutsrqponmlkjihgfedcba654321")),
			}
			store2, err := sessions.NewRedisStore(cookieOpts, redisCfg2, 30*time.Minute)
			Expect(err).To(BeNil())

			resp := rec.Result()
			cookies := resp.Cookies()
			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			_, err = store2.Load(req2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("decrypting session"))
		})
	})

	Describe("Value methods (inherited from store)", func() {
		It("should SaveValue, LoadValue, and DeleteValue via cookies", func() {
			store := newTestRedisStore(mr)

			opts := &sessions.ValueOptions{
				Name:   "test_value",
				Secret: []byte("redissecret012345"),
				MaxAge: 5 * time.Minute,
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			err := store.SaveValue(rec, req, []byte("hello"), opts)
			Expect(err).To(BeNil())

			// Load via cookie
			resp := rec.Result()
			cookies := resp.Cookies()
			Expect(cookies).To(HaveLen(1))
			Expect(cookies[0].Name).To(Equal("test_value"))

			req2 := httptest.NewRequest("GET", "/", nil)
			req2.AddCookie(cookies[0])
			val, err := store.LoadValue(req2, opts)
			Expect(err).To(BeNil())
			Expect(string(val)).To(Equal("hello"))

			// Delete
			rec2 := httptest.NewRecorder()
			req3 := httptest.NewRequest("GET", "/", nil)
			req3.AddCookie(cookies[0])
			err = store.DeleteValue(rec2, req3, opts)
			Expect(err).To(BeNil())

			resp2 := rec2.Result()
			clearCookies := resp2.Cookies()
			Expect(clearCookies).To(HaveLen(1))
			Expect(clearCookies[0].MaxAge).To(Equal(-1))
		})

		It("LoadValue should return nil when no cookie is present", func() {
			store := newTestRedisStore(mr)
			opts := &sessions.ValueOptions{Name: "missing_value"}
			req := httptest.NewRequest("GET", "/", nil)
			val, err := store.LoadValue(req, opts)
			Expect(err).To(BeNil())
			Expect(val).To(BeNil())
		})
	})
})

var _ = Describe("NewRedisStore errors", func() {
	It("should fail when Addr is empty", func() {
		_, err := sessions.NewRedisStore(
			&config.CookieStoreOptions{Name: "_xw", Secret: config.NewResolvedSecretRef([]byte("cookiesecret0123")), SameSite: "lax"},
			&config.RedisConfig{TTL: time.Hour},
			0,
		)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("redis addr is required"))
	})

	It("should fail when TTL is zero", func() {
		_, err := sessions.NewRedisStore(
			&config.CookieStoreOptions{Name: "_xw", Secret: config.NewResolvedSecretRef([]byte("cookiesecret0123")), SameSite: "lax"},
			&config.RedisConfig{Addr: "localhost:6379", TTL: 0},
			0,
		)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("TTL must be greater than 0"))
	})

	It("should fail when SameSite=None and not Secure", func() {
		_, err := sessions.NewRedisStore(
			&config.CookieStoreOptions{Name: "_xw", Secret: config.NewResolvedSecretRef([]byte("cookiesecret0123")), SameSite: "none", Secure: false},
			&config.RedisConfig{Addr: "localhost:6379", TTL: time.Hour},
			0,
		)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("SameSite=None"))
	})

	It("should fail when EncryptSecret is invalid (too short)", func() {
		_, err := sessions.NewRedisStore(
			&config.CookieStoreOptions{Name: "_xw", Secret: config.NewResolvedSecretRef([]byte("cookiesecret0123")), SameSite: "lax"},
			&config.RedisConfig{Addr: "localhost:6379", TTL: time.Hour, EncryptSecret: config.NewResolvedSecretRef([]byte("short"))},
			0,
		)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("encrypt cipher"))
	})
})

var _ = Describe("RedisStore.Close", func() {
	It("should close without error", func() {
		mr, err := miniredis.Run()
		Expect(err).ToNot(HaveOccurred())
		defer mr.Close()

		store, err := sessions.NewRedisStore(
			&config.CookieStoreOptions{Name: "_xw", Secret: config.NewResolvedSecretRef([]byte("cookiesecret0123")), SameSite: "lax"},
			&config.RedisConfig{Addr: mr.Addr(), TTL: time.Hour},
			0,
		)
		Expect(err).To(BeNil())
		Expect(store.Close()).To(Succeed())
	})
})
