package sessions

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/agiledragon/gomonkey/v2"

	"github.com/flipcloud-ai/ezauth/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

var _ = Describe("Sessions Module Test Suite", func() {
	When("session store interface test", func() {
		now := time.Now()
		maxAge := 12 * time.Hour
		Describe("cookie load error test", func() {
			var p = gomonkey.ApplyFunc(time.Now, func() time.Time {
				return now
			})
			defer p.Reset()
			opt := &config.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
				Domains:  []string{"www.userequesthost.com", "www.test123.com"},
				Path:     "/",
				Expire:   1 * time.Hour,
				Refresh:  1 * time.Hour,
				MaxAge:   maxAge,
				Secure:   true,
				HTTPOnly: testutils.BoolPtr(true),
				SameSite: "strict",
			}
			It("empty session config", func(ctx SpecContext) {
				s, err := NewSessionStore(nil)
				Expect(err).NotTo(BeNil())
				Expect(errors.Is(err, ErrEmptyConfig)).To(BeTrue())
				Expect(s).To(BeNil())
			})
			It("create cookie session", func(ctx SpecContext) {
				s, err := NewSessionStore(&config.Session{
					StoreType: "cookie",
					Cookie:    *opt,
				})
				Expect(err).To(BeNil())
				Expect(s.(*CookieStore).Cookie).To(Equal(opt))
			})
		})
	})
})

var _ = Describe("store base stub methods", func() {
	var s *store

	BeforeEach(func() {
		s = &store{
			Cookie: &config.CookieStoreOptions{
				Name:   "_xw",
				Secret: config.NewResolvedSecretRef([]byte("cookiesecret0123")),
			},
		}
	})

	It("should return ErrNotImplemented from Save", func() {
		Expect(errors.Is(s.Save(nil, nil, nil), ErrNotImplemented)).To(BeTrue())
	})

	It("should return ErrNotImplemented from Load", func() {
		_, err := s.Load(nil)
		Expect(errors.Is(err, ErrNotImplemented)).To(BeTrue())
	})

	It("should return ErrNotImplemented from Clear", func() {
		Expect(errors.Is(s.Clear(nil, nil), ErrNotImplemented)).To(BeTrue())
	})

	It("should return ErrNotImplemented from VerifyConnection", func() {
		Expect(errors.Is(s.VerifyConnection(context.Background()), ErrNotImplemented)).To(BeTrue())
	})

	It("should return nil from Close", func() {
		Expect(s.Close()).To(BeNil())
	})
})

var _ = Describe("NewSessionStore", func() {
	It("should create a RedisStore when StoreType is redis", func() {
		s, err := NewSessionStore(&config.Session{
			StoreType: config.RedisSession,
			Cookie: config.CookieStoreOptions{
				Name:     "_xw",
				Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
				SameSite: "lax",
			},
			Redis: config.RedisConfig{
				Addr: "localhost:6379",
				TTL:  time.Hour,
			},
		})
		Expect(err).To(BeNil())
		Expect(s).NotTo(BeNil())
		_, ok := s.(*RedisStore)
		Expect(ok).To(BeTrue())
	})
})

var _ = Describe("store.cookieOptsFor Expire override", func() {
	It("should apply Expire from ValueOptions when non-zero", func() {
		s := &store{
			Cookie: &config.CookieStoreOptions{
				Name:     "_xw",
				Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
				Expire:   0,
				MaxAge:   0,
				SameSite: "lax",
			},
		}
		opts := &ValueOptions{Name: "_csrf", Expire: 5 * time.Minute}
		result := s.cookieOptsFor(opts)
		Expect(result.Expire).To(Equal(5 * time.Minute))
	})
})

var _ = Describe("joinCookies edge cases", func() {
	It("should return error on empty slice", func() {
		_, err := joinCookies([]*http.Cookie{}, "name")
		Expect(err).To(HaveOccurred())
	})

	It("should return the single cookie unchanged", func() {
		c := &http.Cookie{Name: "x", Value: "v"}
		result, err := joinCookies([]*http.Cookie{c}, "x")
		Expect(err).To(BeNil())
		Expect(result.Value).To(Equal("v"))
	})
})

var _ = Describe("splitCookieName overflow", func() {
	It("should truncate name when combined length exceeds 256 chars", func() {
		longName := string(make([]byte, 260))
		for i := range longName {
			longName = longName[:i] + "a" + longName[i+1:]
		}
		result := splitCookieName(longName, 0)
		Expect(len(result)).To(BeNumerically("<=", 256))
	})
})
