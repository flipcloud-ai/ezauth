package sessions

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
)

func save(opt *config.CookieStoreOptions, ss *ezapi.Session) (SessionStore, *http.Request, *httptest.ResponseRecorder) {
	s, err := NewCookieStore(opt, opt.Refresh)
	Expect(err).To(BeNil())
	rec := httptest.NewRecorder()
	logger, _ := testutils.SetupTestLogger()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(ezlog.RequestContext(r.Context(), logger))
		Expect(s.Save(w, r, ss)).To(Succeed())
	})
	r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	Expect(err).To(BeNil())
	h.ServeHTTP(rec, r)

	return s, r, rec
}

var _ = Describe("Sessions Module Test Suite", func() {
	When("cookie store test", func() {
		now := time.Now()
		maxAge := 12 * time.Hour
		exp := now.Add(1 * time.Hour).Round(2 * time.Second).UTC()
		nonce, _ := encryption.Nonce(32)
		logger, _ := testutils.SetupTestLogger()
		DescribeTable("cookie store test", func(opt *config.CookieStoreOptions, ss *ezapi.Session, isError bool) {
			var p = gomonkey.ApplyFunc(time.Now, func() time.Time {
				return now
			})
			defer p.Reset()
			s, err := NewCookieStore(opt, opt.Refresh)
			if isError {
				Expect(err).NotTo(BeNil())
				return
			} else {
				Expect(err).To(BeNil())
			}
			Expect(s.(*CookieStore).RefreshPeriod).To(Equal(opt.Refresh))
			cipher, _ := encryption.NewGCMCipher(opt.Secret.Bytes())
			Expect(s.(*CookieStore).CookieCipher).To(Equal(cipher))
			Expect(s.(*CookieStore).Cookie).To(Equal(opt))
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(ezlog.RequestContext(r.Context(), logger))
				Expect(s.Save(w, r, ss)).To(Succeed())
			})
			rec := httptest.NewRecorder()
			r, err := http.NewRequest("GET", "/", nil)
			Expect(err).To(BeNil())
			h.ServeHTTP(rec, r)
		},
			Entry("full cookie", &config.CookieStoreOptions{
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
			}, &ezapi.Session{}, false),
			Entry("invalid secret", &config.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   config.NewResolvedSecretRef([]byte("invalid")),
				Domains:  []string{"www.userequesthost.com", "www.test123.com"},
				Path:     "/",
				Expire:   1 * time.Hour,
				Refresh:  1 * time.Hour,
				MaxAge:   maxAge,
				Secure:   true,
				HTTPOnly: testutils.BoolPtr(true),
				SameSite: "strict",
			}, &ezapi.Session{}, true),
		)
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
			ss := &ezapi.Session{
				CreatedAt:    now.Unix(),
				ExpiresOn:    now.Add(1 * time.Hour).Unix(),
				AccessToken:  "abcd1234",
				IDToken:      "abcd1234",
				RefreshToken: "abcd1234",
				Nonce:        nonce,
				Profile: ezapi.Profile{
					Subject: "lalala",
					Email:   "test@123.com",
					User:    "test@123.com",
				},
			}
			It("invalid cookie name", func(ctx SpecContext) {
				newopt := &config.CookieStoreOptions{}
				*newopt = *opt
				s, r, rec := save(newopt, ss)
				c := rec.Result().Cookies()
				h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, cookie := range c {
						r.AddCookie(cookie)
					}
				})
				h.ServeHTTP(rec, r)
				s.(*CookieStore).Cookie.Name = "invalid_name"
				ess, err := s.Load(r)
				Expect(err).NotTo(BeNil())
				Expect(errors.Is(err, http.ErrNoCookie)).To(BeTrue())
				Expect(ess).To(BeNil())
			})
			It("invalid cookie signature", func(ctx SpecContext) {
				newopt := &config.CookieStoreOptions{}
				*newopt = *opt
				s, r, rec := save(newopt, ss)
				c := rec.Result().Cookies()
				h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, cookie := range c {
						r.AddCookie(cookie)
					}
				})
				h.ServeHTTP(rec, r)
				s.(*CookieStore).Cookie.Secret = config.NewResolvedSecretRef([]byte("invalid_secret"))
				ess, err := s.Load(r)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("Cookie failed in validation"))
				Expect(ess).To(BeNil())
			})
			It("decode failure", func(ctx SpecContext) {
				newopt := &config.CookieStoreOptions{}
				*newopt = *opt
				s, r, rec := save(newopt, ss)
				c := rec.Result().Cookies()
				h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, cookie := range c {
						r.AddCookie(cookie)
					}
				})
				cipher, err := encryption.NewGCMCipher([]byte("invalid_secret12"))
				Expect(err).To(BeNil())
				s.(*CookieStore).CookieCipher = cipher
				h.ServeHTTP(rec, r)
				ess, err := s.Load(r)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("error decrypting the session state"))
				Expect(ess).To(BeNil())
			})
			It("refresh needed", func(ctx SpecContext) {
				newopt := &config.CookieStoreOptions{}
				*newopt = *opt
				nss := &ezapi.Session{}
				*nss = *ss
				nss.CreatedAt = time.Now().Add(-2 * time.Hour).Unix()
				s, r, rec := save(newopt, nss)
				c := rec.Result().Cookies()
				h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, cookie := range c {
						r.AddCookie(cookie)
					}
				})
				h.ServeHTTP(rec, r)
				_, err := s.Load(r)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("session is expired, need to refresh"))
				Expect(errors.Is(err, ErrNeedsRefresh)).To(BeTrue())
			})
		})
		DescribeTable("cookie general interface test", func(s *CookieStore, f gstruct.Fields, ss *ezapi.Session, host string) {
			var p = gomonkey.ApplyFunc(time.Now, func() time.Time {
				return now
			})
			defer p.Reset()
			logger, _ := testutils.SetupTestLogger()
			cipher, err := encryption.NewGCMCipher(s.Cookie.Secret.Bytes())
			Expect(err).To(BeNil())
			s.CookieCipher = cipher
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(ezlog.RequestContext(r.Context(), logger))
				Expect(s.Save(w, r, ss)).To(Succeed())
			})
			rec := httptest.NewRecorder()
			r, err := http.NewRequest("GET", "/", nil)
			r.Host = host
			r = r.WithContext(ezlog.RequestContext(r.Context(), logger))
			Expect(err).To(BeNil())
			h.ServeHTTP(rec, r)

			val, valErr := ss.EncodeSessionState(s.CookieCipher, true)
			Expect(valErr).To(BeNil())
			cookies, cookieErr := s.makeSessionCookie(r, val)
			Expect(cookieErr).To(BeNil())
			rwc := rec.Result().Cookies()
			Expect(len(rwc)).To(Equal(len(cookies)))
			var c *http.Cookie
			if len(cookies) == 1 {
				for _, cookie := range rwc {
					if cookie.Name == s.Cookie.Name {
						c = cookie
					}
				}
				Expect(c).NotTo(BeNil())
				Expect(*c).To(gstruct.MatchFields(gstruct.IgnoreExtras, f))
				h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.AddCookie(c)
				})
			} else {
				h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, cookie := range rwc {
						r.AddCookie(cookie)
					}
				})
			}

			rec = httptest.NewRecorder()
			r, err = http.NewRequest("GET", "/", nil)
			Expect(err).To(BeNil())
			h.ServeHTTP(rec, r)
			ess, err := s.Load(r)
			Expect(err).To(BeNil())
			Expect(cmp.Equal(*ess, *ss)).To(BeTrue())

			h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(ezlog.RequestContext(r.Context(), logger))
				Expect(s.Save(w, r, ss)).To(Succeed())
				Expect(s.Clear(w, r)).To(Succeed())
			})
			rec = httptest.NewRecorder()
			r, err = http.NewRequest("GET", "/", nil)
			Expect(err).To(BeNil())
			h.ServeHTTP(rec, r)
			Expect(len(rec.Result().Cookies())).NotTo(Equal(0))
			for _, cookie := range rec.Result().Cookies() {
				if matchCookieName(cookie.Name, s.Cookie.Name) {
					if cookie.Expires.After(now) || cookie.Expires.IsZero() {
						continue
					}
					Expect(cookie.Expires).To(BeElementOf(exp, exp.Add(-1*time.Second)))
					Expect(cookie.Value).To(Equal(""))
				}
			}
		},
			Entry("full cookie", &CookieStore{
				store: store{
					RefreshPeriod: 1 * time.Hour,
				},
				Cookie: &config.CookieStoreOptions{
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
				},
			}, gstruct.Fields{
				"Name":     Equal("_ez_proxy"),
				"Path":     Equal("/"),
				"Domain":   Equal("www.userequesthost.com"),
				"Expires":  BeElementOf(exp, exp.Add(-1*time.Second)),
				"MaxAge":   Equal(int(maxAge.Seconds())),
				"Secure":   BeTrue(),
				"HttpOnly": BeTrue(),
				"SameSite": Equal(http.SameSiteStrictMode),
			}, &ezapi.Session{}, "www.userequesthost.com"),
			Entry("cookie domain not match", &CookieStore{
				store: store{
					RefreshPeriod: 1 * time.Hour,
				},
				Cookie: &config.CookieStoreOptions{
					Name:     "_ez_proxy",
					Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
					Domains:  []string{"www.test123.com", "www.test321.com"},
					Path:     "/",
					Expire:   1 * time.Hour,
					Refresh:  1 * time.Hour,
					MaxAge:   maxAge,
					Secure:   true,
					HTTPOnly: testutils.BoolPtr(true),
					SameSite: "strict",
				},
			}, gstruct.Fields{
				"Name":     Equal("_ez_proxy"),
				"Path":     Equal("/"),
				"Domain":   Equal(""),
				"Expires":  BeElementOf(exp, exp.Add(-1*time.Second)),
				"MaxAge":   Equal(int(maxAge.Seconds())),
				"Secure":   BeTrue(),
				"HttpOnly": BeTrue(),
				"SameSite": Equal(http.SameSiteStrictMode),
			}, &ezapi.Session{}, "www.unrelated.com"),
			Entry("empty domain config", &CookieStore{
				store: store{
					RefreshPeriod: 1 * time.Hour,
				},
				Cookie: &config.CookieStoreOptions{
					Name:     "_ez_proxy",
					Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
					Domains:  []string{},
					Path:     "/",
					Refresh:  1 * time.Hour,
					Secure:   true,
					HTTPOnly: testutils.BoolPtr(true),
					SameSite: "lax",
				},
			}, gstruct.Fields{
				"Name":     Equal("_ez_proxy"),
				"Path":     Equal("/"),
				"Domain":   Equal(""),
				"MaxAge":   Equal(int(0)),
				"Secure":   BeTrue(),
				"HttpOnly": BeTrue(),
				"SameSite": Equal(http.SameSiteLaxMode),
			}, &ezapi.Session{}, ""),
			Entry("no request host", &CookieStore{
				store: store{
					RefreshPeriod: 1 * time.Hour,
				},
				Cookie: &config.CookieStoreOptions{
					Name:     "_ez_proxy",
					Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
					Domains:  []string{"www.test123.com", "www.test321.com"},
					Path:     "/",
					Refresh:  1 * time.Hour,
					Secure:   true,
					HTTPOnly: testutils.BoolPtr(true),
				},
			}, gstruct.Fields{
				"Name":     Equal("_ez_proxy"),
				"Path":     Equal("/"),
				"Domain":   Equal(""),
				"MaxAge":   Equal(int(0)),
				"Secure":   BeTrue(),
				"HttpOnly": BeTrue(),
				"SameSite": BeElementOf(http.SameSiteDefaultMode, http.SameSite(0)),
			}, &ezapi.Session{}, ""),
			Entry("non expired cookie", &CookieStore{
				store: store{
					RefreshPeriod: 1 * time.Hour,
				},
				Cookie: &config.CookieStoreOptions{
					Name:     "_ez_proxy",
					Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
					Domains:  []string{"www.userequesthost.com"},
					Path:     "/",
					Refresh:  1 * time.Hour,
					MaxAge:   -100,
					Secure:   false,
					HTTPOnly: testutils.BoolPtr(false),
				},
			}, gstruct.Fields{
				"Name":     Equal("_ez_proxy"),
				"Path":     Equal("/"),
				"Domain":   Equal("www.userequesthost.com"),
				"MaxAge":   Equal(-1),
				"Secure":   BeFalse(),
				"HttpOnly": BeFalse(),
				"SameSite": BeElementOf(http.SameSiteDefaultMode, http.SameSite(0)),
			}, &ezapi.Session{}, "www.userequesthost.com"),
			Entry("cookie exceeds max length", &CookieStore{
				store: store{
					RefreshPeriod: 1 * time.Hour,
				},
				Cookie: &config.CookieStoreOptions{
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
				},
			}, gstruct.Fields{
				"Name":     Equal("_ez_proxy"),
				"Path":     Equal("/"),
				"Domain":   Equal("www.userequesthost.com"),
				"Expires":  BeElementOf(exp, exp.Add(-1*time.Second)),
				"MaxAge":   Equal(int(maxAge.Seconds())),
				"Secure":   BeTrue(),
				"HttpOnly": BeTrue(),
				"SameSite": Equal(http.SameSiteStrictMode),
			}, func() *ezapi.Session {
				aTok, err := ezutils.NewRandomString(2048)
				Expect(err).ToNot(HaveOccurred())
				iTok, err := ezutils.NewRandomString(2048)
				Expect(err).ToNot(HaveOccurred())
				rTok, err := ezutils.NewRandomString(2048)
				Expect(err).ToNot(HaveOccurred())
				return &ezapi.Session{
					CreatedAt:    now.Unix(),
					ExpiresOn:    now.Add(1 * time.Hour).Unix(),
					AccessToken:  aTok,
					IDToken:      iTok,
					RefreshToken: rTok,
					Nonce:        nonce,
					Profile: ezapi.Profile{
						Subject: "lalala",
						Email:   "test@123.com",
						User:    "test@123.com",
					},
				}
			}(), "www.userequesthost.com"),
		)
		Describe("SaveValue / LoadValue", func() {
			baseOpt := &config.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
				Path:     "/app",
				Domains:  []string{"example.com"},
				Secure:   true,
				HTTPOnly: testutils.BoolPtr(true),
				SameSite: "strict",
			}

			It("round-trips a raw byte value and inherits session cookie scope/transport", func() {
				s, err := NewCookieStore(baseOpt, 0)
				Expect(err).To(BeNil())

				rec := httptest.NewRecorder()
				r, err := http.NewRequest("GET", "/", nil)
				Expect(err).To(BeNil())
				r.Host = "example.com"
				r = r.WithContext(ezlog.RequestContext(r.Context(), logger))

				payload := []byte("hello-csrf-token")
				vopts := &ValueOptions{Name: "_csrf", MaxAge: 12 * time.Hour}
				Expect(s.SaveValue(rec, r, payload, vopts)).To(Succeed())

				cookies := rec.Result().Cookies()
				Expect(cookies).NotTo(BeEmpty())
				c := cookies[0]
				Expect(c.Name).To(Equal("_csrf"))
				// Scope + transport are inherited from the session cookie.
				Expect(c.Path).To(Equal("/app"))
				Expect(c.Domain).To(Equal("example.com"))
				Expect(c.Secure).To(BeTrue())
				Expect(c.HttpOnly).To(BeTrue())
				Expect(c.SameSite).To(Equal(http.SameSiteStrictMode))
				// MaxAge is CSRF's own override.
				Expect(c.MaxAge).To(Equal(int((12 * time.Hour).Seconds())))

				// Replay the response cookies into a fresh request to load.
				r2, err := http.NewRequest("GET", "/", nil)
				Expect(err).To(BeNil())
				for _, ck := range cookies {
					r2.AddCookie(ck)
				}
				got, err := s.LoadValue(r2, vopts)
				Expect(err).To(BeNil())
				Expect(got).To(Equal(payload))
			})

			It("returns (nil, nil) when the cookie is missing", func() {
				s, err := NewCookieStore(baseOpt, 0)
				Expect(err).To(BeNil())
				r, err := http.NewRequest("GET", "/", nil)
				Expect(err).To(BeNil())
				got, err := s.LoadValue(r, &ValueOptions{Name: "_missing"})
				Expect(err).To(BeNil())
				Expect(got).To(BeNil())
			})

			It("reuses the store's secret when the caller leaves it unset", func() {
				s, err := NewCookieStore(baseOpt, 0)
				Expect(err).To(BeNil())

				rec := httptest.NewRecorder()
				r, err := http.NewRequest("GET", "/", nil)
				Expect(err).To(BeNil())
				r.Host = "example.com"
				r = r.WithContext(ezlog.RequestContext(r.Context(), logger))

				payload := []byte("secret-fallback")
				Expect(s.SaveValue(rec, r, payload, &ValueOptions{Name: "_csrf"})).To(Succeed())
				cookies := rec.Result().Cookies()
				Expect(cookies).NotTo(BeEmpty())

				// The cookie must validate against the session secret, since
				// ValueOptions didn't carry one of its own.
				val, verr := encryption.Validate(cookies[0], baseOpt.Secret.Bytes())
				Expect(verr).To(BeNil())
				Expect(val).To(Equal(payload))
			})

			It("honors a caller-supplied Secret override", func() {
				s, err := NewCookieStore(baseOpt, 0)
				Expect(err).To(BeNil())

				rec := httptest.NewRecorder()
				r, err := http.NewRequest("GET", "/", nil)
				Expect(err).To(BeNil())
				r.Host = "example.com"
				r = r.WithContext(ezlog.RequestContext(r.Context(), logger))

				overrideSecret := []byte("anothersecret123")
				payload := []byte("override")
				Expect(s.SaveValue(rec, r, payload, &ValueOptions{Name: "_csrf", Secret: overrideSecret})).To(Succeed())
				cookies := rec.Result().Cookies()
				Expect(cookies).NotTo(BeEmpty())

				// Validating with the session secret should now fail.
				_, verr := encryption.Validate(cookies[0], baseOpt.Secret.Bytes())
				Expect(verr).NotTo(BeNil())
				val, verr := encryption.Validate(cookies[0], []byte(overrideSecret))
				Expect(verr).To(BeNil())
				Expect(val).To(Equal(payload))
			})

			It("errors when opts is missing a Name", func() {
				s, err := NewCookieStore(baseOpt, 0)
				Expect(err).To(BeNil())
				rec := httptest.NewRecorder()
				r, err := http.NewRequest("GET", "/", nil)
				Expect(err).To(BeNil())
				Expect(s.SaveValue(rec, r, []byte("x"), &ValueOptions{})).NotTo(Succeed())
				_, err = s.LoadValue(r, &ValueOptions{})
				Expect(err).NotTo(BeNil())
				Expect(s.DeleteValue(rec, r, &ValueOptions{})).NotTo(Succeed())
			})

			It("DeleteValue emits a clearing cookie that inherits scope", func() {
				s, err := NewCookieStore(baseOpt, 0)
				Expect(err).To(BeNil())
				rec := httptest.NewRecorder()
				r, err := http.NewRequest("GET", "/", nil)
				Expect(err).To(BeNil())
				r.Host = "example.com"
				r = r.WithContext(ezlog.RequestContext(r.Context(), logger))

				Expect(s.DeleteValue(rec, r, &ValueOptions{Name: "_csrf"})).To(Succeed())
				cookies := rec.Result().Cookies()
				Expect(cookies).NotTo(BeEmpty())
				c := cookies[0]
				Expect(c.Name).To(Equal("_csrf"))
				Expect(c.MaxAge).To(Equal(-1))
				// Scope + transport still inherited from the session cookie so
				// the browser treats it as the same cookie and evicts it.
				Expect(c.Path).To(Equal("/app"))
				Expect(c.Domain).To(Equal("example.com"))
				Expect(c.Secure).To(BeTrue())
				Expect(c.HttpOnly).To(BeTrue())
				Expect(c.SameSite).To(Equal(http.SameSiteStrictMode))
			})
		})

		Describe("matchCookieName", func() {
			DescribeTable("name matching",
				func(name, base string, expected bool) {
					Expect(matchCookieName(name, base)).To(Equal(expected))
				},
				Entry("exact match", "_ez_proxy", "_ez_proxy", true),
				Entry("single digit suffix", "_ez_proxy_0", "_ez_proxy", true),
				Entry("multi digit suffix", "_ez_proxy_12", "_ez_proxy", true),
				Entry("underscore only no digits", "_ez_proxy_", "_ez_proxy", false),
				Entry("non-digit suffix", "_ez_proxy_a", "_ez_proxy", false),
				Entry("digits then non-digit", "_ez_proxy_1a", "_ez_proxy", false),
				Entry("unrelated name", "other_cookie", "_ez_proxy", false),
				Entry("prefix match without separator", "_ez_proxy2", "_ez_proxy", false),
				Entry("base with special chars", "_xw.proxy_1", "_xw.proxy", true),
				Entry("base is shorter prefix sharing separator", "_ez_proxy_1", "_xw", false),
			)
		})
	})
})

var _ = Describe("CookieStore.VerifyConnection", func() {
	It("should always return nil", func() {
		cs := &CookieStore{}
		Expect(cs.VerifyConnection(context.Background())).To(BeNil())
	})
})

var _ = Describe("CookieStore.Clear", func() {
	It("should emit a clearing cookie when a matching cookie is present", func() {
		opt := &config.CookieStoreOptions{
			Name:     "_ez_proxy",
			Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
			Path:     "/",
			Secure:   false,
			HTTPOnly: testutils.BoolPtr(true),
			SameSite: "lax",
		}
		s, err := NewCookieStore(opt, 0)
		Expect(err).To(BeNil())

		ss := &ezapi.Session{}
		ss.CreatedAtNow()
		ss.ExpiresIn(time.Hour)

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		Expect(s.Save(rec, req, ss)).To(Succeed())

		rec2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/", nil)
		for _, c := range rec.Result().Cookies() {
			req2.AddCookie(c)
		}
		Expect(s.Clear(rec2, req2)).To(Succeed())

		clearCookies := rec2.Result().Cookies()
		Expect(clearCookies).NotTo(BeEmpty())
		Expect(clearCookies[0].MaxAge).To(Equal(-1))
	})

	It("should be a no-op when no matching cookies are present", func() {
		opt := &config.CookieStoreOptions{
			Name:     "_ez_proxy",
			Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
			Path:     "/",
			SameSite: "lax",
		}
		s, err := NewCookieStore(opt, 0)
		Expect(err).To(BeNil())

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "other_cookie", Value: "x"})
		Expect(s.Clear(rec, req)).To(Succeed())
		Expect(rec.Result().Cookies()).To(BeEmpty())
	})
})

var _ = Describe("NewCookieStore errors", func() {
	It("should fail when SameSite=None and not Secure", func() {
		opt := &config.CookieStoreOptions{
			Name:     "_xw",
			Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
			SameSite: "none",
			Secure:   false,
		}
		_, err := NewCookieStore(opt, 0)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("SameSite=None"))
	})
})

var _ = Describe("ParseSameSite", func() {
	DescribeTable("converts strings to http.SameSite",
		func(input string, expected http.SameSite) {
			Expect(ParseSameSite(input)).To(Equal(expected))
		},
		Entry("lax", "lax", http.SameSiteLaxMode),
		Entry("Lax uppercase", "Lax", http.SameSiteLaxMode),
		Entry("strict", "strict", http.SameSiteStrictMode),
		Entry("none", "none", http.SameSiteNoneMode),
		Entry("unknown returns default", "unknown", http.SameSiteDefaultMode),
		Entry("empty returns default", "", http.SameSiteDefaultMode),
	)
})
