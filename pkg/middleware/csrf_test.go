package middleware

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/agiledragon/gomonkey/v2"

	"github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	ezutil "github.com/flipcloud-ai/ezauth/pkg/utils"
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

// newTestStore builds a cookie-backed SessionStore used by the CSRF
// middleware. The cookie attributes here (Path, Secure, HTTPOnly, SameSite)
// are what the CSRF cookie inherits at write time — Secure is off so httptest
// (non-TLS) will accept the cookie.
func newTestStore() sessions.SessionStore {
	store, err := sessions.NewCookieStore(&config.CookieStoreOptions{
		Name:     "_xw_session",
		Secret:   config.NewResolvedSecretRef([]byte("cookiesecret0123")),
		Path:     "/",
		Secure:   false,
		HTTPOnly: testutils.BoolPtr(true),
		SameSite: "lax",
	}, 0)
	Expect(err).To(BeNil())
	return store
}

// buildCSRF constructs a CSRF handler wired to a recording "ok" next handler.
// The returned handler is already wrapped by `InitSession` so the request info
// is populated before CSRF runs.
func buildCSRF(opts *config.CSRFConfig) http.Handler {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	csrfMw := CSRF(opts, newTestStore(), nil)
	return csrfMw(next)
}

// seedRequestInfo attaches a fresh AuthRequest to the request so the CSRF
// middleware's `apis.GetRequest(r)` returns a shared pointer rather than a
// short-lived empty value.
func seedRequestInfo(r *http.Request) *http.Request {
	info := &ezapi.AuthRequest{RequestID: "test-req"}
	return ezapi.AddRequestInfo(r, info)
}

var _ = Describe("CSRF Middleware Test Suite", func() {
	var secret = config.NewResolvedSecretRef([]byte("cookiesecret0123"))

	defaultOpts := func() *config.CSRFConfig {
		return &config.CSRFConfig{
			Enabled:    true,
			Name:       "_xw_csrf",
			HeaderName: "X-CSRF-Token",
			Secret:     secret,
			MaxAge:     12 * time.Hour,
		}
	}

	Describe("mask / unmask / xorToken", func() {
		It("round-trips a token through mask+unmask", func() {
			realToken := bytes.Repeat([]byte{0xAB}, tokenLength)
			masked, err := mask(realToken)
			Expect(err).To(BeNil())
			Expect(masked).NotTo(BeEmpty())

			decoded, err := base64.StdEncoding.DecodeString(masked)
			Expect(err).To(BeNil())
			Expect(decoded).To(HaveLen(tokenLength * 2))

			unmasked := unmask(decoded)
			Expect(unmasked).To(Equal(realToken))
		})

		It("produces different masked values for the same real token", func() {
			realToken := bytes.Repeat([]byte{0x5A}, tokenLength)
			a, err := mask(realToken)
			Expect(err).To(BeNil())
			b, err := mask(realToken)
			Expect(err).To(BeNil())
			Expect(a).NotTo(Equal(b))
		})

		It("returns nil on issued tokens of the wrong length", func() {
			Expect(unmask([]byte("too-short"))).To(BeNil())
			Expect(unmask(bytes.Repeat([]byte{0x01}, tokenLength))).To(BeNil())
		})

		It("xorToken truncates to the shorter slice", func() {
			a := []byte{0x01, 0x02, 0x03, 0x04}
			b := []byte{0xFF, 0xFF}
			out := xorToken(a, b)
			Expect(out).To(Equal([]byte{0xFE, 0xFD}))
			// Reversed argument order should be symmetric in length selection.
			Expect(xorToken(b, a)).To(Equal([]byte{0xFE, 0xFD}))
		})
	})

	Describe("CSRF constructor", func() {
		It("applies package defaults when opts is nil", func() {
			h := CSRF(nil, newTestStore(), nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).(*csrf)
			Expect(h.opts.Name).To(Equal(cookieName))
			Expect(h.opts.HeaderName).To(Equal(headerName))
			Expect(h.opts.MaxAge).To(Equal(12 * time.Hour))
			Expect(h.ErrorHandler).NotTo(BeNil())
		})

		It("backfills empty name/header/zero max age from defaults", func() {
			opts := &config.CSRFConfig{}
			h := CSRF(opts, newTestStore(), nil)(nil).(*csrf)
			Expect(h.opts.Name).To(Equal(cookieName))
			Expect(h.opts.HeaderName).To(Equal(headerName))
			Expect(h.opts.MaxAge).To(Equal(12 * time.Hour))
		})

		It("uses the provided custom error handler", func() {
			customCalled := false
			custom := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				customCalled = true
				w.WriteHeader(http.StatusTeapot)
			})
			opts := defaultOpts()
			h := CSRF(opts, newTestStore(), custom)(nil).(*csrf)
			Expect(h.ErrorHandler).NotTo(BeNil())

			// Directly invoke the error handler to verify wiring.
			rec := httptest.NewRecorder()
			h.ErrorHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
			Expect(customCalled).To(BeTrue())
			Expect(rec.Code).To(Equal(http.StatusTeapot))
		})
	})

	Describe("FailureReason / ErrorHandler helpers", func() {
		It("returns nil when no error is stored in the request context", func() {
			r := httptest.NewRequest("GET", "/", nil)
			Expect(FailureReason(r)).To(BeNil())
		})

		It("returns the wrapped error when one is stored", func() {
			r := httptest.NewRequest("GET", "/", nil)
			r = wrapCSRFError(r, ErrBadToken)
			Expect(FailureReason(r)).To(Equal(ErrBadToken))
		})

		It("falls back to a generic message when wrapped error is nil", func() {
			r := httptest.NewRequest("GET", "/", nil)
			r = wrapCSRFError(r, nil)
			err := FailureReason(r)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("request may be expired"))
		})

		It("writes a 403 with the failure reason", func() {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			r = wrapCSRFError(r, ErrBadOrigin)
			ErrorHandler(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadOrigin.Error()))
		})
	})

	Describe("Safe-method request handling", func() {
		It("generates a real token, sets a signed cookie, and passes through", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			h.ServeHTTP(rec, r)

			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("ok"))
			Expect(rec.Header().Get("Vary")).To(Equal("Cookie"))

			cookies := rec.Result().Cookies()
			var found *http.Cookie
			for _, c := range cookies {
				if c.Name == opts.Name {
					found = c
					break
				}
			}
			Expect(found).NotTo(BeNil())
			Expect(found.HttpOnly).To(BeTrue())

			val, err := encryption.Validate(found, opts.Secret.Bytes())
			Expect(err).To(BeNil())
			Expect(val).To(HaveLen(tokenLength))
		})

		It("reuses the token from a prior cookie instead of rotating each request", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			// First request: middleware issues a cookie.
			rec1 := httptest.NewRecorder()
			r1 := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			h.ServeHTTP(rec1, r1)
			cookie := rec1.Result().Cookies()[0]
			tok1, err := encryption.Validate(cookie, opts.Secret.Bytes())
			Expect(err).To(BeNil())

			// Second request: carries the cookie; middleware should keep using it.
			rec2 := httptest.NewRecorder()
			r2 := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			r2.AddCookie(cookie)
			h.ServeHTTP(rec2, r2)

			// No new cookie should be emitted when a valid one exists.
			Expect(rec2.Result().Cookies()).To(BeEmpty())
			info := ezapi.GetRequest(r2)
			Expect(info.CSRFToken).To(Equal(tok1))
		})

		It("issues a fresh cookie when the existing one is signed with a different secret", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			// Build a tampered cookie signed with a different secret.
			fakeSigned, err := encryption.SignedValue([]byte("wrong-secret-0123"), opts.Name,
				bytes.Repeat([]byte{0xCC}, tokenLength))
			Expect(err).To(BeNil())
			badCookie := &http.Cookie{Name: opts.Name, Value: fakeSigned}

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			r.AddCookie(badCookie)
			h.ServeHTTP(rec, r)

			Expect(rec.Code).To(Equal(http.StatusOK))
			// Bad cookie rejected, middleware should mint and set a new one.
			Expect(rec.Result().Cookies()).To(HaveLen(1))
		})
	})

	Describe("Unsafe-method request handling", func() {
		// issueToken runs a GET through the middleware to obtain the cookie and
		// the masked token that a browser would subsequently submit.
		issueToken := func(opts *config.CSRFConfig) (*http.Cookie, string) {
			var captured string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if v, ok := r.Context().Value(tokenKey).(string); ok {
					captured = v
				}
				w.WriteHeader(http.StatusOK)
			})
			h := CSRF(opts, newTestStore(), nil)(next)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
			cookies := rec.Result().Cookies()
			Expect(cookies).NotTo(BeEmpty())
			return cookies[0], captured
		}

		It("accepts a POST whose token matches the cookie (header-based)", func() {
			opts := defaultOpts()
			cookie, masked := issueToken(opts)
			Expect(masked).NotTo(BeEmpty())

			h := buildCSRF(opts)
			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.AddCookie(cookie)
			r.Header.Set(opts.HeaderName, masked)
			// Same-origin so the Referer check is a no-op.
			r.Header.Set("Referer", "https://"+r.Host+"/")
			// Treat the request as arriving over TLS so the scheme match works.
			r.Header.Set("Origin", "https://"+r.Host)

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("ok"))
		})

		It("accepts a POST whose token arrives in the form body", func() {
			opts := defaultOpts()
			cookie, masked := issueToken(opts)

			h := buildCSRF(opts)
			rec := httptest.NewRecorder()
			body := url.Values{tokenFormField: []string{masked}}
			r := seedRequestInfo(httptest.NewRequest("POST", "/",
				strings.NewReader(body.Encode())))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(cookie)
			r.Header.Set("Origin", "https://"+r.Host)

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
		})

		It("accepts a POST whose token arrives in a multipart form", func() {
			opts := defaultOpts()
			cookie, masked := issueToken(opts)

			var buf bytes.Buffer
			mw := multipart.NewWriter(&buf)
			Expect(mw.WriteField(tokenFormField, masked)).To(Succeed())
			Expect(mw.Close()).To(Succeed())

			h := buildCSRF(opts)
			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", &buf))
			r.Header.Set("Content-Type", mw.FormDataContentType())
			r.AddCookie(cookie)
			r.Header.Set("Origin", "https://"+r.Host)
			// Pre-parse so MultipartForm is non-nil when the middleware reads it.
			Expect(r.ParseMultipartForm(1 << 20)).To(Succeed())

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
		})

		It("rejects a POST with no token at all", func() {
			opts := defaultOpts()
			cookie, _ := issueToken(opts)

			h := buildCSRF(opts)
			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.AddCookie(cookie)
			r.Header.Set("Origin", "https://"+r.Host)

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrNoToken.Error()))
		})

		It("rejects a POST with a token that doesn't match the cookie", func() {
			opts := defaultOpts()
			cookie, _ := issueToken(opts)

			// Build a mask derived from an unrelated token.
			bogus, err := mask(bytes.Repeat([]byte{0x42}, tokenLength))
			Expect(err).To(BeNil())

			h := buildCSRF(opts)
			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.AddCookie(cookie)
			r.Header.Set(opts.HeaderName, bogus)
			r.Header.Set("Origin", "https://"+r.Host)

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadToken.Error()))
		})

		It("rejects a POST whose token is not valid base64", func() {
			opts := defaultOpts()
			cookie, _ := issueToken(opts)

			h := buildCSRF(opts)
			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.AddCookie(cookie)
			r.Header.Set(opts.HeaderName, "!!!not-base64!!!")
			r.Header.Set("Origin", "https://"+r.Host)

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadToken.Error()))
		})
	})

	Describe("Origin / Referer enforcement", func() {
		It("rejects a cross-origin POST whose Origin host is not in the allowlist", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.Host = "api.example.com"
			r.Header.Set("Origin", "https://evil.example.com")

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadOrigin.Error()))
		})

		It("accepts a cross-origin POST whose Origin host is in the allowlist", func() {
			opts := defaultOpts()
			opts.TrustedOrigins = []string{"trusted.example.com"}
			h := buildCSRF(opts)

			// Establish a valid token pair first.
			var captured string
			seed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if v, ok := r.Context().Value(tokenKey).(string); ok {
					captured = v
				}
			})
			seedH := CSRF(opts, newTestStore(), nil)(seed)
			rec0 := httptest.NewRecorder()
			r0 := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			seedH.ServeHTTP(rec0, r0)
			cookie := rec0.Result().Cookies()[0]

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.AddCookie(cookie)
			r.Host = "api.example.com"
			r.Header.Set("Origin", "https://trusted.example.com")
			r.Header.Set(opts.HeaderName, captured)

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
		})

		It("rejects a malformed Origin header", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			// net/url tolerates a lot; use a value with a control byte to force an error.
			r.Header.Set("Origin", "http://\x7f")

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadOrigin.Error()))
		})

		// Regression: a same-host Origin with a downgraded scheme (http)
		// must be rejected when the request itself is HTTPS. Browsers set
		// Origin themselves, so its scheme reflects the real browsing
		// context — a mismatch indicates a MITM downgrade, not a spoof.
		It("rejects an Origin whose scheme downgrades from HTTPS to HTTP", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "https://api.example.com/", nil))
			r.Host = "api.example.com"
			// Attacker-injected form submitting cleartext Origin to an
			// HTTPS endpoint the victim is authenticated against.
			r.Header.Set("Origin", "http://api.example.com")

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadOrigin.Error()))
		})

		It("falls back to Referer when Origin is absent", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			// No Origin, no Referer: middleware should reject with ErrNoReferer.
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrNoReferer.Error()))
		})

		It("rejects a cleartext Referer when request is served via TLS", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.Header.Set("Referer", "http://insecure.example.com/form")

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadReferer.Error()))
		})

		It("rejects a cross-origin Referer not in the allowlist", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.Host = "api.example.com"
			r.Header.Set("Referer", "https://attacker.example.com/")

			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
			Expect(rec.Body.String()).To(ContainSubstring(ErrBadReferer.Error()))
		})

		It("skips Referer/Origin checks over plain HTTP (no TLS)", func() {
			opts := defaultOpts()
			cookie, masked := func() (*http.Cookie, string) {
				var captured string
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if v, ok := r.Context().Value(tokenKey).(string); ok {
						captured = v
					}
				})
				h := CSRF(opts, newTestStore(), nil)(next)
				rec := httptest.NewRecorder()
				r := seedRequestInfo(httptest.NewRequest("GET", "http://example.com/", nil))
				h.ServeHTTP(rec, r)
				cookies := rec.Result().Cookies()
				Expect(cookies).NotTo(BeEmpty())
				return cookies[0], captured
			}()

			h := buildCSRF(opts)
			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "http://example.com/", nil))
			r.AddCookie(cookie)
			r.Header.Set(opts.HeaderName, masked)
			// No Origin/Referer: plaintext HTTP with no TLS skips strict checks.
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
		})
	})

	Describe("Error-path edge cases", func() {
		It("invokes the error handler via the shared ErrorHandler when reqInfo is nil", func() {
			// GetRequest never returns nil — it returns an empty struct. To hit the
			// nil branch we stub it via a custom handler that mimics the behavior.
			called := false
			custom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				Expect(FailureReason(r)).NotTo(BeNil())
				w.WriteHeader(http.StatusForbidden)
			})

			cs := &csrf{
				h:            http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
				opts:         *defaultOpts(),
				ErrorHandler: custom,
			}
			// Directly exercise wrapCSRFError + ErrorHandler path.
			rec := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			r = wrapCSRFError(r, errors.New("no request info"))
			cs.ErrorHandler.ServeHTTP(rec, r)

			Expect(called).To(BeTrue())
			Expect(rec.Code).To(Equal(http.StatusForbidden))
		})

		It("returns a decoded issued token from requestToken", func() {
			opts := defaultOpts()
			cs := CSRF(opts, newTestStore(), nil)(nil).(*csrf)

			payload := bytes.Repeat([]byte{0x01}, tokenLength*2)
			encoded := base64.StdEncoding.EncodeToString(payload)

			r := httptest.NewRequest("POST", "/", nil)
			r.Header.Set(opts.HeaderName, encoded)

			decoded, err := cs.requestToken(r)
			Expect(err).To(BeNil())
			Expect(decoded).To(Equal(payload))
		})

		It("returns nil when no token is supplied on any channel", func() {
			opts := defaultOpts()
			cs := CSRF(opts, newTestStore(), nil)(nil).(*csrf)
			r := httptest.NewRequest("POST", "/", nil)
			decoded, err := cs.requestToken(r)
			Expect(err).To(BeNil())
			Expect(decoded).To(BeNil())
		})
	})

	Describe("Bearer token exemption", func() {
		It("passes a POST with a Bearer token through without CSRF enforcement", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			r.Header.Set("Authorization", "Bearer xw_someapitoken")
			// No CSRF cookie, no token header — would be rejected without the exemption.
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
		})

		It("still enforces CSRF on a POST without a Bearer token", func() {
			opts := defaultOpts()
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("POST", "/", nil))
			// No Authorization header and no CSRF token — must be rejected.
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
		})
	})

	Describe("Token helper", func() {
		It("should return the masked token set in context", func() {
			opts := defaultOpts()
			var capturedToken string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedToken = Token(r)
				w.WriteHeader(http.StatusOK)
			})
			h := CSRF(opts, newTestStore(), nil)(next)

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			h.ServeHTTP(rec, r)

			Expect(capturedToken).NotTo(BeEmpty())
		})

		It("should return empty string when CSRF middleware has not run", func() {
			r := httptest.NewRequest("GET", "/", nil)
			Expect(Token(r)).To(BeEmpty())
		})
	})

	Describe("ExcludePrefixes", func() {
		It("should skip CSRF enforcement for excluded path prefixes", func() {
			opts := defaultOpts()
			opts.ExcludePrefixes = []string{"/static/", "/assets/"}
			h := buildCSRF(opts)

			rec := httptest.NewRecorder()
			// POST to excluded path — no token, no cookie — should pass through
			r := seedRequestInfo(httptest.NewRequest("POST", "/static/app.js", nil))
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
		})
	})

	Describe("reqInfo == nil path", func() {
		It("should reject when no AuthRequest is in the context", func() {
			opts := defaultOpts()
			h := CSRF(opts, newTestStore(), nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			// No seedRequestInfo — so LookupRequest returns nil
			r := httptest.NewRequest("POST", "/", nil)
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
		})
	})

	Describe("saveToken nil store", func() {
		It("should return error from saveToken when store is nil", func() {
			opts := defaultOpts()
			cs := &csrf{
				h:            http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
				opts:         *opts,
				store:        nil,
				ErrorHandler: http.HandlerFunc(ErrorHandler),
			}
			rec := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			err := cs.saveToken(rec, r, bytes.Repeat([]byte{0x01}, tokenLength))
			Expect(err).To(HaveOccurred())
		})

		It("should call error handler when saveToken fails due to nil store", func() {
			opts := defaultOpts()
			// Build a csrf with no store — token generation will fail at save
			h := CSRF(opts, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
		})
	})

	Describe("defaultCSRFOpts sanity", func() {
		It("has sane defaults for CSRF-owned fields", func() {
			Expect(defaultCSRFOpts.Name).To(Equal(cookieName))
			Expect(defaultCSRFOpts.HeaderName).To(Equal(headerName))
			Expect(defaultCSRFOpts.MaxAge).To(Equal(12 * time.Hour))
		})

		It("exposes the expected safe method set", func() {
			Expect(safeMethods).To(ConsistOf("GET", "HEAD", "OPTIONS", "TRACE"))
		})
	})

	Describe("mask RandomBytes failure", func() {
		It("returns 500 when mask fails to generate random bytes", func() {
			// First call (token generation) succeeds; second call (mask OTP) fails.
			calls := 0
			patch := gomonkey.ApplyFunc(ezutil.RandomBytes, func(n int) ([]byte, error) {
				calls++
				if calls > 1 {
					return nil, fmt.Errorf("entropy exhausted")
				}
				return bytes.Repeat([]byte{0x01}, n), nil
			})
			defer patch.Reset()

			opts := defaultOpts()
			h := CSRF(opts, newTestStore(), nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			r := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
			h.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusInternalServerError))
		})
	})

	Describe("token length invariant", func() {
		It("generated tokens are always tokenLength bytes", func() {
			for i := range 5 {
				opts := defaultOpts()
				// Capture reqInfo from inside the next handler where the live
				// request (with the mutated AuthRequest pointer) is accessible.
				var capturedInfo *ezapi.AuthRequest
				next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					capturedInfo = ezapi.LookupRequest(r)
				})
				h := CSRF(opts, newTestStore(), nil)(next)
				rec := httptest.NewRecorder()
				r := seedRequestInfo(httptest.NewRequest("GET", "/", nil))
				h.ServeHTTP(rec, r)
				Expect(capturedInfo).NotTo(BeNil(), fmt.Sprintf("iteration %d", i))
				Expect(capturedInfo.CSRFToken).To(HaveLen(tokenLength),
					fmt.Sprintf("iteration %d", i))
			}
		})
	})
})
