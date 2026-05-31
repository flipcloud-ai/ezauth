package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/agiledragon/gomonkey/v2"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	middleware "github.com/flipcloud-ai/ezauth/pkg/middleware"
	eztmpl "github.com/flipcloud-ai/ezauth/pkg/server/templates"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap/zaptest/observer"
)

func randInt() int {
	const max = 65535
	return 1024 + rand.Intn(max-1024)
}

var _ = Describe("Server Module Test Suite", func() {
	When("server unit test", func() {
		defaultTemplate := testutils.LoadFromConfig("empty.yaml")
		invalidPath := defaultTemplate
		invalidPath.Server.TemplatePath = "/not_exist"
		u, _ := url.Parse("https://www.invalid.com")
		It("clean cache middleware test", func(ctx SpecContext) {
			rec := httptest.NewRecorder()
			r, err := http.NewRequest("GET", "/", nil)
			noCacheMiddleware(http.DefaultServeMux).ServeHTTP(rec, r)
			Expect(err).To(BeNil())
			for k, v := range noCacheHeaders {
				Expect(rec.Result().Header[k][0]).To(Equal(v))
			}
		})
		DescribeTableSubtree("server start test", func(opts ezcfg.Options, hasErr bool, e error) {
			var ctx context.Context
			var cancel context.CancelFunc
			var err error
			logger, _ := testutils.SetupTestLogger()
			BeforeEach(func() {
				ctx, cancel = context.WithCancel(context.Background())
				opts.Server.Port = randInt()
				s := &Server{
					ServeCfg: opts.Server,
					Logger:   logger,
				}

				go func() {
					time.Sleep(1 * time.Second)
					cancel()
				}()
				err = s.Start(ctx, opts)
			})
			It("match error", func() {
				if hasErr {
					Expect(err).NotTo(BeNil())
					Expect(errors.Is(err, http.ErrServerClosed)).To(BeFalse())
					if e != nil {
						Expect(errors.Is(err, e)).To(BeTrue())
					}
				} else {
					Expect(errors.Is(err, http.ErrServerClosed)).To(BeTrue())
					Expect(err.Error()).To(ContainSubstring("http: Server closed"))
				}
			})
		},
			Entry("empty configuration", ezcfg.Options{Audit: ezcfg.AuditConfig{Enabled: testutils.BoolPtr(true)}}, true, nil),
			// A provider that fails OIDC discovery (e.g. unreachable IdP) is now
			// non-fatal: the server starts successfully and logs a warning instead.
			// The periodic cache refresh will retry the failed provider.
			Entry("provider init failure is non-fatal", ezcfg.Options{
				Server: ezcfg.ServerConfig{
					Port:                  9999,
					TrustForwardedHeaders: testutils.BoolPtr(true),
				},
				Audit: ezcfg.AuditConfig{Enabled: testutils.BoolPtr(true)},
				Auth: ezcfg.AuthConfig{
					Provider: []*ezcfg.ProviderConfig{
						{
							ProviderName: "lalala",
							OIDCConfig: ezcfg.OIDCConfig{
								Issuer: u,
							},
						},
					},
					Session: ezcfg.Session{
						Cookie: ezcfg.CookieStoreOptions{
							Minimal:  false,
							Name:     "_ez_proxy",
							Secret:   ezcfg.NewResolvedSecretRef([]byte("cookiesecret0321")),
							Domains:  []string{"www.test123.com"},
							Path:     "/",
							Expire:   2 * time.Hour,
							Refresh:  2 * time.Hour,
							MaxAge:   2 * time.Hour,
							Secure:   true,
							HTTPOnly: testutils.BoolPtr(true),
							SameSite: "strict",
						},
					},
				},
			}, false, nil),
			Entry("not exist template path falls back to embedded defaults", invalidPath, false, nil),
			Entry("default configuration", defaultTemplate, false, nil),
			Entry("https configuration", testutils.LoadFromConfig("https.yaml"), false, nil),
			Entry("http2 configuration", testutils.LoadFromConfig("http2.yaml"), false, nil),
			Entry("invalid cipher", testutils.LoadFromConfig("tls_error/invalid_cipher.yaml"), true, nil),
			Entry("invalid version", testutils.LoadFromConfig("tls_error/invalid_tls_version.yaml"), true, nil),
			Entry("tls not exist", testutils.LoadFromConfig("tls_error/tls_cert_not_exist.yaml"), true, nil),
			Entry("standard configuration", testutils.LoadFromConfig("standard.yaml"), false, nil),
		)
	})
	When("cookie secure auto-downgrade with TLS disabled", func() {
		var s *Server
		var opts ezcfg.Options
		var logs *observer.ObservedLogs
		BeforeEach(func() {
			var logger ezlog.Logger
			logger, logs = testutils.SetupLogsCapture()
			opts = ezcfg.Options{
				Server: ezcfg.ServerConfig{
					Port:                  randInt(),
					Hostname:              "localhost",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				},
				Auth: ezcfg.AuthConfig{
					Session: ezcfg.Session{
						Cookie: ezcfg.CookieStoreOptions{
							Name:   "_ez_proxy",
							Secret: ezcfg.NewResolvedSecretRef([]byte("test-secret")),
						},
					},
				},
				Audit: ezcfg.AuditConfig{Enabled: testutils.BoolPtr(true)},
			}
			s = &Server{
				ServeCfg: opts.Server,
				Logger:   logger,
			}
		})
		DescribeTable("cookie.secure auto-downgrade",
			func(inputSecure, tlsEnabled, wantSecure bool, wantLogCount int) {
				ctx, cancel := context.WithCancel(context.Background())
				opts.Auth.Session.Cookie.Secure = inputSecure
				s.ServeCfg.TLS.Enabled = tlsEnabled
				go func() { time.Sleep(100 * time.Millisecond); cancel() }()
				_ = s.Start(ctx, opts)
				Expect(s.AuthCfg.Session.Cookie.Secure).To(Equal(wantSecure))
				Expect(logs.FilterMessageSnippet("automatically setting cookie.secure=false").Len()).To(Equal(wantLogCount))
			},
			Entry("TLS off, secure=true  → downgraded, log emitted", true, false, false, 1),
			Entry("TLS off, secure=false → unchanged, no log", false, false, false, 0),
			Entry("TLS on,  secure=true  → unchanged, no log", true, true, true, 0),
			Entry("TLS on,  secure=false → unchanged, no log", false, true, false, 0),
		)
	})
	When("cleanupServer unit test", func() {
		It("returns nil when both Shutdown and Close succeed", func() {
			logger, _ := testutils.SetupTestLogger()
			srv := &fakeServer{}
			cache := &fakeCache{}
			err := cleanupServer(context.Background(), srv, cache, logger)
			Expect(err).To(BeNil())
		})
		It("returns shutdown error when Shutdown fails", func() {
			logger, _ := testutils.SetupTestLogger()
			shutdownErr := errors.New("shutdown failed")
			srv := &fakeServer{err: shutdownErr}
			cache := &fakeCache{}
			err := cleanupServer(context.Background(), srv, cache, logger)
			Expect(err).To(MatchError(shutdownErr))
		})
		It("returns close error when Close fails", func() {
			logger, _ := testutils.SetupTestLogger()
			closeErr := errors.New("close failed")
			srv := &fakeServer{}
			cache := &fakeCache{err: closeErr}
			err := cleanupServer(context.Background(), srv, cache, logger)
			Expect(err).To(MatchError(closeErr))
		})
		It("returns shutdown error when both fail", func() {
			logger, _ := testutils.SetupTestLogger()
			shutdownErr := errors.New("shutdown failed")
			closeErr := errors.New("close failed")
			srv := &fakeServer{err: shutdownErr}
			cache := &fakeCache{err: closeErr}
			err := cleanupServer(context.Background(), srv, cache, logger)
			Expect(err).To(MatchError(shutdownErr))
		})
	})
})

type fakeServer struct {
	err error
}

func (f *fakeServer) Shutdown(_ context.Context) error { return f.err }

type fakeCache struct {
	err error
}

func (f *fakeCache) Close() error { return f.err }

var _ = Describe("Proxy enabled/disabled", func() {
	When("proxy enabled configuration", func() {
		It("should build proxy when IsEnabled returns true", func() {
			logger, _ := testutils.SetupTestLogger()
			enabled := true
			s := &Server{
				ServeCfg: ezcfg.ServerConfig{
					Hostname:              "localhost",
					Upstream:              &url.URL{Scheme: "http", Host: "127.0.0.1:8080"},
					TrustForwardedHeaders: testutils.BoolPtr(true),
				},
				AuthCfg: ezcfg.AuthConfig{
					Proxy: ezcfg.AuthProxyConfig{
						Enabled: &enabled,
					},
				},
				Logger: logger,
			}
			Expect(s.AuthCfg.Proxy.IsEnabled()).To(BeTrue())
			s.revProxy = newProxy(s.buildProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
			Expect(s.revProxy).NotTo(BeNil())
		})

		It("should build proxy by default when Enabled is nil", func() {
			logger, _ := testutils.SetupTestLogger()
			s := &Server{
				ServeCfg: ezcfg.ServerConfig{
					Hostname:              "localhost",
					Upstream:              &url.URL{Scheme: "http", Host: "127.0.0.1:8080"},
					TrustForwardedHeaders: testutils.BoolPtr(true),
				},
				AuthCfg: ezcfg.AuthConfig{},
				Logger:  logger,
			}
			Expect(s.AuthCfg.Proxy.IsEnabled()).To(BeTrue())
			s.revProxy = newProxy(s.buildProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
			Expect(s.revProxy).NotTo(BeNil())
		})
	})

	When("proxy disabled configuration", func() {
		It("should leave proxy nil when proxy is disabled", func() {
			logger, _ := testutils.SetupTestLogger()
			enabled := false
			opts := ezcfg.Options{
				Server: ezcfg.ServerConfig{
					Port:                  randInt(),
					Hostname:              "localhost",
					Upstream:              &url.URL{Scheme: "http", Host: "127.0.0.1:8080"},
					TrustForwardedHeaders: testutils.BoolPtr(true),
				},
				Auth: ezcfg.AuthConfig{
					Proxy: ezcfg.AuthProxyConfig{
						Enabled: &enabled,
					},
					Session: ezcfg.Session{
						Cookie: ezcfg.CookieStoreOptions{
							Name:   "_ez_proxy",
							Secret: ezcfg.NewResolvedSecretRef([]byte("test-secret")),
						},
					},
				},
				Audit: ezcfg.AuditConfig{Enabled: testutils.BoolPtr(true)},
			}
			s := &Server{
				ServeCfg: opts.Server,
				Logger:   logger,
			}
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				time.Sleep(100 * time.Millisecond)
				cancel()
			}()
			_ = s.Start(ctx, opts)
			Expect(s.revProxy).To(BeNil())
		})

		It("should register 404 handler for catch-all route in buildServeMux", func() {
			logger, _ := testutils.SetupTestLogger()
			enabled := false
			s := &Server{
				ServeCfg: ezcfg.ServerConfig{
					Hostname:              "localhost",
					Upstream:              &url.URL{Scheme: "http", Host: "127.0.0.1:8080"},
					AuthPrefix:            "/ezauth",
					StaticPrefix:          "/static",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				},
				AuthCfg: ezcfg.AuthConfig{
					Proxy: ezcfg.AuthProxyConfig{
						Enabled: &enabled,
					},
				},
				Logger: logger,
			}
			bsmRend, _, _ := eztmpl.New("", "")
			s.renderer = bsmRend
			s.buildServeMux()
			Expect(s.ServeMux).NotTo(BeNil())
			req := httptest.NewRequest("GET", "/some/random/path", nil)
			rec := httptest.NewRecorder()
			s.ServeMux.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusNotFound))
		})

	})
})

var _ = Describe("Server auth-only mode integration", func() {
	var (
		ctx        context.Context
		cancel     context.CancelFunc
		srvURL     string
		authPrefix string
		client     *http.Client
	)

	BeforeEach(func() {
		logger, _ := testutils.SetupTestLogger()
		opts := testutils.LoadFromConfig("standard.yaml")
		enabled := false
		opts.Auth.Proxy.Enabled = &enabled
		opts.Server.Port = randInt()
		authPrefix = opts.Server.AuthPrefix
		srvURL = fmt.Sprintf("http://localhost:%d", opts.Server.Port)

		ctx, cancel = context.WithCancel(context.Background())
		s := &Server{ServeCfg: opts.Server, Logger: logger}

		go func() { _ = s.Start(ctx, opts) }()

		client = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		Eventually(func() error {
			resp, err := http.Get(srvURL + "/healthz")
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			return nil
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	})

	AfterEach(func() {
		cancel()
	})

	// ── basic endpoints ──

	It("should serve health endpoint", func() {
		resp, err := client.Get(srvURL + "/healthz")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, _ := io.ReadAll(resp.Body)
		Expect(string(body)).To(ContainSubstring("Healthy"))
	})

	It("should serve robots.txt", func() {
		resp, err := client.Get(srvURL + "/robots.txt")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("should return 404 for unknown paths instead of redirecting to login", func() {
		resp, err := client.Get(srvURL + "/some/random/unknown/path")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
	})

	It("should render login page with HTML content", func() {
		resp, err := client.Get(srvURL + authPrefix + "/login")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, _ := io.ReadAll(resp.Body)
		Expect(string(body)).To(ContainSubstring("<form"))
		Expect(string(body)).To(ContainSubstring("username"))
	})

	It("should fail login with invalid credentials", func() {
		form := url.Values{"username": {"test"}, "password": {"wrong"}}
		req, _ := http.NewRequest("POST", srvURL+authPrefix+"/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
	})
})

var _ = Describe("Auth-only login response format", func() {
	// newServer sets up a minimal Server with sessionStore for auth-only login testing.
	newServer := func(jsonResponse bool) *Server {
		logger, _ := testutils.SetupTestLogger()
		store, err := sessions.NewSessionStore(&ezcfg.Session{
			Cookie: ezcfg.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   ezcfg.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
				Path:     "/",
				HTTPOnly: testutils.BoolPtr(true),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		enabled := false
		return &Server{
			AuthCfg: ezcfg.AuthConfig{
				JWT: ezcfg.JWTConfig{
					SecretKey: ezcfg.NewResolvedSecretRef([]byte("test-jwt-secret-key-32bytes-ok!!")),
				},
				Static: []ezcfg.PasswordConfig{
					{User: "test", Password: "test1234"},
				},
				Proxy: ezcfg.AuthProxyConfig{
					Enabled:      &enabled,
					JSONResponse: jsonResponse,
				},
			},
			Logger:       logger,
			sessionStore: store,
		}
	}

	doLogin := func(s *Server, acceptHeader string) *httptest.ResponseRecorder {
		form := url.Values{"username": {"test"}, "password": {"test1234"}}
		req := httptest.NewRequest("POST", "/ezauth/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if acceptHeader != "" {
			req.Header.Set("Accept", acceptHeader)
		}
		rec := httptest.NewRecorder()
		s.userPassLoginAuthOnly(rec, req)
		return rec
	}

	doFailingLogin := func(s *Server) *httptest.ResponseRecorder {
		form := url.Values{"username": {"test"}, "password": {"wrong"}}
		req := httptest.NewRequest("POST", "/ezauth/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		s.userPassLoginAuthOnly(rec, req)
		return rec
	}

	DescribeTable("login success response format",
		func(jsonResponse bool, accept string, expectCode int, expectBody string, expectContentType string) {
			s := newServer(jsonResponse)
			rec := doLogin(s, accept)

			Expect(rec.Code).To(Equal(expectCode))
			Expect(rec.Body.String()).To(ContainSubstring(expectBody))
			Expect(rec.Result().Cookies()).ToNot(BeEmpty())
			if expectContentType != "" {
				Expect(rec.Header().Get("Content-Type")).To(ContainSubstring(expectContentType))
			}
		},
		// json_response: false (default) — respects Accept header
		Entry("no json_response, browser Accept → HTML",
			false, "text/html,application/xhtml+xml", http.StatusOK, "Logged in", "text/html"),
		Entry("no json_response, API Accept → JSON",
			false, "application/json", http.StatusOK, "authenticated", "application/json"),
		Entry("no json_response, curl wildcard Accept → JSON",
			false, "*/*", http.StatusOK, "authenticated", "application/json"),
		Entry("no json_response, no Accept header → JSON",
			false, "", http.StatusOK, "authenticated", "application/json"),

		// json_response: true — forces JSON regardless of Accept
		Entry("json_response true, browser Accept → JSON (forced)",
			true, "text/html,application/xhtml+xml", http.StatusOK, "authenticated", "application/json"),
		Entry("json_response true, API Accept → JSON",
			true, "application/json", http.StatusOK, "authenticated", "application/json"),
		Entry("json_response true, no Accept → JSON",
			true, "", http.StatusOK, "authenticated", "application/json"),
	)

	It("should set session cookie with HttpOnly flag", func() {
		s := newServer(false)
		rec := doLogin(s, "text/html")
		cookies := rec.Result().Cookies()
		var sc *http.Cookie
		for _, c := range cookies {
			if c.Name == "_ez_proxy" {
				sc = c
				break
			}
		}
		Expect(sc).ToNot(BeNil())
		Expect(sc.HttpOnly).To(BeTrue())
		Expect(sc.Value).ToNot(BeEmpty())
	})

	It("should return 401 for invalid credentials regardless of json_response", func() {
		for _, jr := range []bool{false, true} {
			s := newServer(jr)
			rec := doFailingLogin(s)
			Expect(rec.Code).To(Equal(http.StatusUnauthorized))
		}
	})

	It("should return 200 with JSON even for XHR requests when json_response is true", func() {
		s := newServer(true)
		form := url.Values{"username": {"test"}, "password": {"test1234"}}
		req := httptest.NewRequest("POST", "/ezauth/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		rec := httptest.NewRecorder()
		s.userPassLoginAuthOnly(rec, req)

		Expect(rec.Code).To(Equal(http.StatusOK))
		Expect(rec.Body.String()).To(ContainSubstring("authenticated"))
	})
})

var _ = Describe("Recovery middleware wraps wrapSkipAuth", func() {
	// Verify that Recovery sits outside wrapSkipAuth so panics originating from
	// skip-auth path handlers are caught and result in a 500 rather than crashing.
	It("returns 500 when a skip-auth path handler panics", func() {
		logger, _ := testutils.SetupTestLogger()

		// Build a minimal Server with a skip-auth path configured.
		skipPath := "/webhook"
		enabled := true
		s := &Server{
			ServeCfg: ezcfg.ServerConfig{
				AuthPrefix:            "/ezauth",
				StaticPrefix:          "/static",
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: ezcfg.AuthConfig{
				Proxy: ezcfg.AuthProxyConfig{
					Enabled: &enabled,
					SkipAuthPaths: []ezcfg.SkipAuthConfig{
						{Path: skipPath, Match: "exact"},
					},
				},
			},
			Logger: logger,
		}

		// Install a reverse proxy that panics to simulate a misbehaving upstream
		// handler in the skip-auth chain.
		s.revProxy = newProxy(buildPanicProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
		panicRend, _, _ := eztmpl.New("", "")
		s.renderer = panicRend
		s.buildServeMux()

		// Wrap exactly as Start() does: Recovery outermost, then wrapSkipAuth.
		handler := middleware.Recovery(s.Logger)(s.wrapSkipAuth(s.ServeMux))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, skipPath, nil)
		handler.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusInternalServerError))
		Expect(rec.Body.String()).To(ContainSubstring("Internal Server Error"))
	})
})

// buildPanicProxy returns a *httputil.ReverseProxy whose director panics so
// that the test can verify Recovery catches panics from skip-auth path handlers.
func buildPanicProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			panic("simulated upstream panic")
		},
	}
}

var _ = Describe("CSRF error handler response format", func() {
	// newCSRFServer builds a minimal Server with CSRF enabled, a real session
	// store, and the templates loaded so respondError can render HTML pages.
	newCSRFServer := func(jsonResponse bool) http.Handler {
		logger, _ := testutils.SetupTestLogger()
		store, err := sessions.NewSessionStore(&ezcfg.Session{
			Cookie: ezcfg.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   ezcfg.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
				Path:     "/",
				HTTPOnly: testutils.BoolPtr(true),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		enabled := false
		csrfRend, _, err := eztmpl.New("", "")
		Expect(err).ToNot(HaveOccurred())
		s := &Server{
			ServeCfg: ezcfg.ServerConfig{
				AuthPrefix:            "/ezauth",
				StaticPrefix:          "/static",
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: ezcfg.AuthConfig{
				Proxy: ezcfg.AuthProxyConfig{
					Enabled:      &enabled,
					JSONResponse: jsonResponse,
				},
				Session: ezcfg.Session{
					CSRF: ezcfg.CSRFConfig{
						Enabled:    true,
						Name:       "_xw_csrf",
						HeaderName: "X-CSRF-Token",
						Secret:     ezcfg.NewResolvedSecretRef([]byte("csrfsecret0123456789012345678901")),
						MaxAge:     12 * time.Hour,
					},
				},
			},
			Logger:       logger,
			sessionStore: store,
			renderer:     csrfRend,
		}

		chain := s.buildPreAuthMiddlewares()
		h := chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("ok"))
		})
		return h
	}

	It("returns HTML 403 when browser POSTs without CSRF token and JSONResponse is false", func() {
		h := newCSRFServer(false)

		// First GET to obtain a valid CSRF session cookie.
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/ezauth/login", nil)
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		h.ServeHTTP(rec, r)
		Expect(rec.Code).To(Equal(http.StatusOK))
		csrfCookie := rec.Result().Cookies()[0]

		// POST with the session cookie but no CSRF token — browser Accept header.
		rec2 := httptest.NewRecorder()
		r2 := httptest.NewRequest("POST", "/ezauth/login", strings.NewReader("username=test&password=test"))
		r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r2.Header.Set("Accept", "text/html,application/xhtml+xml")
		r2.Header.Set("Origin", "http://"+r2.Host)
		r2.AddCookie(csrfCookie)
		h.ServeHTTP(rec2, r2)

		Expect(rec2.Code).To(Equal(http.StatusForbidden))
		Expect(rec2.Header().Get("Content-Type")).To(ContainSubstring("text/html"))
		Expect(rec2.Body.String()).To(ContainSubstring("Forbidden"))
	})

	It("returns JSON 403 when API client POSTs without CSRF token and JSONResponse is true", func() {
		h := newCSRFServer(true)

		// First GET to obtain a valid CSRF session cookie.
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/ezauth/login", nil)
		h.ServeHTTP(rec, r)
		Expect(rec.Code).To(Equal(http.StatusOK))
		csrfCookie := rec.Result().Cookies()[0]

		// POST with the session cookie but no CSRF token — JSONResponse forces JSON.
		rec2 := httptest.NewRecorder()
		r2 := httptest.NewRequest("POST", "/ezauth/login", strings.NewReader("username=test&password=test"))
		r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r2.Header.Set("Origin", "http://"+r2.Host)
		r2.AddCookie(csrfCookie)
		h.ServeHTTP(rec2, r2)

		Expect(rec2.Code).To(Equal(http.StatusForbidden))
		Expect(rec2.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		Expect(rec2.Body.String()).To(ContainSubstring("CSRF token"))
	})

	It("returns JSON 403 when API client sends application/json Accept and no CSRF token", func() {
		h := newCSRFServer(false)

		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/ezauth/login", nil)
		h.ServeHTTP(rec, r)
		Expect(rec.Code).To(Equal(http.StatusOK))
		csrfCookie := rec.Result().Cookies()[0]

		rec2 := httptest.NewRecorder()
		r2 := httptest.NewRequest("POST", "/ezauth/login", strings.NewReader("{}"))
		r2.Header.Set("Content-Type", "application/json")
		r2.Header.Set("Accept", "application/json")
		r2.Header.Set("Origin", "http://"+r2.Host)
		r2.AddCookie(csrfCookie)
		h.ServeHTTP(rec2, r2)

		Expect(rec2.Code).To(Equal(http.StatusForbidden))
		Expect(rec2.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		Expect(rec2.Body.String()).To(ContainSubstring("CSRF token"))
	})
})

var _ = Describe("Pprof endpoints", func() {
	newPprofServer := func(enabled bool) *Server {
		logger, _ := testutils.SetupTestLogger()
		return &Server{
			ServeCfg: ezcfg.ServerConfig{
				Hostname:              "localhost",
				StaticPrefix:          "/static",
				AuthPrefix:            "/ezauth",
				Pprof:                 ezcfg.PprofConfig{Enabled: enabled},
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: ezcfg.AuthConfig{},
			Logger:  logger,
		}
	}

	When("pprof is enabled", func() {
		It("should not serve pprof on the main mux", func() {
			s := newPprofServer(true)
			pprofRend, _, _ := eztmpl.New("", "")
			s.renderer = pprofRend
			s.buildServeMux()
			Expect(s.ServeMux).NotTo(BeNil())

			req := httptest.NewRequest("GET", "/debug/pprof/", nil)
			rec := httptest.NewRecorder()
			s.ServeMux.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusNotFound))
		})
	})

	When("pprof is disabled", func() {
		It("should return 404 for pprof path", func() {
			s := newPprofServer(false)
			pprofRend, _, _ := eztmpl.New("", "")
			s.renderer = pprofRend
			s.buildServeMux()
			Expect(s.ServeMux).NotTo(BeNil())

			req := httptest.NewRequest("GET", "/debug/pprof/", nil)
			rec := httptest.NewRecorder()
			s.ServeMux.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusNotFound))
		})
	})
})

var _ = Describe("Metrics endpoints", func() {
	var (
		ctx        context.Context
		cancel     context.CancelFunc
		srvURL     string
		metricsURL string
		client     *http.Client
	)

	When("metrics is enabled", func() {
		BeforeEach(func() {
			logger, _ := testutils.SetupTestLogger()
			opts := testutils.LoadFromConfig("standard.yaml")
			enabled := false
			opts.Auth.Proxy.Enabled = &enabled
			opts.Server.Port = randInt()
			metricsPort := randInt()
			srvURL = fmt.Sprintf("http://localhost:%d", opts.Server.Port)
			metricsURL = fmt.Sprintf("http://localhost:%d/metrics", metricsPort)
			opts.Server.Metrics = ezcfg.MetricsConfig{
				Enabled: true,
				Path:    "/metrics",
				Port:    metricsPort,
				Host:    "localhost",
			}

			ctx, cancel = context.WithCancel(context.Background())
			s := &Server{ServeCfg: opts.Server, Logger: logger}

			go func() { _ = s.Start(ctx, opts) }()

			client = &http.Client{Timeout: 5 * time.Second}

			Eventually(func() error {
				resp, err := client.Get(srvURL + "/healthz")
				if err != nil {
					return err
				}
				_ = resp.Body.Close()
				return nil
			}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
		})

		AfterEach(func() {
			cancel()
		})

		It("should serve metrics in Prometheus format", func() {
			resp, err := client.Get(metricsURL)
			Expect(err).ToNot(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(resp.Header.Get("Content-Type")).To(ContainSubstring("text/plain"))
			body, _ := io.ReadAll(resp.Body)
			Expect(string(body)).To(ContainSubstring("ezauth_"))
		})
	})

	When("metrics is disabled", func() {
		BeforeEach(func() {
			logger, _ := testutils.SetupTestLogger()
			opts := testutils.LoadFromConfig("standard.yaml")
			enabled := false
			opts.Auth.Proxy.Enabled = &enabled
			opts.Server.Port = randInt()
			metricsPort := randInt()
			srvURL = fmt.Sprintf("http://localhost:%d", opts.Server.Port)
			metricsURL = fmt.Sprintf("http://localhost:%d/metrics", metricsPort)
			opts.Server.Metrics = ezcfg.MetricsConfig{
				Enabled: false,
				Port:    metricsPort,
				Host:    "localhost",
			}

			ctx, cancel = context.WithCancel(context.Background())
			s := &Server{ServeCfg: opts.Server, Logger: logger}

			go func() { _ = s.Start(ctx, opts) }()

			client = &http.Client{Timeout: 2 * time.Second}

			Eventually(func() error {
				resp, err := client.Get(srvURL + "/healthz")
				if err != nil {
					return err
				}
				_ = resp.Body.Close()
				return nil
			}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
		})

		AfterEach(func() {
			cancel()
		})

		It("should not serve metrics", func() {
			_, err := client.Get(metricsURL)
			Expect(err).To(HaveOccurred())
		})
	})
})

// newPortalServer builds a minimal Server ready for portal tests.
func newPortalServer(rbacEnabled bool, auditEnabled bool) (*Server, error) {
	logger, err := testutils.SetupTestLogger()
	if err != nil {
		return nil, err
	}
	rend, _, err := eztmpl.New("", "")
	if err != nil {
		return nil, err
	}
	s := &Server{
		Logger:   logger,
		renderer: rend,
		ServeCfg: ezcfg.ServerConfig{
			AuthPrefix:            "/ezauth",
			StaticPrefix:          "/static",
			AppName:               "TestApp",
			TrustForwardedHeaders: testutils.BoolPtr(true),
		},
	}
	if rbacEnabled {
		// Assign a non-nil rbacController to enable RBAC pages.
		// We reuse setupRBACServer which already initialises a real controller.
		sWithRBAC := setupRBACServerWithConfig(logger, s.ServeCfg, nil)
		s.rbacController = sWithRBAC.rbacController
	}
	if auditEnabled {
		_, ac := newAuditTestLogger(50)
		s.auditCore = ac
	}
	return s, nil
}

var _ = Describe("newPortalData", func() {
	var s *Server

	BeforeEach(func() {
		var err error
		s, err = newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
	})

	It("returns '?' initials when session is nil", func() {
		req := httptest.NewRequest(http.MethodGet, "/portal/overview", nil)
		data := s.newPortalData(req, "overview")
		Expect(data.UserInitials).To(Equal("?"))
		Expect(data.Username).To(BeEmpty())
	})

	It("returns '?' initials when session user and preferred username are empty", func() {
		req := httptest.NewRequest(http.MethodGet, "/portal/overview", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{User: "", PreferredUsername: ""}}})
		data := s.newPortalData(req, "overview")
		Expect(data.UserInitials).To(Equal("?"))
	})

	It("uses the first character (uppercase) for a single-character username", func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{User: "a"}}})
		data := s.newPortalData(req, "overview")
		Expect(data.UserInitials).To(Equal("A"))
		Expect(data.Username).To(Equal("a"))
	})

	It("uses the first two characters (uppercase) for a longer username", func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{User: "alice"}}})
		data := s.newPortalData(req, "overview")
		Expect(data.UserInitials).To(Equal("AL"))
	})

	It("falls back to PreferredUsername when User is empty", func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{
			User: "", PreferredUsername: "bob",
		}}})
		data := s.newPortalData(req, "overview")
		Expect(data.Username).To(Equal("bob"))
		Expect(data.UserInitials).To(Equal("BO"))
	})

	It("populates AppName, AuthPrefix, StaticPrefix and ActivePage from config", func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		data := s.newPortalData(req, "users")
		Expect(data.AppName).To(Equal("TestApp"))
		Expect(data.AuthPrefix).To(Equal("/ezauth"))
		Expect(data.StaticPrefix).To(Equal("/static"))
		Expect(data.ActivePage).To(Equal("users"))
	})

	It("sets RBACEnabled=false when rbacController is nil", func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		data := s.newPortalData(req, "overview")
		Expect(data.RBACEnabled).To(BeFalse())
	})

	It("sets RBACEnabled=true when rbacController is set", func() {
		var err error
		s, err = newPortalServer(true, false)
		Expect(err).ToNot(HaveOccurred())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		data := s.newPortalData(req, "overview")
		Expect(data.RBACEnabled).To(BeTrue())
	})

	It("sets AuditEnabled=true when auditCore is set", func() {
		var err error
		s, err = newPortalServer(false, true)
		Expect(err).ToNot(HaveOccurred())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		data := s.newPortalData(req, "audit")
		Expect(data.AuditEnabled).To(BeTrue())
	})

	It("sets LogoData from renderer logo", func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		data := s.newPortalData(req, "overview")
		Expect(data.LogoData).To(Equal(s.renderer.Logo()))
		Expect(string(data.LogoData)).NotTo(BeEmpty())
	})
})

var _ = Describe("renderPortalPage", func() {
	It("returns 500 when the requested template does not exist", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		s.renderPortalPage(rr, req, "admin/nonexistent.html", "overview")
		Expect(rr.Code).To(Equal(http.StatusInternalServerError))
	})

	It("returns 500 when template execution fails", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())

		// Patch Execute to simulate a template execution failure.
		patch := gomonkey.ApplyMethod(&template.Template{}, "Execute", func(_ *template.Template, _ io.Writer, _ any) error {
			return errors.New("simulated execute failure")
		})
		defer patch.Reset()

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		s.renderPortalPage(rr, req, "admin/overview.html", "overview")
		Expect(rr.Code).To(Equal(http.StatusInternalServerError))
	})

	DescribeTable("renders each admin page with correct Content-Type and HTML structure",
		func(tmplName, activePage, bodyContains string) {
			s, err := newPortalServer(true, true)
			Expect(err).ToNot(HaveOccurred())

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/portal/"+activePage, nil)
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{User: "admin"}}})
			s.renderPortalPage(rr, req, tmplName, activePage)

			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Header().Get("Content-Type")).To(Equal("text/html; charset=utf-8"))
			// Cache-control must be set by noCacheHeader.
			Expect(rr.Header().Get("Cache-Control")).To(ContainSubstring("no-cache"))
			body := rr.Body.String()
			Expect(body).To(ContainSubstring(bodyContains))
		},
		Entry("overview", "admin/overview.html", "overview", "Overview"),
		Entry("users", "admin/users.html", "users", "Users"),
		Entry("groups", "admin/groups.html", "groups", "Groups"),
		Entry("roles", "admin/roles.html", "roles", "Roles"),
		Entry("policies", "admin/policies.html", "policies", "Policies"),
		Entry("providers", "admin/providers.html", "providers", "Providers"),
		Entry("audit", "admin/audit.html", "audit", "Audit"),
		Entry("profile", "admin/profile.html", "profile", "Profile"),
		Entry("tokens", "admin/tokens.html", "tokens", "Access Tokens"),
	)

	It("injects AppName into rendered HTML", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
		s.ServeCfg.AppName = "MyPortal"

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		s.renderPortalPage(rr, req, "admin/overview.html", "overview")
		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Body.String()).To(ContainSubstring("MyPortal"))
	})

	It("sets no-store and no-cache headers", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		s.renderPortalPage(rr, req, "admin/overview.html", "overview")

		Expect(rr.Header().Get("Cache-Control")).To(ContainSubstring("no-store"))
	})
})

var _ = Describe("portalRouter", func() {
	// newRouter mounts the portalRouter on a gorilla mux, simulating the
	// production subrouter path prefix /ezauth/portal.
	newRouter := func(s *Server) *mux.Router {
		r := mux.NewRouter()
		sub := r.PathPrefix("/ezauth/portal").Subrouter()
		s.portalRouter(sub)
		return r
	}

	DescribeTable("each portal page returns 200",
		func(path string) {
			s, err := newPortalServer(true, true)
			Expect(err).ToNot(HaveOccurred())
			r := newRouter(s)

			req := httptest.NewRequest(http.MethodGet, "/ezauth/portal"+path, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		},
		Entry("overview", "/overview"),
		Entry("users", "/users"),
		Entry("groups", "/groups"),
		Entry("roles", "/roles"),
		Entry("policies", "/policies"),
		Entry("providers", "/providers"),
		Entry("audit", "/audit"),
	)

	DescribeTable("redirects RBAC-only pages to overview when RBAC is disabled",
		func(path string) {
			s, err := newPortalServer(false, false)
			Expect(err).ToNot(HaveOccurred())
			r := newRouter(s)
			req := httptest.NewRequest(http.MethodGet, "/ezauth/portal"+path, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusFound))
			Expect(rr.Header().Get("Location")).To(Equal("/ezauth/portal/overview"))
		},
		Entry("/roles", "/roles"),
		Entry("/policies", "/policies"),
	)

	It("does NOT redirect /roles when RBAC is enabled", func() {
		s, err := newPortalServer(true, false)
		Expect(err).ToNot(HaveOccurred())
		r := newRouter(s)

		req := httptest.NewRequest(http.MethodGet, "/ezauth/portal/roles", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
	})

	It("redirects an unknown sub-path to overview", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
		r := newRouter(s)

		req := httptest.NewRequest(http.MethodGet, "/ezauth/portal/does-not-exist", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusFound))
		Expect(rr.Header().Get("Location")).To(Equal("/ezauth/portal/overview"))
	})

	It("renders the user initials in the page body", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
		r := newRouter(s)

		req := httptest.NewRequest(http.MethodGet, "/ezauth/portal/overview", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{User: "carol"}}})
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		body := rr.Body.String()
		// The template renders PORTAL_INITIALS as a JS constant.
		Expect(strings.Contains(body, "CA")).To(BeTrue())
	})

	It("renders AUTH_PREFIX correctly in the page script block", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
		r := newRouter(s)

		req := httptest.NewRequest(http.MethodGet, "/ezauth/portal/overview", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		// Go html/template escapes "/" as "\/" inside JS string context.
		Expect(rr.Body.String()).To(ContainSubstring(`AUTH_PREFIX = "\/ezauth"`))
	})
})

var _ = Describe("selfPortalRouter", func() {
	// newSelfRouter calls the real selfPortalRouter with a no-op chain so that
	// sessions injected via ezapi.AddRequestInfo pass through unmodified.
	newSelfRouter := func(s *Server) *mux.Router {
		r := mux.NewRouter()
		s.selfPortalRouter(r, "/ezauth", middleware.NewChain())
		return r
	}

	It("returns 200 for /portal/profile with a session", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
		r := newSelfRouter(s)

		req := httptest.NewRequest(http.MethodGet, "/ezauth/portal/profile", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{User: "alice"}}})
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Body.String()).To(ContainSubstring("Profile"))
	})

	It("returns 200 for /portal/tokens when DB is non-nil", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
		// Give the server a non-nil DB so the tokens page renders.
		sWithDB := setupUserServer(s.Logger, nil)
		sWithDB.renderer = s.renderer
		sWithDB.ServeCfg = s.ServeCfg
		r := newSelfRouter(sWithDB)

		req := httptest.NewRequest(http.MethodGet, "/ezauth/portal/tokens", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{Session: &ezapi.Session{Profile: ezapi.Profile{User: "alice"}}})
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Body.String()).To(ContainSubstring("Access Tokens"))
	})

	It("redirects /portal/tokens to /portal/profile when DB is nil", func() {
		s, err := newPortalServer(false, false)
		Expect(err).ToNot(HaveOccurred())
		// Ensure DB is nil.
		s.DB = nil
		r := newSelfRouter(s)

		req := httptest.NewRequest(http.MethodGet, "/ezauth/portal/tokens", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusFound))
		Expect(rr.Header().Get("Location")).To(Equal("/ezauth/portal/profile"))
	})
})

var _ = Describe("Swagger UI", func() {
	var (
		router     *mux.Router
		testLogger ezlog.Logger
	)

	BeforeEach(func() {
		var err error
		testLogger, err = testutils.SetupTestLogger()
		Expect(err).ToNot(HaveOccurred())

		t := testutils.LoadFromConfig("standard.yaml")
		s := &Server{
			ServeCfg: t.Server,
			Logger:   testLogger,
		}
		err = s.Providers(context.Background())
		Expect(err).ToNot(HaveOccurred())
		swaggerRend, _, _ := eztmpl.New("", "")
		s.renderer = swaggerRend
		s.buildServeMux()
		router = s.ServeMux
	})

	newRequest := func(method, path string) *http.Request {
		req, _ := http.NewRequest(method, path, nil)
		req.RequestURI = path // http-swagger uses RequestURI to parse path
		return req.WithContext(ezlog.RequestContext(req.Context(), testLogger))
	}

	Describe("GET /swagger", func() {
		It("should serve the Swagger UI index page", func() {
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, newRequest("GET", "/swagger/index.html"))
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	Describe("GET /swagger/doc.json", func() {
		var loadSpec func() map[string]interface{}

		BeforeEach(func() {
			loadSpec = func() map[string]interface{} {
				rr := httptest.NewRecorder()
				router.ServeHTTP(rr, newRequest("GET", "/swagger/doc.json"))
				Expect(rr.Code).To(Equal(http.StatusOK))
				var spec map[string]interface{}
				Expect(json.Unmarshal(rr.Body.Bytes(), &spec)).To(Succeed())
				return spec
			}
		})

		It("should return valid OpenAPI JSON", func() {
			spec := loadSpec()
			Expect(spec).To(HaveKey("swagger"))
			Expect(spec).To(HaveKey("info"))
			Expect(spec).To(HaveKey("paths"))
			info, ok := spec["info"].(map[string]interface{})
			Expect(ok).To(BeTrue(), "info should be a map")
			Expect(info["title"]).To(Equal("EzAuth API"))
		})

		It("should include all expected tag groups", func() {
			spec := loadSpec()
			// swag places tags inside path operations; collect them all.
			tagSet := make(map[string]bool)
			paths, ok := spec["paths"].(map[string]interface{})
			Expect(ok).To(BeTrue(), "paths should be a map")
			for _, pathItem := range paths {
				pi, ok := pathItem.(map[string]interface{})
				if !ok {
					continue
				}
				for _, method := range pi {
					op, ok := method.(map[string]interface{})
					if !ok {
						continue
					}
					tags, ok := op["tags"].([]interface{})
					if !ok {
						continue
					}
					for _, t := range tags {
						tagSet[t.(string)] = true
					}
				}
			}
			Expect(tagSet).To(HaveKey("Authentication"))
			Expect(tagSet).To(HaveKey("System"))
			Expect(tagSet).To(HaveKey("User Management"))
			Expect(tagSet).To(HaveKey("Group Management"))
			Expect(tagSet).To(HaveKey("Provider Management"))
		})

		It("should include all core auth endpoints", func() {
			paths := loadSpec()["paths"].(map[string]interface{})
			Expect(paths).To(HaveKey("/ezauth/login"))
			Expect(paths).To(HaveKey("/ezauth/logout"))
			Expect(paths).To(HaveKey("/ezauth/start"))
			Expect(paths).To(HaveKey("/ezauth/callback"))
			Expect(paths).To(HaveKey("/ezauth/verify"))
			Expect(paths).To(HaveKey("/healthz"))
			Expect(paths).To(HaveKey("/robots.txt"))
		})

		It("should include all admin endpoints", func() {
			paths := loadSpec()["paths"].(map[string]interface{})
			Expect(paths).To(HaveKey("/ezauth/users/"))
			Expect(paths).To(HaveKey("/ezauth/users/{uid}"))
			Expect(paths).To(HaveKey("/ezauth/users/{uid}/reset-password"))
			Expect(paths).To(HaveKey("/ezauth/users/{uid}/roles/assign"))
			Expect(paths).To(HaveKey("/ezauth/users/{uid}/roles/unassign"))
			Expect(paths).To(HaveKey("/ezauth/groups/"))
			Expect(paths).To(HaveKey("/ezauth/groups/{name}"))
			Expect(paths).To(HaveKey("/ezauth/groups/{name}/members/assign"))
			Expect(paths).To(HaveKey("/ezauth/groups/{name}/members/unassign"))
			Expect(paths).To(HaveKey("/ezauth/groups/{name}/roles/assign"))
			Expect(paths).To(HaveKey("/ezauth/groups/{name}/roles/unassign"))
			Expect(paths).To(HaveKey("/ezauth/provider/{name}"))
			Expect(paths).To(HaveKey("/ezauth/provider/"))
		})
	})

	Describe("Swagger UI without auth", func() {
		It("should be accessible without session cookie", func() {
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, newRequest("GET", "/swagger/index.html"))
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})
})

// newBootstrapMockServer creates a Server with a fresh sqlmock gorm.DB and
// returns both the Server and the mock for expectation setup.
func newBootstrapMockServer(logger ezlog.Logger, groupName string) (*Server, sqlmock.Sqlmock) {
	mockdb, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	Expect(err).ToNot(HaveOccurred())
	gormDB, err := gorm.Open(
		postgres.New(postgres.Config{Conn: mockdb, DriverName: "postgres"}),
		&gorm.Config{},
	)
	Expect(err).ToNot(HaveOccurred())

	mockPGx := &pgx.PGxDB{Database: database.Database{Logger: logger}}
	mockPGx.DB = gormDB

	s := &Server{
		Logger:           logger,
		DB:               mockPGx,
		systemAdminGroup: groupName,
	}
	return s, mock
}

var _ = Describe("Bootstrap", func() {
	var (
		ctx    context.Context
		logger ezlog.Logger
	)

	BeforeEach(func() {
		ctx = context.Background()
		logger, _ = testutils.SetupTestLogger()
	})

	Context("DB is nil", func() {
		It("returns immediately without touching DB", func() {
			s := &Server{Logger: logger}
			Expect(func() { s.Bootstrap(ctx, "/tmp/secret") }).ToNot(Panic())
		})
	})

	Context("full happy path — nothing exists yet", func() {
		It("creates root user, system admin group, and group membership", func() {
			dir := GinkgoT().TempDir()
			secretPath := filepath.Join(dir, "root.secret")
			rootID := uuid.New()

			s, mock := newBootstrapMockServer(logger, "system-admins")

			mock.ExpectQuery(`SELECT "id" FROM "users"`).
				WillReturnRows(mock.NewRows([]string{"id"}))

			mock.ExpectBegin()
			mock.ExpectQuery(`INSERT INTO "users"`).
				WillReturnRows(mock.NewRows([]string{"id"}).AddRow(rootID))
			mock.ExpectCommit()

			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WillReturnRows(mock.NewRows([]string{"id", "name", "created_at", "updated_at"}))

			mock.ExpectBegin()
			mock.ExpectQuery(`INSERT INTO "groups"`).
				WillReturnRows(mock.NewRows([]string{"id"}).AddRow(uuid.New()))
			mock.ExpectCommit()

			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WillReturnRows(mock.NewRows([]string{"id", "name", "created_at", "updated_at"}).
					AddRow(uuid.New(), "system-admins", "2020-01-01", "2020-01-01"))
			mock.ExpectQuery(`SELECT .* FROM "users"`).
				WillReturnRows(mock.NewRows([]string{"id"}))

			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WillReturnRows(mock.NewRows([]string{"id", "name", "created_at", "updated_at"}).
					AddRow(uuid.New(), "system-admins", "2020-01-01", "2020-01-01"))
			mock.ExpectQuery(`SELECT .* FROM "users"`).
				WillReturnRows(mock.NewRows([]string{"id"}).AddRow(rootID))
			mock.ExpectExec(`INSERT INTO "user_groups"`).WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()

			Expect(func() { s.Bootstrap(ctx, secretPath) }).ToNot(Panic())
		})
	})

	Context("idempotency — root user and group already exist", func() {
		It("skips creation steps and does not error", func() {
			dir := GinkgoT().TempDir()
			secretPath := filepath.Join(dir, "root.secret")
			existingID := uuid.New()

			s, mock := newBootstrapMockServer(logger, "system-admins")

			mock.ExpectQuery(`SELECT "id" FROM "users"`).
				WillReturnRows(mock.NewRows([]string{"id"}).AddRow(existingID))

			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WillReturnRows(mock.NewRows([]string{"id", "name", "created_at", "updated_at"}).
					AddRow(uuid.New(), "system-admins", "2020-01-01", "2020-01-01"))

			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WillReturnRows(mock.NewRows([]string{"id", "name", "created_at", "updated_at"}).
					AddRow(uuid.New(), "system-admins", "2020-01-01", "2020-01-01"))
			mock.ExpectQuery(`SELECT .* FROM "users"`).
				WillReturnRows(mock.NewRows([]string{"id"}).AddRow(existingID))

			Expect(func() { s.Bootstrap(ctx, secretPath) }).ToNot(Panic())
		})
	})
})
