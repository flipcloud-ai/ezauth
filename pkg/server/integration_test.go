package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	xwmiddleware "github.com/flipcloud-ai/ezauth/pkg/middleware"
	"github.com/flipcloud-ai/ezauth/pkg/server/rbac"
	eztmpl "github.com/flipcloud-ai/ezauth/pkg/server/templates"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

// newTestSessionStore returns a cookie session store wired with a test secret.
func newTestSessionStore() sessions.SessionStore {
	store, err := sessions.NewSessionStore(&ezcfg.Session{
		Cookie: ezcfg.CookieStoreOptions{
			Name:     "_ez_proxy",
			Secret:   ezcfg.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
			Path:     "/",
			HTTPOnly: testutils.BoolPtr(true),
		},
	})
	ExpectWithOffset(1, err).ToNot(HaveOccurred())
	return store
}

// newMiddlewareTestServer builds a minimal *Server for middleware-chain tests.
// overrides is applied last so individual tests can override fields.
func newMiddlewareTestServer(overrides func(*Server)) *Server {
	logger, _ := testutils.SetupTestLogger()
	s := &Server{
		ServeCfg: ezcfg.ServerConfig{
			AuthPrefix:            "/ezauth",
			StaticPrefix:          "/static",
			TrustForwardedHeaders: testutils.BoolPtr(true),
		},
		AuthCfg:       ezcfg.AuthConfig{},
		adminUsername: fallbackAdminUser,
		Logger:        logger,
	}
	if overrides != nil {
		overrides(s)
	}
	return s
}

// spySessionStore wraps a real SessionStore and records whether Load was called.
type spySessionStore struct {
	sessions.SessionStore
	loadCalled bool
}

func (sp *spySessionStore) Load(req *http.Request) (*ezapi.Session, error) {
	sp.loadCalled = true
	return sp.SessionStore.Load(req)
}

// stubRBACController is a minimal rbac.Controller implementation for tests.
// EnforceRequest records each call via the provided hook; all other methods
// are no-ops so the stub satisfies the interface without a real database.
type stubRBACController struct {
	onEnforce func(req *http.Request) (bool, error)
}

func (s *stubRBACController) EnforceRequest(req *http.Request) (bool, error) {
	if s.onEnforce != nil {
		return s.onEnforce(req)
	}
	return true, nil
}
func (s *stubRBACController) RouteWalk(_ *mux.Router) error { return nil }
func (s *stubRBACController) SeedDefaults() error           { return nil }

func (s *stubRBACController) ListPermissions(_ context.Context, _ string, _, _ int) (map[string][]*models.Permission, error) {
	return nil, nil
}
func (s *stubRBACController) GetPermission(_ context.Context, _ string) (*models.Permission, error) {
	return nil, nil
}
func (s *stubRBACController) AddPermission(_ context.Context, _ *models.Permission) error {
	return nil
}
func (s *stubRBACController) UpdatePermission(_ context.Context, _ *models.Permission) error {
	return nil
}
func (s *stubRBACController) DeletePermission(_ context.Context, _ string) error { return nil }

func (s *stubRBACController) ListPolicies(_ context.Context, _, _ int) ([]*models.Policy, error) {
	return nil, nil
}
func (s *stubRBACController) GetPolicy(_ context.Context, _ string) (*models.Policy, error) {
	return nil, nil
}
func (s *stubRBACController) AddPolicy(_ context.Context, _ *models.Policy) error { return nil }
func (s *stubRBACController) UpdatePolicy(_ context.Context, _ string, _ *models.Policy) error {
	return nil
}
func (s *stubRBACController) DeletePolicy(_ context.Context, _ string) error { return nil }

func (s *stubRBACController) ListRoles(_ context.Context, _, _ int) ([]*models.RoleDB, error) {
	return nil, nil
}
func (s *stubRBACController) GetRole(_ context.Context, _ string) (*models.RoleDB, error) {
	return nil, nil
}
func (s *stubRBACController) AddRole(_ context.Context, _ *models.RoleDB) error { return nil }
func (s *stubRBACController) UpdateRole(_ context.Context, _ string, _ *models.RoleDB) error {
	return nil
}
func (s *stubRBACController) DeleteRole(_ context.Context, _ string) error { return nil }

func (s *stubRBACController) AddRoleToUser(_ context.Context, _ string, _ []string) error {
	return nil
}
func (s *stubRBACController) RemoveRoleFromUser(_ context.Context, _ string, _ []string) error {
	return nil
}
func (s *stubRBACController) AddRoleToGroup(_ context.Context, _ string, _ []string) error {
	return nil
}
func (s *stubRBACController) RemoveRoleFromGroup(_ context.Context, _ string, _ []string) error {
	return nil
}

func (s *stubRBACController) GetUserPermissions(_ context.Context, _ string) ([]*models.Permission, error) {
	return nil, nil
}
func (s *stubRBACController) GetGroupPermissions(_ context.Context, _ string) ([]*models.Permission, error) {
	return nil, nil
}
func (s *stubRBACController) GetRolePermissions(_ context.Context, _ string) ([]*models.Permission, error) {
	return nil, nil
}

// preAuthedRequest builds a GET request to path with a pre-injected session for
// the bootstrap root user, bypassing LoadSession's cookie lookup. Gate and
// AdminGate (no-DB static mode) both pass for this identity.
func preAuthedRequest(path string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	info := &ezapi.AuthRequest{
		RequestID: "test-id",
		Session: &ezapi.Session{
			Profile:   ezapi.Profile{User: fallbackAdminUser, IDType: ezapi.UserIDType},
			ExpiresOn: time.Now().Add(time.Hour).Unix(),
		},
	}
	return ezapi.AddRequestInfo(req, info)
}

var _ rbac.Controller = (*stubRBACController)(nil)

var _ = Describe("Middleware chain integration", func() {

	Describe("buildPreAuthMiddlewares", func() {
		// InitSession must run before RequestLogger so that RequestLogger can
		// embed the request_id in the context logger. If the order is reversed,
		// RequestLogger reads an empty RequestID and the log entry has no
		// request_id field. We verify this by capturing log output with an
		// observer and checking that request_id is non-empty after the chain runs.
		It("should run InitSession before RequestLogger so request_id is present in the context logger", func() {
			core, logs := observer.New(zap.InfoLevel)
			observedLogger := ezlog.New(zap.New(core))

			s := newMiddlewareTestServer(func(s *Server) {
				s.Logger = observedLogger
			})
			chain := s.buildPreAuthMiddlewares()

			h := chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Emit a log entry through the request-scoped logger that
				// RequestLogger installed. The entry carries request_id only
				// if InitSession has already run and populated RequestID.
				ezlog.FromContext(req.Context()).Info("probe")
				rw.WriteHeader(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			h.ServeHTTP(rec, req)

			Expect(logs.Len()).To(Equal(1))
			entry := logs.All()[0]
			var requestID string
			for _, f := range entry.Context {
				if f.Key == "request_id" {
					requestID = f.String
					break
				}
			}
			Expect(requestID).NotTo(BeEmpty(),
				"request_id must be non-empty in the context logger; "+
					"if InitSession ran after RequestLogger the field would be empty")
		})

		It("should not add CSRF middleware when CSRF is disabled", func() {
			s := newMiddlewareTestServer(func(s *Server) {
				s.AuthCfg.Session.CSRF.Enabled = false
			})
			chain := s.buildPreAuthMiddlewares()

			h := chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			h.ServeHTTP(rec, req)

			Expect(rec.Header().Get("Vary")).NotTo(ContainSubstring("Cookie"))
		})

		It("should add CSRF middleware when CSRF is enabled", func() {
			s := newMiddlewareTestServer(func(s *Server) {
				s.AuthCfg.Session.CSRF = ezcfg.CSRFConfig{
					Enabled:    true,
					Name:       "_xw_csrf",
					HeaderName: "X-CSRF-Token",
					Secret:     ezcfg.NewResolvedSecretRef([]byte("csrfsecret0123456789012345678901")),
					MaxAge:     12 * time.Hour,
				}
				s.sessionStore = newTestSessionStore()
			})
			chain := s.buildPreAuthMiddlewares()

			h := chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
			h.ServeHTTP(rec, req)

			Expect(rec.Header().Get("Vary")).To(ContainSubstring("Cookie"))
		})

		DescribeTable("RedirectToHTTPS conditional behaviour",
			func(forceHTTPS, tlsEnable bool, expectRedirect bool) {
				s := newMiddlewareTestServer(func(s *Server) {
					s.ServeCfg.ForceHTTPS = forceHTTPS
					s.ServeCfg.TLS.Enabled = tlsEnable
					s.ServeCfg.Port = 8443
				})
				chain := s.buildPreAuthMiddlewares()

				h := chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusOK)
				})

				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
				h.ServeHTTP(rec, req)

				if expectRedirect {
					Expect(rec.Code).To(Equal(http.StatusPermanentRedirect))
					Expect(rec.Header().Get("Location")).To(ContainSubstring("https://"))
				} else {
					Expect(rec.Code).To(Equal(http.StatusOK))
				}
			},
			Entry("both ForceHTTPS and TLS enabled", true, true, true),
			Entry("ForceHTTPS enabled but TLS disabled", true, false, false),
			Entry("ForceHTTPS disabled but TLS enabled", false, true, false),
			Entry("neither ForceHTTPS nor TLS enabled", false, false, false),
		)
	})

	Describe("buildSessionMiddlewares", func() {
		// Favicon must be first in the session chain so that /favicon.ico
		// requests are short-circuited before LoadSession is called. If the
		// order were reversed, LoadSession would run on every favicon request.
		It("should run Favicon before LoadSession so LoadSession is never called for /favicon.ico", func() {
			spy := &spySessionStore{SessionStore: newTestSessionStore()}
			s := newMiddlewareTestServer(func(s *Server) {
				s.sessionStore = spy
			})
			chain := s.buildSessionMiddlewares()

			h := chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
			h.ServeHTTP(rec, req)

			Expect(rec.Code).To(Equal(http.StatusFound))
			Expect(spy.loadCalled).To(BeFalse(),
				"LoadSession must not be called for /favicon.ico; "+
					"if Favicon ran after LoadSession the session store would be hit unnecessarily")
		})

	})

	Describe("buildServeMux", func() {
		// Authorization is appended to adminChain (buildSessionMiddlewares +
		// AdminGate) only when s.rbacController is non-nil. If someone removes
		// that guard, EnforceRequest would be called even without RBAC configured,
		// leading to a nil-pointer dereference or unnecessary overhead on every
		// admin path request.
		It("should append Authorization middleware to admin chain only when rbacController is set", func() {
			store := newTestSessionStore()

			enforceCalled := false
			stub := &stubRBACController{
				onEnforce: func(_ *http.Request) (bool, error) {
					enforceCalled = true
					return true, nil
				},
			}

			sWithout := newMiddlewareTestServer(func(s *Server) {
				s.sessionStore = store
			})
			rend, _, _ := eztmpl.New("", "")
			sWithout.renderer = rend
			sWithout.buildServeMux()

			sWith := newMiddlewareTestServer(func(s *Server) {
				s.sessionStore = store
				s.rbacController = stub
			})
			sWith.renderer = rend
			sWith.buildServeMux()

			enforceCalled = false
			rec1 := httptest.NewRecorder()
			sWith.ServeMux.ServeHTTP(rec1, preAuthedRequest("/ezauth/users/"))
			Expect(enforceCalled).To(BeTrue(), "Authorization middleware must run when rbacController is set")

			enforceCalled = false
			rec2 := httptest.NewRecorder()
			sWithout.ServeMux.ServeHTTP(rec2, preAuthedRequest("/ezauth/users/"))
			Expect(enforceCalled).To(BeFalse(), "Authorization middleware must not run when rbacController is nil")
		})
	})

	Describe("wrapSkipAuth", func() {
		It("should bypass CSRF and session chain for configured skip-auth paths", func() {
			upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
				_, _ = rw.Write([]byte("upstream ok"))
			}))
			defer upstream.Close()

			upstreamURL, _ := url.Parse(upstream.URL)

			s := newMiddlewareTestServer(func(s *Server) {
				s.AuthCfg.Session.CSRF = ezcfg.CSRFConfig{
					Enabled:    true,
					Name:       "_xw_csrf",
					HeaderName: "X-CSRF-Token",
					Secret:     ezcfg.NewResolvedSecretRef([]byte("csrfsecret0123456789012345678901")),
					MaxAge:     12 * time.Hour,
				}
				s.sessionStore = newTestSessionStore()
				s.AuthCfg.Proxy.SkipAuthPaths = []ezcfg.SkipAuthConfig{
					{Path: "/webhook", Match: "exact"},
				}
				s.revProxy = newProxy(httputil.NewSingleHostReverseProxy(upstreamURL), s.AuthCfg.Proxy.SkipAuthPaths)
			})

			skipRend, _, _ := eztmpl.New("", "")
			s.renderer = skipRend
			s.buildServeMux()

			handler := xwmiddleware.NewChain(xwmiddleware.Recovery(s.Logger), s.wrapSkipAuth).Then(s.ServeMux)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("payload=test"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			handler.ServeHTTP(rec, req)

			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(ContainSubstring("upstream ok"))
		})

		// When no skip-auth paths are configured (or proxy is nil), wrapSkipAuth
		// returns next unchanged so there is zero overhead for the common case.
		// A direct call through the returned handler must reach the main mux.
		It("should pass through to the main mux when no skip-auth paths are configured", func() {
			s := newMiddlewareTestServer(nil)
			noSkipRend, _, _ := eztmpl.New("", "")
			s.renderer = noSkipRend
			s.buildServeMux()

			handler := xwmiddleware.NewChain(xwmiddleware.Recovery(s.Logger), s.wrapSkipAuth).Then(s.ServeMux)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("payload=test"))
			handler.ServeHTTP(rec, req)

			// Without skip-auth configured, wrapSkipAuth returns next unchanged.
			// The request reaches the main mux, which returns 404 for
			// unregistered paths when no proxy is configured.
			Expect(rec.Code).To(Equal(http.StatusNotFound))
		})
	})
})
