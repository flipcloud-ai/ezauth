package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
	xwp "github.com/flipcloud-ai/ezauth/pkg/providers"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeStore implements sessions.SessionStore for testing
type fakeStore struct {
	session *ezapi.Session
	err     error
	saved   *ezapi.Session
	cleared bool
	saveErr error
}

func (f *fakeStore) Save(_ http.ResponseWriter, _ *http.Request, s *ezapi.Session) error {
	f.saved = s
	return f.saveErr
}
func (f *fakeStore) Load(_ *http.Request) (*ezapi.Session, error) { return f.session, f.err }
func (f *fakeStore) Clear(_ http.ResponseWriter, _ *http.Request) error {
	f.cleared = true
	return nil
}
func (f *fakeStore) VerifyConnection(_ context.Context) error { return nil }
func (f *fakeStore) SaveValue(_ http.ResponseWriter, _ *http.Request, _ []byte, _ *sessions.ValueOptions) error {
	return nil
}
func (f *fakeStore) LoadValue(_ *http.Request, _ *sessions.ValueOptions) ([]byte, error) {
	return nil, nil
}
func (f *fakeStore) DeleteValue(_ http.ResponseWriter, _ *http.Request, _ *sessions.ValueOptions) error {
	return nil
}

// fakeStoreWithClearErr wraps fakeStore but returns clearErr from Clear.
type fakeStoreWithClearErr struct {
	fakeStore
	clearErr error
}

func (f *fakeStoreWithClearErr) Clear(w http.ResponseWriter, r *http.Request) error {
	f.cleared = true
	return f.clearErr
}
func (f *fakeStore) Close() error { return nil }

// stubProvider embeds DefaultProvider and overrides RefreshSession / ProviderName for testing
type stubProvider struct {
	xwp.DefaultProvider
	name       string
	refreshErr error
	refreshed  bool
}

func (p *stubProvider) Callback(rw http.ResponseWriter, req *http.Request) error {
	return xwp.ErrNotImplemented
}
func (p *stubProvider) Redeem(ctx context.Context, _, _, _ string) (*ezapi.Session, error) {
	return nil, xwp.ErrNotImplemented
}
func (p *stubProvider) ProviderName() string { return url.QueryEscape(p.name) }

func (p *stubProvider) RefreshSession(_ context.Context, s *ezapi.Session) error {
	p.refreshed = true
	if p.refreshErr != nil {
		return p.refreshErr
	}
	s.AccessToken = "refreshed-access"
	s.RefreshToken = "refreshed-refresh"
	return nil
}

func newStubProvider(name string, refreshErr error) *stubProvider {
	return &stubProvider{name: name, refreshErr: refreshErr}
}

// newCacheResolver wraps a Cache as an xwp.ResolveFunc for use in tests.
func newCacheResolver(c ezcache.Cache[string, xwp.Provider]) xwp.ResolveFunc {
	if c == nil {
		return nil
	}
	return func(ctx context.Context, name string) xwp.Provider {
		p, err := c.Get(ctx, name)
		if err != nil {
			return nil
		}
		return p
	}
}

var _ = Describe("Session Refresh Middleware", func() {
	var (
		cache   ezcache.Cache[string, xwp.Provider]
		store   *fakeStore
		session *ezapi.Session
	)

	BeforeEach(func() {
		cache = ezcache.NewMemoryCache[string, xwp.Provider](10, 0)
		store = &fakeStore{}
		session = &ezapi.Session{
			AccessToken: "old-access",
		}
		session.CreatedAtNow()
		session.ExpiresIn(15 * time.Minute)
	})

	Describe("password / static session", func() {
		It("should pass through unchanged when NeedsRefresh is triggered", func() {
			session.IDType = ezapi.UserIDType
			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(newCacheResolver(cache), store)
			called := false
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).NotTo(BeNil())
				Expect(info.Session.AccessToken).To(Equal("old-access"))
				called = true
			}))

			r := httptest.NewRequest("GET", "/", nil)
			r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(called).To(BeTrue())
			Expect(store.saved).To(BeNil())
			Expect(store.cleared).To(BeFalse())
		})

		It("should pass through with empty IDType", func() {
			session.IDType = ""
			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(newCacheResolver(cache), store)
			called := false
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).NotTo(BeNil())
				called = true
			}))

			r := httptest.NewRequest("GET", "/", nil)
			r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(called).To(BeTrue())
			Expect(store.cleared).To(BeFalse())
		})
	})

	Describe("OAuth session refresh", func() {
		BeforeEach(func() {
			session.IDType = ezapi.OIDCUserIDType
			session.Provider = url.QueryEscape("test-oidc")
		})

		It("should clear session when no providers are configured (nil cache)", func() {
			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(nil, store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).To(BeNil())
			}))

			r := httptest.NewRequest("GET", "/", nil)
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(store.cleared).To(BeTrue())
		})

		It("should clear session when provider is not found in cache", func() {
			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).To(BeNil())
			}))

			r := httptest.NewRequest("GET", "/", nil)
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(store.cleared).To(BeTrue())
		})

		It("should clear session when Provider field is empty", func() {
			session.Provider = ""
			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).To(BeNil())
			}))

			r := httptest.NewRequest("GET", "/", nil)
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(store.cleared).To(BeTrue())
		})

		It("should refresh and persist session on success", func() {
			sp := newStubProvider("test-oidc", nil)
			err := cache.Set(context.Background(), sp.ProviderName(), sp, 0)
			Expect(err).ToNot(HaveOccurred())

			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).NotTo(BeNil())
				Expect(info.Session.AccessToken).To(Equal("refreshed-access"))
				Expect(info.Session.RefreshToken).To(Equal("refreshed-refresh"))
			}))

			r := httptest.NewRequest("GET", "/", nil)
			r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(sp.refreshed).To(BeTrue())
			Expect(store.saved).NotTo(BeNil())
			Expect(store.cleared).To(BeFalse())
		})

		It("should return refreshed session even when Save fails", func() {
			sp := newStubProvider("test-oidc", nil)
			err := cache.Set(context.Background(), sp.ProviderName(), sp, 0)
			Expect(err).ToNot(HaveOccurred())

			store.session = session
			store.err = sessions.ErrNeedsRefresh
			store.saveErr = errors.New("save failed")

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).NotTo(BeNil())
				Expect(info.Session.AccessToken).To(Equal("refreshed-access"))
			}))

			r := httptest.NewRequest("GET", "/", nil)
			r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(sp.refreshed).To(BeTrue())
			Expect(store.saved).NotTo(BeNil())
			Expect(store.cleared).To(BeFalse())
		})

		It("should keep session when refresh fails", func() {
			sp := newStubProvider("test-oidc", errors.New("refresh failed"))
			err := cache.Set(context.Background(), sp.ProviderName(), sp, 0)
			Expect(err).ToNot(HaveOccurred())

			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).ToNot(BeNil())
			}))

			r := httptest.NewRequest("GET", "/", nil)
			r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(sp.refreshed).To(BeTrue())
			Expect(store.cleared).To(BeFalse())
		})

		It("should use default provider when no specific provider matches", func() {
			sp := newStubProvider("other-provider", nil)
			// Store under "default" key, not matching session's provider
			err := cache.Set(context.Background(), "default", sp, 0)
			Expect(err).ToNot(HaveOccurred())

			session.Provider = "missing-provider"
			store.session = session
			store.err = sessions.ErrNeedsRefresh

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).To(BeNil())
			}))

			r := httptest.NewRequest("GET", "/", nil)
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(store.cleared).To(BeTrue())
		})
	})

	Describe("no session", func() {
		It("should leave Session nil when no cookie is present (ErrNoCookie)", func() {
			store.session = nil
			store.err = http.ErrNoCookie

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).To(BeNil())
			}))

			r := httptest.NewRequest("GET", "/", nil)
			handler.ServeHTTP(httptest.NewRecorder(), r)
			Expect(store.cleared).To(BeFalse())
		})
	})

	Describe("pre-existing session bypass", func() {
		It("should skip load when session is already set in context", func() {
			store.session = &ezapi.Session{AccessToken: "should-not-load"}
			store.err = nil

			mw := LoadSession(newCacheResolver(cache), store)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := ezapi.GetRequest(r)
				Expect(info.Session).NotTo(BeNil())
				Expect(info.Session.AccessToken).To(Equal("existing-token"))
			}))

			r := httptest.NewRequest("GET", "/", nil)
			r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{Session: &ezapi.Session{AccessToken: "existing-token"}})
			handler.ServeHTTP(httptest.NewRecorder(), r)
		})
	})
})

var _ = Describe("InitSession middleware", func() {
	It("should set request ID and trust flag when no prior AuthRequest exists", func() {
		patch := gomonkey.ApplyFunc(ezutils.NewRandomUUID, func() (string, error) {
			return "test-uuid-1234", nil
		})
		defer patch.Reset()

		mw := InitSession(true)
		var capturedInfo *ezapi.AuthRequest
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedInfo = ezapi.GetRequest(r)
		}))

		r := httptest.NewRequest("GET", "/", nil)
		handler.ServeHTTP(httptest.NewRecorder(), r)

		Expect(capturedInfo).NotTo(BeNil())
		Expect(capturedInfo.RequestID).To(Equal("test-uuid-1234"))
		Expect(capturedInfo.TrustForwardedHeaders).To(BeTrue())
	})

	It("should backfill missing RequestID on pre-existing AuthRequest", func() {
		patch := gomonkey.ApplyFunc(ezutils.NewRandomUUID, func() (string, error) {
			return "backfilled-uuid", nil
		})
		defer patch.Reset()

		mw := InitSession(false)
		var capturedInfo *ezapi.AuthRequest
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedInfo = ezapi.GetRequest(r)
		}))

		r := httptest.NewRequest("GET", "/", nil)
		r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{RequestID: ""})
		handler.ServeHTTP(httptest.NewRecorder(), r)

		Expect(capturedInfo.RequestID).To(Equal("backfilled-uuid"))
	})

	It("should not overwrite existing RequestID on pre-existing AuthRequest", func() {
		patch := gomonkey.ApplyFunc(ezutils.NewRandomUUID, func() (string, error) {
			return "new-uuid", nil
		})
		defer patch.Reset()

		mw := InitSession(false)
		var capturedInfo *ezapi.AuthRequest
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedInfo = ezapi.GetRequest(r)
		}))

		r := httptest.NewRequest("GET", "/", nil)
		r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{RequestID: "existing-id"})
		handler.ServeHTTP(httptest.NewRecorder(), r)

		Expect(capturedInfo.RequestID).To(Equal("existing-id"))
	})

	It("should return 500 when UUID generation fails", func() {
		patch := gomonkey.ApplyFunc(ezutils.NewRandomUUID, func() (string, error) {
			return "", errors.New("rand failure")
		})
		defer patch.Reset()

		mw := InitSession(false)
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		r := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		Expect(rec.Code).To(Equal(http.StatusInternalServerError))
	})
})

var _ = Describe("loadSession error paths", func() {
	It("should set session nil and log on transient (unknown) error", func() {
		store := &fakeStore{err: errors.New("transient db error")}

		mw := LoadSession(nil, store)
		var capturedSession *ezapi.Session
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedSession = ezapi.GetRequest(r).Session
		}))

		r := httptest.NewRequest("GET", "/", nil)
		r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
		handler.ServeHTTP(httptest.NewRecorder(), r)

		Expect(capturedSession).To(BeNil())
	})

	It("should clear session on ErrCorruptedSession", func() {
		store := &fakeStore{err: sessions.ErrCorruptedSession}

		mw := LoadSession(nil, store)
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		r := httptest.NewRequest("GET", "/", nil)
		r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
		handler.ServeHTTP(httptest.NewRecorder(), r)

		Expect(store.cleared).To(BeTrue())
	})

	It("should still proceed when Clear fails on corrupted session", func() {
		clearErr := errors.New("clear failed")
		store := &fakeStoreWithClearErr{
			fakeStore: fakeStore{
				err: fmt.Errorf("%w: underlying cause", sessions.ErrCorruptedSession),
			},
			clearErr: clearErr,
		}

		called := false
		mw := LoadSession(nil, store)
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		r := httptest.NewRequest("GET", "/", nil)
		r = ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
		handler.ServeHTTP(httptest.NewRecorder(), r)

		// Even when Clear returns an error, the middleware logs and continues.
		Expect(called).To(BeTrue())
	})
})
