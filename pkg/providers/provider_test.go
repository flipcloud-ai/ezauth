package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	audience = "https://aud.randomcloud123.com"
)

var (
	oidcClientID string
	oidcSecret   string
	testLogger   ezlog.Logger
)

func init() {
	var err error
	oidcClientID, err = ezutils.NewRandomString(16)
	if err != nil {
		panic(fmt.Sprintf("generate test oidc client ID: %v", err))
	}
	oidcSecret, err = ezutils.NewRandomString(16)
	if err != nil {
		panic(fmt.Sprintf("generate test oidc secret: %v", err))
	}
}

var _ = BeforeSuite(func() {
	testLogger, _ = testutils.SetupTestLogger()
})

var _ = Describe("Provider Module Test Suite", func() {
	When("creating provider with valid config", func() {
		It("should create provider with correct settings", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			firstProvider := providers["test2"]
			Expect(firstProvider).NotTo(BeNil())
			Expect(firstProvider.ProviderName()).To(Equal("test2"))
			pOpts := firstProvider.Opts()
			Expect(pOpts).To(HaveField("ProviderName", "test2"))
			Expect(pOpts).To(HaveField("Type", "oauth2"))
			Expect(pOpts).To(HaveField("Scope", "openid email profile"))
			Expect(pOpts).To(HaveField("UserClaim", "sub"))
		})
	})

	When("creating provider with invalid options", func() {
		It("should return error when provider config is nil", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			_, err = NewProvider(nil, sessionStore)
			Expect(err).To(Equal(ErrInitProvider))
		})

		It("should return error when provider list is empty", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			_, err = NewProvider([]*ezcfg.ProviderConfig{}, sessionStore)
			Expect(err).To(Equal(ErrInitProvider))
		})

		It("should return partial results and joined error when one provider fails", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			// valid config alongside a broken one (empty type → NewOauthProvider will fail)
			broken := &ezcfg.ProviderConfig{ProviderName: "broken"}
			cfgs := append(opts.Auth.Provider, broken)
			result, err := NewProvider(cfgs, sessionStore)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("broken"))
			// the valid provider still loaded
			Expect(result).To(HaveKey("test2"))
			Expect(result).NotTo(HaveKey("broken"))
		})
	})

	When("testing provider interface methods", func() {
		It("should return nil error for GetLoginURL", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			p := providers["test2"]
			req := httptest.NewRequest("GET", "/", nil)
			req = req.WithContext(ezlog.RequestContext(req.Context(), testLogger))
			rec := httptest.NewRecorder()
			_, err = p.GetLoginURL(rec, req)
			Expect(err).To(BeNil())
		})

		It("should return error for Callback without code", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			p := providers["test2"]
			req := httptest.NewRequest("GET", "/", nil)
			err = p.Callback(nil, req)
			Expect(err).To(HaveOccurred())
		})

		It("should return error for Redeem without code", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			p := providers["test2"]
			_, err = p.Redeem(context.Background(), "", "verifier", "redir")
			Expect(err).To(Equal(ErrNoAccessToken))
		})

		It("should return false for ValidateSession with empty session", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			p := providers["test2"]
			sess := &ezapi.Session{}
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, sess)
			Expect(result).To(BeFalse())
		})

		It("should return error for RefreshSession without token", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			p := providers["test2"]
			sess := &ezapi.Session{}
			err = p.RefreshSession(context.Background(), sess)
			Expect(err).To(HaveOccurred())
		})
	})

	When("testing Authorize method", func() {
		It("should return true when no allowed groups are configured", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			p := providers["test2"]
			sess := &ezapi.Session{Profile: ezapi.Profile{Groups: []string{"group1", "group2"}}}
			result := p.Authorize(context.Background(), sess)
			Expect(result).To(BeTrue())
		})
	})

	When("testing GetSessionStore method", func() {
		It("should return the session store", func(ctx SpecContext) {
			opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
			sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
			Expect(err).To(BeNil())
			providers, err := NewProvider(opts.Auth.Provider, sessionStore)
			Expect(err).To(BeNil())
			p := providers["test2"]
			ss := p.GetSessionStore()
			Expect(ss).NotTo(BeNil())
		})
	})

	When("testing Authorize with non-matching groups", func() {
		It("should return false when session groups do not match allowed groups", func(ctx SpecContext) {
			dp := &DefaultProvider{
				name: "test",
				opts: ezcfg.ProviderConfig{
					AllowedGroups: []string{"admins", "ops"},
				},
			}
			dp.setAllowedGroups()
			sess := &ezapi.Session{
				Profile: ezapi.Profile{
					Groups: []string{"devs", "qa"},
				},
			}
			result := dp.Authorize(context.Background(), sess)
			Expect(result).To(BeFalse())
		})
	})
})

var _ = Describe("DefaultProvider stub methods", func() {
	var dp *DefaultProvider

	BeforeEach(func() {
		dp = &DefaultProvider{
			name: "stub",
			opts: ezcfg.ProviderConfig{},
		}
	})

	It("should return ErrNotImplemented from GetLoginURL", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		u, err := dp.GetLoginURL(rec, req)
		Expect(u).To(BeNil())
		Expect(err).To(MatchError(ErrNotImplemented))
	})

	It("should return false from ValidateSession", func() {
		result := dp.ValidateSession(context.Background(), &ezapi.Session{})
		Expect(result).To(BeFalse())
	})

	It("should return ErrNotImplemented from RefreshSession", func() {
		err := dp.RefreshSession(context.Background(), &ezapi.Session{})
		Expect(err).To(MatchError(ErrNotImplemented))
	})

	It("should return ErrNotImplemented from Revoke", func() {
		err := dp.Revoke(context.Background(), &ezapi.Session{})
		Expect(err).To(MatchError(ErrNotImplemented))
	})
})

var _ = Describe("hasQueryParams", func() {
	DescribeTable("should detect query parameters in endpoint URLs",
		func(endpoint string, expected bool) {
			Expect(hasQueryParams(endpoint)).To(Equal(expected))
		},
		Entry("url with query params returns true", "https://example.com/path?foo=bar", true),
		Entry("url without query params returns false", "https://example.com/path", false),
		Entry("invalid url returns false", "://invalid", false),
		Entry("empty string returns false", "", false),
	)
})

var _ = Describe("NewProvider nil entry in opts slice", func() {
	It("should skip nil entries and not panic", func() {
		opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
		sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
		Expect(err).To(BeNil())
		// Build a slice with a nil entry alongside a valid config.
		cfgs := []*ezcfg.ProviderConfig{nil, opts.Auth.Provider[0]}
		result, err := NewProvider(cfgs, sessionStore)
		Expect(err).To(BeNil())
		Expect(result).To(HaveKey("test2"))
	})
})

var _ = Describe("getOAuthRedirectURI RedirectAllowedDomains", func() {
	It("should return error when request host is not in allowed domains", func(ctx SpecContext) {
		opts := testutils.LoadFromConfig("oauth2/oidc.yaml")
		sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)
		Expect(err).To(BeNil())
		providerMap, err := NewProvider(opts.Auth.Provider, sessionStore)
		Expect(err).To(BeNil())
		p := providerMap["test2"].(*OauthProvider)
		p.opts.RedirectURL = nil
		p.opts.RedirectAllowedDomains = []string{"other.example.com"}
		_ = ezlog.RequestContext
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://notallowed.example.com/", nil)
		req = req.WithContext(ezlog.RequestContext(req.Context(), testLogger))
		_, loginErr := p.GetLoginURL(rec, req)
		Expect(loginErr).To(HaveOccurred())
		Expect(loginErr.Error()).To(ContainSubstring("not in allowed domains"))
	})
})
