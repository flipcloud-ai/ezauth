package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezauth "github.com/flipcloud-ai/ezauth/pkg/server/auth"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var errMock = fmt.Errorf("mock error")

var (
	idToken               = "abCdefghi123.ranDom888.IDToken"
	accessToken           = "abCdefghi123.ranDom888.AccessToken"
	refreshToken          = "abCdefghi123.ranDom888.RefreshToken"
	cookiesecret          = config.NewResolvedSecretRef([]byte("cookiesecret1234"))
	redirectURL           = "https://redirect.randomcloud123.com"
	validateURL           = "https://validate.randomcloud123.com"
	authorizationEndpoint = "https://www.randomcloud123.com/authorize"
	tokenEndpoint         = "https://www.randomcloud123.com/token"
	introspectionEndpoint = "https://www.randomcloud123.com/introspect"
	revocationEndpoint    = "https://www.randomcloud123.com/revoke"
	userInfoEndpoint      = "https://www.randomcloud123.com/userinfo"
	jwksUri               = "https://www.randomcloud123.com/keys"
)

type redeemTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

type oidcInfo struct {
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	IntrospectionEndpoint       string   `json:"introspection_endpoint"`
	RevocationEndpoint          string   `json:"revocation_endpoint"`
	UserinfoEndpoint            string   `json:"userinfo_endpoint"`
	GrantTypesSupported         []string `json:"grant_types_supported"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
	TokenAuthMethods            []string `json:"token_endpoint_auth_methods_supported"`
	JwksUri                     string   `json:"jwks_uri"`
	ResponseModesSupported      []string `json:"response_modes_supported"`
	SubjectTypesSupported       []string `json:"subject_types_supported"`
	IDTokenSigningAlgSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypeSupported       []string `json:"response_types_supported"`
	ScopesSupported             []string `json:"scopes_supported"`
	Issuer                      string   `json:"issuer"`
	RequestURIParameter         bool     `json:"request_uri_parameter_supported"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	LogoutEndpoint              string   `json:"end_session_endpoint"`
	ClaimsSupported             []string `json:"claims_supported"`
}

func newOIDCServer(body []byte, middlewares ...func(rw http.ResponseWriter, r *http.Request)) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		for _, m := range middlewares {
			m(rw, r)
		}
		rw.Header().Add("content-type", "application/json")
		_, _ = rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

// Helper to create mock profile for JWT parsing
func mockProfileParser() *gomonkey.Patches {
	return gomonkey.ApplyFunc(ezutils.ParseJWT, func(token string) ([]byte, error) {
		body, _ := json.Marshal(ezapi.Profile{
			User: "user@123456.com",
		})
		return body, nil
	})
}

// Helper to create mock profile parser that returns external user
func mockExternalProfileParser() *gomonkey.Patches {
	return gomonkey.ApplyFunc(ezutils.ParseJWT, func(idToken string) ([]byte, error) {
		payload, _ := json.Marshal(ezapi.Profile{
			Subject:           "externaluser@randomcloud123.com",
			EmailVerified:     true,
			Email:             "externaluser@randomcloud123.com",
			User:              "externaluser@randomcloud123.com",
			PreferredUsername: "externaluser@randomcloud123.com",
			Groups:            []string{"test1"},
		})
		return payload, nil
	})
}

// Standard token response for tests
var standardTokenResponse = redeemTokenResponse{
	AccessToken:  accessToken,
	ExpiresIn:    10,
	TokenType:    "Bearer",
	RefreshToken: refreshToken,
	IDToken:      idToken,
}

// Standard profile for tests
var standardProfile = ezapi.Profile{
	Subject:           "testuser@randomcloud123.com",
	Email:             "testuser@randomcloud123.com",
	User:              "testuser@randomcloud123.com",
	PreferredUsername: "testuser@randomcloud123.com",
	Groups:            []string{"test1", "test2"},
}

// Helper to create redeemTokenResponse
func newTokenResponse(accessToken, refreshToken, idToken string) redeemTokenResponse {
	return redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      idToken,
	}
}

var _ = Describe("Oauth Module Test Suite", Ordered, func() {
	var s *httptest.Server
	var u *url.URL
	var au, ju, rd, emptyOIDC, tokenUrl, profileURL *url.URL
	var testLogger ezlog.Logger
	BeforeAll(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})
	jwtCfg := config.JWTConfig{
		SecretKey:      config.NewResolvedSecretRef([]byte("lalalalala-test-jwt-key-32bytes!")),
		TokenIssuer:    "randomcloud123.com",
		ExpireDuration: 1 * time.Hour,
		Audience:       audience,
	}
	profile := ezapi.Profile{
		Subject: "auth.randomcloud123.com",
		Email:   "lalalala@123.com",
	}
	it, err := ezauth.GenerateToken(jwtCfg, profile)
	Expect(err).ToNot(HaveOccurred())
	var defaultpcfg config.ProviderConfig
	fakeVerifier := &oidc.IDTokenVerifier{}
	var verifierPatch *gomonkey.Patches
	BeforeEach(func() {
		verifierPatch = gomonkey.ApplyMethod(fakeVerifier, "Verify", func(_ *oidc.IDTokenVerifier, _ context.Context, token string) (*oidc.IDToken, error) {
			if token == idToken || token == it || token == "abCdefghi123.ranDom888.NewIDToken" {
				return nil, nil
			}
			return nil, ErrInvalidIDToken
		})
		rd, _ = url.Parse(redirectURL)
		au, _ = url.Parse(authorizationEndpoint)
		ju, _ = url.Parse(jwksUri)
		nobody, _ := json.Marshal(oidcInfo{})
		emptyOIDC, _ = newOIDCServer(nobody)
		profile, _ := json.Marshal(standardProfile)
		profileURL, _ = newOIDCServer(profile, func(rw http.ResponseWriter, r *http.Request) {
			t := r.Header.Get("Authorization")
			token := strings.Split(t, " ")[1]
			if token != "abCdefghi123.ranDom888.NewAccessToken" && token != accessToken {
				rw.WriteHeader(http.StatusForbidden)
				_, _ = rw.Write([]byte("invalid"))
			}
		})
		tokeBody, _ := json.Marshal(standardTokenResponse)
		tokenUrl, _ = newOIDCServer(tokeBody)
		body, _ := json.Marshal(oidcInfo{
			AuthorizationEndpoint: authorizationEndpoint,
			TokenEndpoint:         tokenUrl.String(),
			IntrospectionEndpoint: introspectionEndpoint,
			RevocationEndpoint:    revocationEndpoint,
			UserinfoEndpoint:      profileURL.String(),
			CodeChallengeMethods:  []string{"S256", "plain"},
			JwksUri:               jwksUri,
		})
		u, s = newOIDCServer(body)
		defaultpcfg = config.ProviderConfig{
			RedirectURL: rd,
			ValidateURL: tokenUrl,
			OIDCConfig: config.OIDCConfig{
				Issuer: u,
			},
			ClientID:     oidcClientID,
			ClientSecret: oidcSecret,
			SkipNonce:    true,
			LoginParameters: map[string][]string{
				"test1": {
					"foo",
					"bar",
				},
				"test2": {
					"foo",
				},
			},
		}
	})
	AfterEach(func() {
		verifierPatch.Reset()
		s.Close()
	})
	When("Test 0: Oauth2 provider functional test", func() {
		var opt config.ProviderConfig
		var p *OauthProvider
		BeforeEach(func() {
			v, err := url.Parse(validateURL)
			Expect(err).To(BeNil())
			opt = config.ProviderConfig{
				ProviderName: "oauth",
				RedirectURL:  rd,
				ValidateURL:  v,
				OIDCConfig: config.OIDCConfig{
					Issuer: u,
				},
				ClientID:     oidcClientID,
				ClientSecret: oidcSecret,
				SkipNonce:    true,
			}
			p, err = NewOauthProvider(context.Background(), &opt)
			Expect(err).To(BeNil())
			sessionStore, err := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			Expect(err).To(BeNil())
			p.SessionStore = sessionStore
		})
		nu, _ := url.Parse("https://www.notissuer.com")
		It("provider setup test", func(ctx SpecContext) {
			Expect(p).NotTo(BeNil())
			Expect(p.ProviderName()).To(Equal("oauth"))
			opts := p.Opts()
			Expect(opts.RedirectURL).To(Equal(opt.RedirectURL))
			Expect(opts.ClientID).To(Equal(opt.ClientID))
			Expect(opts.ClientSecret).To(Equal(opt.ClientSecret))
			Expect(opts.AuthURL).To(Equal(au))
			Expect(opts.TokenURL).To(Equal(tokenUrl))
			Expect(opts.UserInfoURL).To(Equal(profileURL))
			Expect(opts.JWKsURL).To(Equal(ju))
			Expect(opts.CodeChallengeMethod).To(Equal([]string{"S256", "plain"}))
		})
		DescribeTable("provider create test", func(optsfunc func() config.ProviderConfig, isNull bool) {
			opt := optsfunc()
			p, _ := NewOauthProvider(context.Background(), &opt)
			if isNull {
				Expect(p).To(BeNil())
			} else {
				Expect(p).NotTo(BeNil())
				Expect(p.name).To(Equal("oauth2"))
			}
		},
			Entry("default provider", func() config.ProviderConfig {
				return defaultpcfg
			}, false),
			Entry("no oidc provider", func() config.ProviderConfig {
				c := defaultpcfg
				c.Issuer = nu
				return c
			}, true),
		)
		It("provider handler test", func(ctx SpecContext) {
			Expect(p).NotTo(BeNil())
			// Exercise GetLoginURL and capture the state cookie it writes
			loginRec := httptest.NewRecorder()
			loginReq, _ := http.NewRequest("GET", "http://www.test.com", nil)
			loginReq = loginReq.WithContext(ezlog.RequestContext(loginReq.Context(), testLogger))
			loginURL, err := p.GetLoginURL(loginRec, loginReq)
			Expect(err).To(BeNil())
			Expect(loginURL.Host).To(Equal(au.Host))
			Expect(loginURL.Path).To(Equal(au.Path))
			q := loginURL.Query()
			Expect(q.Get("client_id")).To(Equal(oidcClientID))
			Expect(q.Get("redirect_uri")).To(Equal(redirectURL))
			Expect(q.Get("response_type")).To(Equal("code"))
			Expect(q.Get("scope")).To(Equal(p.opts.Scope))
			Expect(q.Get("code_challenge")).NotTo(Equal(""))
			Expect(q.Get("code_challenge_method")).To(Equal("S256"))

			p.opts.TokenURL = tokenUrl
			p.opts.ValidateURL = tokenUrl
			ss, err := p.Redeem(context.TODO(), redirectURL, "code", "")
			Expect(err).To(BeNil())
			Expect(ss.AccessToken).To(Equal(accessToken))
			Expect(ss.IDToken).To(Equal(idToken))
			Expect(ss.RefreshToken).To(Equal(refreshToken))
			Expect(ss.ExpiresOn).To(Equal(ss.CreatedAt + int64(10)))

			// Extract statecode from the state parameter and use the state cookie
			// the server emitted during GetLoginURL to invoke Callback
			statecode, _, err := ezutils.DecodeState(q.Get("state"))
			Expect(err).To(BeNil())
			callbackRec := httptest.NewRecorder()
			callbackReq, _ := http.NewRequest("GET", "/?code=code&statecode="+statecode, nil)
			callbackReq = callbackReq.WithContext(ezlog.RequestContext(callbackReq.Context(), testLogger))
			for _, c := range loginRec.Result().Cookies() {
				callbackReq.AddCookie(c)
			}
			err = p.Callback(callbackRec, callbackReq)
			Expect(err).To(BeNil())

			// A successful Callback must invalidate the stored state.
			// Simulate the browser's cookie jar by applying the Set-Cookie
			// headers from both loginRec (state set) and callbackRec
			// (clearing cookie) in order — the latest Set-Cookie for a
			// given name wins, and MaxAge=-1 evicts the entry. Replaying
			// the callback URL with that resulting jar must fail, which
			// exercises the DeleteValue call end-to-end: if DeleteValue
			// were dropped, no clearing cookie would land and the state
			// cookie would survive into the replay.
			jar := make(map[string]*http.Cookie)
			for _, c := range loginRec.Result().Cookies() {
				jar[c.Name] = c
			}
			for _, c := range callbackRec.Result().Cookies() {
				if c.MaxAge < 0 {
					delete(jar, c.Name)
					continue
				}
				jar[c.Name] = c
			}
			Expect(jar).NotTo(HaveKey("oauth_state_" + statecode))

			replayRec := httptest.NewRecorder()
			replayReq, _ := http.NewRequest("GET", "/?code=code&statecode="+statecode, nil)
			replayReq = replayReq.WithContext(ezlog.RequestContext(replayReq.Context(), testLogger))
			for _, c := range jar {
				replayReq.AddCookie(c)
			}
			err = p.Callback(replayRec, replayReq)
			Expect(err).NotTo(BeNil())
		})
		It("refresh token test", func(ctx SpecContext) {
			p.opts.TokenURL = tokenUrl
			p.opts.ValidateURL = tokenUrl
			ss, err := p.Redeem(context.TODO(), redirectURL, "code", "")
			Expect(err).To(BeNil())
			Expect(ss.AccessToken).To(Equal(accessToken))
			b, _ := json.Marshal(newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", it))
			tokenS := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				Expect(r.ParseForm()).To(Succeed())
				if r.Header.Get("Authorization") != "" {
					rw.WriteHeader(400)
					return
				}
				Expect(r.Form.Get("client_id")).To(Equal(oidcClientID))
				Expect(r.Form.Get("client_secret")).To(Equal(oidcSecret))
				rw.Header().Add("content-type", "application/json")
				_, _ = rw.Write(b)
			}))
			p.oauth2Config.Endpoint.TokenURL = tokenS.URL
			err = p.RefreshSession(ctx, ss)
			Expect(err).To(BeNil())
			Expect(ss.AccessToken).To(Equal("abCdefghi123.ranDom888.NewAccessToken"))
			Expect(ss.Profile.Email).To(Equal("lalalala@123.com"))
		})
	})
	When("Test 1: Oauth2 provider login url test", func() {
		body, _ := json.Marshal(oidcInfo{
			AuthorizationEndpoint: authorizationEndpoint,
			TokenEndpoint:         tokenEndpoint,
			IntrospectionEndpoint: introspectionEndpoint,
			RevocationEndpoint:    revocationEndpoint,
			UserinfoEndpoint:      userInfoEndpoint,
			CodeChallengeMethods:  []string{"plain"},
			JwksUri:               jwksUri,
		})
		plainURL, _ := newOIDCServer(body)
		DescribeTable("get login url test", func(optsfunc func() config.ProviderConfig) {
			opts := optsfunc()
			p, _ := NewOauthProvider(context.Background(), &opts)
			Expect(p).NotTo(BeNil())
			sessionStore, err := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			Expect(err).To(BeNil())
			p.SessionStore = sessionStore
			rec := httptest.NewRecorder()
			h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.Header().Add("content-type", "application/json")
				r = r.WithContext(ezlog.RequestContext(r.Context(), testLogger))
				url, err := p.GetLoginURL(rw, r)
				Expect(err).To(BeNil())
				q := url.Query()
				Expect(q.Get("client_id")).To(Equal(opts.ClientID))
				if opts.RedirectURL == nil {
					Expect(q.Get("redirect_uri")).To(Equal("http://www.test.com"))
				} else {
					Expect(q.Get("redirect_uri")).To(Equal(opts.RedirectURL.String()))
				}
				Expect(q.Get("response_type")).To(Equal("code"))
				scope := "openid email profile"
				if opts.Scope != "" {
					scope = opts.Scope
				}
				Expect(q.Get("scope")).To(Equal(scope))
				if slices.Contains(p.opts.CodeChallengeMethod, "S256") {
					Expect(q.Get("code_challenge")).NotTo(Equal(""))
					Expect(q.Get("code_challenge")).NotTo(Equal(q.Get("code_verifier")))
					Expect(q.Get("code_challenge_method")).To(Equal("S256"))
				} else if slices.Contains(p.opts.CodeChallengeMethod, "plain") {
					Expect(q.Get("code_challenge")).NotTo(Equal(""))
					Expect(q.Get("code_challenge")).NotTo(Equal(q.Get("code_verifier")))
					Expect(q.Get("code_challenge_method")).To(Equal("plain"))
				} else {
					Expect(q.Has("code_challenge")).To(BeFalse())
					Expect(q.Has("code_challenge_method")).To(BeFalse())
				}

				if len(opts.LoginParameters) > 0 {
					for k, v := range opts.LoginParameters {
						Expect(q.Get(k)).To(Equal(v[len(v)-1]))
					}
				}
			})

			r, err := http.NewRequest("GET", "http://www.test.com", nil)
			h.ServeHTTP(rec, r)
			Expect(err).To(BeNil())
		},
			Entry("default provider", func() config.ProviderConfig {
				return defaultpcfg
			}),
			Entry("plain code challenge provider", func() config.ProviderConfig {
				c := defaultpcfg
				c.Issuer = plainURL
				return c
			}),
			Entry("empty code challenge provider", func() config.ProviderConfig {
				c := defaultpcfg
				c.Issuer = plainURL
				return c
			}),
			Entry("empty redirect url", func() config.ProviderConfig {
				c := defaultpcfg
				c.RedirectURL = nil
				return c
			}),
		)
		It("get login url error test", func() {
			opts := defaultpcfg
			zl, logs := testutils.SetupLogsCapture()
			type errorInterface struct {
				e      error
				errLog string
				mp     func() *gomonkey.Patches
			}
			interfaces := []errorInterface{
				{
					e:      errMock,
					errLog: "Error in generating code verifier",
					mp: func() *gomonkey.Patches {
						return gomonkey.ApplyFunc(encryption.GenerateCodeVerifier, func() (string, error) {
							return "", errMock
						})
					},
				},
				{
					e:      errMock,
					errLog: "Error in generating code challenge",
					mp: func() *gomonkey.Patches {
						return gomonkey.ApplyFunc(encryption.GenerateCodeChallenge, func() (string, error) {
							return "", errMock
						})
					},
				},
				{
					e:      errMock,
					errLog: "Error storing OAuth state via session store",
					mp: func() *gomonkey.Patches {
						// Patch SaveValue on the concrete CookieStore that GetLoginURL will call.
						return gomonkey.ApplyMethod(&sessions.CookieStore{}, "SaveValue",
							func(_ *sessions.CookieStore, _ http.ResponseWriter, _ *http.Request, _ []byte, _ *sessions.ValueOptions) error {
								return errMock
							})
					},
				},
			}
			sessionStore, err := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			Expect(err).To(BeNil())
			for _, i := range interfaces {
				patch := i.mp()
				p, _ := NewOauthProvider(context.Background(), &opts)
				Expect(p).NotTo(BeNil())
				p.SessionStore = sessionStore
				rec := httptest.NewRecorder()
				h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
					rw.Header().Add("content-type", "application/json")
					r = r.WithContext(ezlog.RequestContext(r.Context(), zl))
					url, err := p.GetLoginURL(rw, r)
					Expect(url).To(BeNil())
					Expect(err).NotTo(BeNil())
					if i.e != nil {
						Expect(errors.Is(err, i.e)).To(BeTrue())
					}
					entry := logs.TakeAll()
					Expect((len(entry))).To(BeNumerically(">", 0))
					for _, l := range entry {
						Expect(l.Message).To(Equal(i.errLog))
					}
				})

				r, err := http.NewRequest("GET", "/", nil)
				h.ServeHTTP(rec, r)
				Expect(err).To(BeNil())
				patch.Reset()
			}
		})
	})
	When("Test 2: Oauth2 provider redeem token test", func() {
		type redeemTest struct {
			optsfunc     func() config.ProviderConfig
			errString    string
			code         string
			res          redeemTokenResponse
			codeVerifier string
			skipVerifier bool
		}
		tokenRes := standardTokenResponse
		DescribeTable("provider redeem test", func(rt redeemTest) {
			opt := rt.optsfunc()
			body, _ := json.Marshal(rt.res)
			tokenUrl, _ := newOIDCServer(body, func(rw http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				Expect(err).To(BeNil())
				q, err := url.ParseQuery(string(b))
				Expect(err).To(BeNil())
				if rt.codeVerifier != "" {
					Expect(q.Get("code_verifier")).To(Equal(rt.codeVerifier))
				} else {
					Expect(r.URL.Query().Has("code_verifier")).To(BeFalse())
				}
				Expect(q.Get("redirect_uri")).To(Equal(redirectURL))
				Expect(q.Get("client_id")).To(Equal(opt.ClientID))
				Expect(q.Get("client_secret")).To(Equal(opt.ClientSecret))
				Expect(q.Get("code")).To(Equal(rt.code))
				Expect(q.Get("grant_type")).To(Equal("authorization_code"))
			})
			p, _ := NewOauthProvider(context.Background(), &opt)
			// rewrite the token url
			if p.opts.TokenURL != nil && p.opts.TokenURL.String() != "" {
				p.opts.TokenURL = tokenUrl
			}
			idTokenPatch := mockExternalProfileParser()
			var patch *gomonkey.Patches
			if !rt.skipVerifier {
				fakeVerifier := &oidc.IDTokenVerifier{}
				patch = gomonkey.ApplyMethod(fakeVerifier, "Verify", func(_ *oidc.IDTokenVerifier, _ context.Context, _ string) (*oidc.IDToken, error) {
					return nil, ErrInvalidIDToken
				})
			}
			ctx := ezlog.RequestContext(context.TODO(), testLogger)
			ss, err := p.Redeem(ctx, redirectURL, rt.code, rt.codeVerifier)
			if rt.errString != "" {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal(rt.errString))
			} else {
				Expect(err).To(BeNil())
				Expect(ss.AccessToken).To(Equal(accessToken))
				Expect(ss.IDToken).To(Equal(idToken))
				Expect(ss.RefreshToken).To(Equal(refreshToken))
				if opt.ClaimsFromProfile {
					Expect(ss.Profile.Subject).To(Equal("testuser@randomcloud123.com"))
					Expect(ss.Profile.Email).To(Equal("testuser@randomcloud123.com"))
					Expect(ss.Profile.User).To(Equal("testuser@randomcloud123.com"))
					Expect(ss.Profile.PreferredUsername).To(Equal("testuser@randomcloud123.com"))
					Expect(ss.Profile.Groups).To(Equal([]string{"test1", "test2"}))
					Expect(ss.Profile.EmailVerified).To(BeFalse())
				} else {
					Expect(ss.Profile.Subject).To(Equal("externaluser@randomcloud123.com"))
					Expect(ss.Profile.Email).To(Equal("externaluser@randomcloud123.com"))
					Expect(ss.Profile.User).To(Equal("externaluser@randomcloud123.com"))
					Expect(ss.Profile.PreferredUsername).To(Equal("externaluser@randomcloud123.com"))
					Expect(ss.Profile.Groups).To(Equal([]string{"test1"}))
					Expect(ss.Profile.EmailVerified).To(BeTrue())
				}
				Expect(ss.ExpiresOn).To(Equal(ss.CreatedAt + int64(10)))
			}
			if !rt.skipVerifier {
				patch.Reset()
			}
			idTokenPatch.Reset()
		},
			Entry("default provider", redeemTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, "", "code", tokenRes, "code_verifier", true,
			}),
			Entry("verify profile", redeemTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.ClaimsFromProfile = true
					return c
				}, "", "code", tokenRes, "code_verifier", true,
			}),
			Entry("verify with invalid profile", redeemTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.ClaimsFromProfile = true
					return c
				}, "", "code", tokenRes, "code_verifier", true,
			}),
			Entry("verify id token", redeemTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, "invalid ID token", "code", tokenRes, "code_verifier", false,
			}),
			Entry("invalid oidc provider", redeemTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.Issuer = emptyOIDC
					return c
				}, "token request: Post \"\": unsupported protocol scheme \"\"", "code", tokenRes, "",
				true,
			}),
			Entry("no authentication code", redeemTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.Issuer = emptyOIDC
					return c
				}, "failed to retrieve redeem code from request", "", tokenRes, "",
				true,
			}),
			Entry("expire", redeemTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, "", "code", tokenRes, "",
				true,
			}),
			Entry("invalid token res", redeemTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, "no access token", "code", redeemTokenResponse{}, "",
				true,
			}),
			Entry("empty token res", redeemTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, "no access token", "code", newTokenResponse("", "", ""), "",
				true,
			}),
		)
	})
	When("Test 3: Oauth2 provider oauth callback test", func() {
		type callbackTest struct {
			e      string
			errLog string
			mp     func() *gomonkey.Patches
			opt    func() config.ProviderConfig
		}
		var patch *gomonkey.Patches
		AfterEach(func() {
			if patch != nil {
				patch.Reset()
			}
		})
		It("provider callback test", func() {
			zl, logs := testutils.SetupLogsCapture()
			jwtpatch := mockProfileParser()
			interfaces := []callbackTest{
				{
					e:  "",
					mp: nil,
					opt: func() config.ProviderConfig {
						return defaultpcfg
					},
				},
				{
					e:      "",
					errLog: "",
					opt: func() config.ProviderConfig {
						c := defaultpcfg
						c.ClaimsFromProfile = true
						c.AllowedGroups = []string{
							"test1",
							"test2",
						}
						return c
					},
				},
				{
					e:      "resources are not authorized",
					errLog: "",
					opt: func() config.ProviderConfig {
						c := defaultpcfg
						c.ClaimsFromProfile = true
						c.AllowedGroups = []string{
							"test3",
						}
						return c
					},
				},
				{
					e:      "resources are not authorized",
					errLog: "",
					opt: func() config.ProviderConfig {
						c := defaultpcfg
						c.AllowedGroups = []string{
							"test1",
							"test2",
						}
						return c
					},
				},
			}
			for idx, i := range interfaces {
				fmt.Printf("running test %d\n", idx)
				logs.TakeAll()
				if i.mp != nil {
					patch = i.mp()
				}
				opt := i.opt()
				p, _ := NewOauthProvider(context.Background(), &opt)
				// Init Session Store
				ss, _ := sessions.NewSessionStore(&config.Session{
					StoreType: "cookie",
					Cookie: config.CookieStoreOptions{
						Name:     "test",
						Secret:   cookiesecret,
						Path:     "/",
						HTTPOnly: testutils.BoolPtr(true),
					},
				})
				p.SessionStore = ss
				rec := httptest.NewRecorder()
				var loginURL *url.URL
				var err error
				s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
					rw.Header().Add("content-type", "application/json")
					r = r.WithContext(ezlog.RequestContext(r.Context(), zl))
					loginURL, err = p.GetLoginURL(rw, r)
					Expect(err).To(BeNil())
					logs.TakeAll() // clear logs from GetLoginURL before Callback test
				}))
				httpReq, httpErr := http.NewRequest("GET", s.URL, nil)
				Expect(httpErr).To(BeNil())
				httpResp, httpErr := http.DefaultClient.Do(httpReq)
				Expect(httpErr).To(BeNil())
				defer func() { _ = httpResp.Body.Close() }()
				httpcookies := httpResp.Cookies()
				// Extract statecode from the login URL state parameter
				statecode, _, decodeErr := ezutils.DecodeState(loginURL.Query().Get("state"))
				Expect(decodeErr).To(BeNil())
				h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
					r = r.WithContext(ezlog.RequestContext(r.Context(), zl))
					err = p.Callback(rw, r)
				})

				r, err := http.NewRequest("GET", "http://www.test.com", nil)
				for _, c := range httpcookies {
					r.AddCookie(c)
				}
				q := loginURL.Query()
				q.Add("code", "code")
				q.Set("statecode", statecode)
				r.URL.RawQuery = q.Encode()
				h.ServeHTTP(rec, r)
				if i.e != "" {
					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(MatchRegexp(i.e))
					if i.errLog != "" {
						entry := logs.TakeAll()
						Expect((len(entry))).To(BeNumerically(">", 0))
						for _, l := range entry {
							Expect(l.Message).To(MatchRegexp(i.errLog))
						}
					}
				} else {
					Expect(err).To(BeNil())
				}
				if patch != nil {
					patch.Reset()
				}
			}
			jwtpatch.Reset()
			verifierPatch.Reset()
		})
		It("callback returns error when state cookie is missing", func() {
			opts := defaultpcfg
			p, _ := NewOauthProvider(context.Background(), &opts)
			ss, _ := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			p.SessionStore = ss
			rec := httptest.NewRecorder()
			r, _ := http.NewRequest("GET", "/?code=code&statecode=abc", nil)
			r = r.WithContext(ezlog.RequestContext(r.Context(), testLogger))
			err := p.Callback(rec, r)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("state cookie not found"))
		})
		It("callback returns error when state cookie has invalid signature", func() {
			opts := defaultpcfg
			p, _ := NewOauthProvider(context.Background(), &opts)
			ss, _ := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			p.SessionStore = ss
			rec := httptest.NewRecorder()
			r, _ := http.NewRequest("GET", "/?code=code&statecode=abc", nil)
			r = r.WithContext(ezlog.RequestContext(r.Context(), testLogger))
			// Supply a cookie under the expected key but with a corrupted
			// signed value. The session store's LoadValue will fail to
			// verify the signature and propagate the error to Callback.
			r.AddCookie(&http.Cookie{Name: "oauth_state_abc", Value: "tampered|invalid|value"})
			err := p.Callback(rec, r)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(MatchRegexp("error loading OAuth state"))
		})
		It("callback returns error when statecode does not match stored value", func() {
			opts := defaultpcfg
			p, _ := NewOauthProvider(context.Background(), &opts)
			ss, _ := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			p.SessionStore = ss
			// Run GetLoginURL once to stash a real signed entry at
			// key `oauth_state_<statecode>`.
			rec := httptest.NewRecorder()
			r, _ := http.NewRequest("GET", "http://www.test.com", nil)
			r = r.WithContext(ezlog.RequestContext(r.Context(), testLogger))
			loginURL, err := p.GetLoginURL(rec, r)
			Expect(err).To(BeNil())
			// Recover the original statecode from the state parameter so the
			// callback keys into the same store entry as the login did.
			statecode, _, err := ezutils.DecodeState(loginURL.Query().Get("state"))
			Expect(err).To(BeNil())
			cookies := rec.Result().Cookies()
			Expect(cookies).NotTo(BeEmpty())

			// Overwrite the stored value with one whose internal statecode
			// field no longer matches the key — defense-in-depth against a
			// collision between the lookup key and the bound statecode.
			tamperedValue := []byte("mismatched-statecode:any-verifier")
			tamperRec := httptest.NewRecorder()
			tamperReq, _ := http.NewRequest("GET", "http://www.test.com", nil)
			tamperReq = tamperReq.WithContext(ezlog.RequestContext(tamperReq.Context(), testLogger))
			Expect(ss.SaveValue(tamperRec, tamperReq, tamperedValue, &sessions.ValueOptions{
				Name: "oauth_state_" + statecode,
			})).To(Succeed())
			tamperedCookies := tamperRec.Result().Cookies()
			Expect(tamperedCookies).NotTo(BeEmpty())

			callbackRec := httptest.NewRecorder()
			cr, _ := http.NewRequest("GET", "/?code=code&statecode="+statecode, nil)
			cr = cr.WithContext(ezlog.RequestContext(cr.Context(), testLogger))
			for _, c := range tamperedCookies {
				cr.AddCookie(c)
			}
			err = p.Callback(callbackRec, cr)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("invalid state code"))
		})
		It("callback returns error when form parsing fails due to malformed query", func() {
			opts := defaultpcfg
			p, _ := NewOauthProvider(context.Background(), &opts)
			ss, _ := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			p.SessionStore = ss
			rec := httptest.NewRecorder()
			// %zz is not a valid hex sequence; url.ParseQuery will fail,
			// causing ParseForm to return an error.
			r, _ := http.NewRequest("GET", "http://test.com/?code=code&statecode=abc%zz", nil)
			r = r.WithContext(ezlog.RequestContext(r.Context(), testLogger))
			err := p.Callback(rec, r)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error parsing callback form"))
		})
	})
	When("Test 3: Oauth2 provider oauth refresh test", func() {
		type refreshTest struct {
			optsfunc  func() config.ProviderConfig
			session   *ezapi.Session
			profile   *ezapi.Profile
			res       redeemTokenResponse
			errString string
		}
		ctx := ezlog.RequestContext(context.TODO(), testLogger)
		DescribeTable("refresh session test", func(rt refreshTest) {
			var err error
			var exp int64
			if rt.session != nil {
				exp = rt.session.ExpiresOn
			}
			opt := rt.optsfunc()
			p, _ := NewOauthProvider(context.Background(), &opt)
			b, _ := json.Marshal(rt.res)
			tokenS := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				Expect(r.ParseForm()).To(Succeed())
				if r.Header.Get("Authorization") != "" {
					rw.WriteHeader(400)
					return
				}
				Expect(r.Form.Get("client_id")).To(Equal(oidcClientID))
				Expect(r.Form.Get("client_secret")).To(Equal(oidcSecret))
				rw.Header().Add("content-type", "application/json")
				_, _ = rw.Write(b)
			}))
			p.oauth2Config.Endpoint.TokenURL = tokenS.URL
			logger, _ := testutils.SetupTestLogger()
			ctx = ezlog.RequestContext(ctx, logger)
			err = p.RefreshSession(ctx, rt.session)
			if rt.errString != "" {
				Expect(err.Error()).To(Equal(rt.errString))
				if rt.session != nil {
					Expect(rt.session.ExpiresOn).To(Equal(exp))
					Expect(rt.session.Profile.Subject).To(Equal(""))
					Expect(rt.session.Profile.Email).To(Equal(""))
					Expect(rt.session.Profile.User).To(Equal(""))
					Expect(rt.session.Profile.PreferredUsername).To(Equal(""))
					Expect(len(rt.session.Profile.Groups)).To(Equal(0))
					Expect(rt.session.Profile.EmailVerified).To(BeFalse())
				}
			} else {
				Expect(err).To(BeNil())
				Expect(rt.session.AccessToken).To(Equal(rt.res.AccessToken))
				Expect(rt.session.IDToken).To(Equal(rt.res.IDToken))
				Expect(rt.session.RefreshToken).To(Equal(rt.res.RefreshToken))
				Expect(rt.session.ExpiresOn).To(Equal(rt.session.CreatedAt + int64(rt.res.ExpiresIn)))
				if rt.profile == nil {
					Expect(rt.session.Profile.Subject).To(Equal("testuser@randomcloud123.com"))
					Expect(rt.session.Profile.Email).To(Equal("testuser@randomcloud123.com"))
					Expect(rt.session.Profile.User).To(Equal("testuser@randomcloud123.com"))
					Expect(rt.session.Profile.PreferredUsername).To(Equal("testuser@randomcloud123.com"))
					Expect(rt.session.Profile.Groups).To(Equal([]string{"test1", "test2"}))
					Expect(rt.session.Profile.EmailVerified).To(BeFalse())
				} else {
					Expect(rt.session.Profile.Subject).To(Equal(rt.profile.Subject))
					Expect(rt.session.Profile.Email).To(Equal(rt.profile.Email))
					Expect(rt.session.Profile.User).To(Equal(rt.profile.User))
					Expect(rt.session.Profile.PreferredUsername).To(Equal(rt.profile.PreferredUsername))
					Expect(rt.session.Profile.Groups).To(Equal(rt.profile.Groups))
					Expect(rt.session.Profile.EmailVerified).To(Equal(rt.profile.EmailVerified))
				}
			}
		},
			Entry("default provider", refreshTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, nil, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.NewIDToken"),
				"",
			}),
			Entry("jwt profile", refreshTest{
				func() config.ProviderConfig {
					jwtProfile := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
						rw.Header().Add("content-type", "application/jwt")
						_, _ = rw.Write([]byte(it))
					}))
					body, _ := json.Marshal(oidcInfo{
						AuthorizationEndpoint: authorizationEndpoint,
						TokenEndpoint:         tokenUrl.String(),
						IntrospectionEndpoint: introspectionEndpoint,
						RevocationEndpoint:    revocationEndpoint,
						UserinfoEndpoint:      jwtProfile.URL,
						CodeChallengeMethods:  []string{"S256", "plain"},
						JwksUri:               jwksUri,
					})
					jwtu, _ := newOIDCServer(body)
					c := defaultpcfg
					c.Issuer = jwtu
					return c
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, &profile, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.NewIDToken"),
				"",
			}),
			Entry("refresh from id token", refreshTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, &profile, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", it),
				"",
			}),
			Entry("empty refresh token", refreshTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: "",
					IDToken:      idToken,
				}, nil, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.NewIDToken"),
				ErrEmptyRefreshToken.Error(),
			}),
			Entry("invalid refresh token response", refreshTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, nil, redeemTokenResponse{},
				ErrRefreshSession.Error(),
			}),
			Entry("empty id token", refreshTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, nil, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", ""),
				ErrInvalidIDToken.Error(),
			}),
			Entry("fake access token", refreshTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.ClaimsFromProfile = true
					return c
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, nil, newTokenResponse("abCdefghi123.ranDom888.FakeAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.NewIDToken"),
				ErrRefreshSession.Error(),
			}),
			Entry("fake id token", refreshTest{
				func() config.ProviderConfig {
					return defaultpcfg
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, nil, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.FakeIDToken"),
				ErrInvalidIDToken.Error(),
			}),
			Entry("fake id token with profile", refreshTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.ClaimsFromProfile = true
					return c
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, nil, newTokenResponse("abCdefghi123.ranDom888.FakeAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.FakeIDToken"),
				ErrInvalidIDToken.Error(),
			}),
			Entry("nil session", refreshTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.ClaimsFromProfile = true
					return c
				}, nil, nil, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.NewIDToken"),
				ErrEmptySession.Error(),
			}),
			Entry("nil profile", refreshTest{
				func() config.ProviderConfig {
					c := defaultpcfg
					c.Issuer = emptyOIDC
					c.ClaimsFromProfile = true
					return c
				}, &ezapi.Session{
					AccessToken:  accessToken,
					CreatedAt:    time.Now().Unix(),
					ExpiresOn:    time.Now().Add(1 * time.Second).Unix(),
					RefreshToken: refreshToken,
					IDToken:      idToken,
				}, nil, newTokenResponse("abCdefghi123.ranDom888.NewAccessToken", "abCdefghi123.ranDom888.NewRefreshToken", "abCdefghi123.ranDom888.NewIDToken"),
				ErrRefreshSession.Error(),
			}),
		)
	})

	When("Test 5: Revoke tests", func() {
		var p *OauthProvider

		BeforeEach(func() {
			opt := defaultpcfg
			opt.ProviderName = "oauth"
			var err error
			p, err = NewOauthProvider(context.Background(), &opt)
			Expect(err).To(BeNil())
			ss, err := sessions.NewSessionStore(&config.Session{
				StoreType: "cookie",
				Cookie: config.CookieStoreOptions{
					Name:     "test",
					Secret:   cookiesecret,
					Path:     "/",
					HTTPOnly: testutils.BoolPtr(true),
				},
			})
			Expect(err).To(BeNil())
			p.SessionStore = ss
		})

		It("should return ErrEmptySession when session is nil", func(ctx SpecContext) {
			testCtx := ezlog.RequestContext(ctx, testLogger)
			err := p.Revoke(testCtx, nil)
			Expect(err).To(MatchError(ErrEmptySession))
		})

		It("should return nil when RevocationURL is nil (no-op)", func(ctx SpecContext) {
			p.opts.RevocationURL = nil
			testCtx := ezlog.RequestContext(ctx, testLogger)
			err := p.Revoke(testCtx, &ezapi.Session{AccessToken: accessToken, RefreshToken: refreshToken})
			Expect(err).To(BeNil())
		})

		It("should return nil when both tokens are empty (no-op)", func(ctx SpecContext) {
			revokeServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusOK)
			}))
			defer revokeServer.Close()
			ru, _ := url.Parse(revokeServer.URL)
			p.opts.RevocationURL = ru
			testCtx := ezlog.RequestContext(ctx, testLogger)
			err := p.Revoke(testCtx, &ezapi.Session{})
			Expect(err).To(BeNil())
		})

		It("should return nil when idp returns 200 with refresh_token", func(ctx SpecContext) {
			revokeServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				Expect(r.ParseForm()).To(Succeed())
				Expect(r.Form.Get("token")).To(Equal(refreshToken))
				Expect(r.Form.Get("token_type_hint")).To(Equal("refresh_token"))
				rw.WriteHeader(http.StatusOK)
			}))
			defer revokeServer.Close()
			ru, _ := url.Parse(revokeServer.URL)
			p.opts.RevocationURL = ru
			testCtx := ezlog.RequestContext(ctx, testLogger)
			err := p.Revoke(testCtx, &ezapi.Session{RefreshToken: refreshToken, AccessToken: accessToken})
			Expect(err).To(BeNil())
		})

		It("should return nil when idp returns 204 with access_token only", func(ctx SpecContext) {
			revokeServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				Expect(r.ParseForm()).To(Succeed())
				Expect(r.Form.Get("token")).To(Equal(accessToken))
				Expect(r.Form.Get("token_type_hint")).To(Equal("access_token"))
				rw.WriteHeader(http.StatusNoContent)
			}))
			defer revokeServer.Close()
			ru, _ := url.Parse(revokeServer.URL)
			p.opts.RevocationURL = ru
			testCtx := ezlog.RequestContext(ctx, testLogger)
			err := p.Revoke(testCtx, &ezapi.Session{AccessToken: accessToken})
			Expect(err).To(BeNil())
		})

		It("should return error containing status code when idp returns 400", func(ctx SpecContext) {
			revokeServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusBadRequest)
				_, _ = rw.Write([]byte("bad request"))
			}))
			defer revokeServer.Close()
			ru, _ := url.Parse(revokeServer.URL)
			p.opts.RevocationURL = ru
			testCtx := ezlog.RequestContext(ctx, testLogger)
			err := p.Revoke(testCtx, &ezapi.Session{RefreshToken: refreshToken})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("400"))
		})
	})

	When("Test 6: ValidateSession supplementary tests", func() {
		var p *OauthProvider

		BeforeEach(func() {
			opt := defaultpcfg
			opt.ProviderName = "oauth"
			var err error
			p, err = NewOauthProvider(context.Background(), &opt)
			Expect(err).To(BeNil())
		})

		It("should return false when access token is empty", func(ctx SpecContext) {
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, &ezapi.Session{})
			Expect(result).To(BeFalse())
		})

		It("should return false when ValidateURL is nil", func(ctx SpecContext) {
			p.opts.ValidateURL = nil
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, &ezapi.Session{AccessToken: accessToken})
			Expect(result).To(BeFalse())
		})

		It("should return false when ValidateURL has no host", func(ctx SpecContext) {
			noHost, _ := url.Parse("/just-a-path")
			p.opts.ValidateURL = noHost
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, &ezapi.Session{AccessToken: accessToken})
			Expect(result).To(BeFalse())
		})

		It("should return true when idp returns 200", func(ctx SpecContext) {
			validateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				Expect(r.URL.Query().Get("access_token")).To(Equal(accessToken))
				rw.WriteHeader(http.StatusOK)
			}))
			defer validateServer.Close()
			vu, _ := url.Parse(validateServer.URL)
			p.opts.ValidateURL = vu
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, &ezapi.Session{AccessToken: accessToken})
			Expect(result).To(BeTrue())
		})

		It("should return false when idp returns 401", func(ctx SpecContext) {
			validateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusUnauthorized)
			}))
			defer validateServer.Close()
			vu, _ := url.Parse(validateServer.URL)
			p.opts.ValidateURL = vu
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, &ezapi.Session{AccessToken: accessToken})
			Expect(result).To(BeFalse())
		})

		It("should append access_token with & when endpoint already has query params", func(ctx SpecContext) {
			validateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				Expect(r.URL.Query().Get("existing")).To(Equal("param"))
				Expect(r.URL.Query().Get("access_token")).To(Equal(accessToken))
				rw.WriteHeader(http.StatusOK)
			}))
			defer validateServer.Close()
			vu, _ := url.Parse(validateServer.URL + "?existing=param")
			p.opts.ValidateURL = vu
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, &ezapi.Session{AccessToken: accessToken})
			Expect(result).To(BeTrue())
		})

		It("should forward custom headers to idp", func(ctx SpecContext) {
			const customHeader = "X-Custom-Auth"
			const customValue = "my-token-value"
			validateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				Expect(r.Header.Get(customHeader)).To(Equal(customValue))
				rw.WriteHeader(http.StatusOK)
			}))
			defer validateServer.Close()
			vu, _ := url.Parse(validateServer.URL)
			p.opts.ValidateURL = vu
			testCtx := ezlog.RequestContext(ctx, testLogger)
			result := p.ValidateSession(testCtx, &ezapi.Session{AccessToken: accessToken}, map[string]string{
				customHeader: customValue,
			})
			Expect(result).To(BeTrue())
		})
	})
})

var _ = Describe("OIDC Nonce Flow", func() {
	var testLogger ezlog.Logger
	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	newNonceProvider := func(skipNonce bool) (*OauthProvider, sessions.SessionStore) {
		cs := config.NewResolvedSecretRef([]byte("cookiesecret1234"))
		rd, _ := url.Parse("https://redirect.randomcloud123.com")
		au, _ := url.Parse("https://www.randomcloud123.com/authorize")
		nobody, _ := json.Marshal(oidcInfo{})
		u, _ := newOIDCServer(nobody)
		opt := config.ProviderConfig{
			ProviderName: "oauth",
			RedirectURL:  rd,
			OIDCConfig:   config.OIDCConfig{Issuer: u, AuthURL: au, JWKsURL: au},
			ClientID:     oidcClientID,
			ClientSecret: oidcSecret,
			SkipNonce:    skipNonce,
		}
		p, err := NewOauthProvider(context.Background(), &opt)
		Expect(err).ToNot(HaveOccurred())
		store, err := sessions.NewSessionStore(&config.Session{
			StoreType: "cookie",
			Cookie:    config.CookieStoreOptions{Name: "test", Secret: cs, Path: "/", HTTPOnly: testutils.BoolPtr(true)},
		})
		Expect(err).ToNot(HaveOccurred())
		p.SessionStore = store
		return p, store
	}

	DescribeTable("nonce presence in login URL",
		func(skipNonce bool, wantNonce bool) {
			p, _ := newNonceProvider(skipNonce)
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "http://www.test.com", nil)
			req = req.WithContext(ezlog.RequestContext(req.Context(), testLogger))
			loginURL, err := p.GetLoginURL(rec, req)
			Expect(err).ToNot(HaveOccurred())
			if wantNonce {
				Expect(loginURL.Query().Get("nonce")).NotTo(BeEmpty())
			} else {
				Expect(loginURL.Query().Get("nonce")).To(BeEmpty())
			}
		},
		Entry("should include nonce when SkipNonce is false", false, true),
		Entry("should skip nonce when SkipNonce is true", true, false),
	)
})

var _ = Describe("OIDC Nonce Callback Verification", func() {
	var testLogger ezlog.Logger
	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	newCallbackProvider := func() (*OauthProvider, *httptest.ResponseRecorder, *http.Request, string) {
		cs := config.NewResolvedSecretRef([]byte("cookiesecret1234"))
		rd, _ := url.Parse("https://redirect.randomcloud123.com")
		nobody, _ := json.Marshal(oidcInfo{})
		u, _ := newOIDCServer(nobody)
		opt := config.ProviderConfig{
			ProviderName: "oauth",
			RedirectURL:  rd,
			OIDCConfig:   config.OIDCConfig{Issuer: u},
			ClientID:     oidcClientID,
			ClientSecret: oidcSecret,
			SkipNonce:    false,
		}
		p, err := NewOauthProvider(context.Background(), &opt)
		Expect(err).ToNot(HaveOccurred())
		store, err := sessions.NewSessionStore(&config.Session{
			StoreType: "cookie",
			Cookie:    config.CookieStoreOptions{Name: "test", Secret: cs, Path: "/", HTTPOnly: testutils.BoolPtr(true)},
		})
		Expect(err).ToNot(HaveOccurred())
		p.SessionStore = store

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "http://www.test.com", nil)
		req = req.WithContext(ezlog.RequestContext(req.Context(), testLogger))
		loginURL, err := p.GetLoginURL(rec, req)
		Expect(err).ToNot(HaveOccurred())
		Expect(loginURL.Query().Get("nonce")).NotTo(BeEmpty())

		statecode, _, decodeErr := ezutils.DecodeState(loginURL.Query().Get("state"))
		Expect(decodeErr).To(BeNil())
		return p, rec, req, statecode
	}

	It("should reject callback when ID token is missing nonce claim", func() {
		p, loginRec, _, statecode := newCallbackProvider()

		patch := gomonkey.ApplyFunc(ezutils.ParseJWT, func(_ string) ([]byte, error) {
			return json.Marshal(map[string]string{"sub": "testuser"})
		})
		defer patch.Reset()
		redeemPatch := gomonkey.ApplyMethod(p, "Redeem",
			func(_ *OauthProvider, _ context.Context, _, _, _ string) (*ezapi.Session, error) {
				return &ezapi.Session{IDToken: "fake.id.token", Profile: ezapi.Profile{Subject: "testuser"}}, nil
			})
		defer redeemPatch.Reset()
		authzPatch := gomonkey.ApplyMethod(p, "Authorize",
			func(_ *OauthProvider, _ context.Context, _ *ezapi.Session) bool { return true })
		defer authzPatch.Reset()

		callbackRec := httptest.NewRecorder()
		callbackReq, _ := http.NewRequest("GET", "/?code=code&statecode="+statecode, nil)
		callbackReq = callbackReq.WithContext(ezlog.RequestContext(callbackReq.Context(), testLogger))
		for _, c := range loginRec.Result().Cookies() {
			callbackReq.AddCookie(c)
		}
		err := p.Callback(callbackRec, callbackReq)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("nonce claim missing from id token"))
	})

	It("should reject callback when nonce does not match", func() {
		p, loginRec, _, statecode := newCallbackProvider()

		patch := gomonkey.ApplyFunc(ezutils.ParseJWT, func(_ string) ([]byte, error) {
			return json.Marshal(map[string]string{"sub": "testuser", "nonce": "WRONG_NONCE_HASH"})
		})
		defer patch.Reset()
		redeemPatch := gomonkey.ApplyMethod(p, "Redeem",
			func(_ *OauthProvider, _ context.Context, _, _, _ string) (*ezapi.Session, error) {
				return &ezapi.Session{IDToken: "fake.id.token", Profile: ezapi.Profile{Subject: "testuser"}}, nil
			})
		defer redeemPatch.Reset()
		authzPatch := gomonkey.ApplyMethod(p, "Authorize",
			func(_ *OauthProvider, _ context.Context, _ *ezapi.Session) bool { return true })
		defer authzPatch.Reset()

		callbackRec := httptest.NewRecorder()
		callbackReq, _ := http.NewRequest("GET", "/?code=code&statecode="+statecode, nil)
		callbackReq = callbackReq.WithContext(ezlog.RequestContext(callbackReq.Context(), testLogger))
		for _, c := range loginRec.Result().Cookies() {
			callbackReq.AddCookie(c)
		}
		err := p.Callback(callbackRec, callbackReq)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("nonce mismatch"))
	})
})
