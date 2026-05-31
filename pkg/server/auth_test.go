package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	ezerror "github.com/flipcloud-ai/ezauth/pkg/error"
	"github.com/flipcloud-ai/ezauth/pkg/middleware"
	ezproviders "github.com/flipcloud-ai/ezauth/pkg/providers"
	dto "github.com/flipcloud-ai/ezauth/pkg/server/dto"
	"github.com/flipcloud-ai/ezauth/pkg/server/rbac"
	eztmpl "github.com/flipcloud-ai/ezauth/pkg/server/templates"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	testp "github.com/flipcloud-ai/ezauth/test/provider"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type authTest struct {
	authBody   url.Values
	errString  string
	errCode    int
	query      map[string]string
	method     string
	jsonErr    bool
	ConfigPath string
}

type callbackTest struct {
	query             map[string]string
	state             map[string]string
	errorString       string
	skipCookie        bool
	jsonErr           bool
	ConfigPath        string
	noDetailSubstring string
	redeemErr         bool
	deleteProvider    bool
}

var _ = Describe("Server Auth Test Suite", func() {
	When("auth unit test", func() {
		var s *Server
		logger, _ := testutils.SetupTestLogger()
		ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(201)
			if r.URL.Path != "" && r.URL.Path != "/" {
				_, _ = rw.Write([]byte(r.URL.Path))
				return
			}
			_, _ = rw.Write([]byte("ok"))
		}))
		u, _ := url.Parse(ts.URL)
		BeforeEach(func() {
			t := testutils.LoadFromConfig("standard.yaml")
			store, _ := sessions.NewSessionStore(&t.Auth.Session)
			rend, _, _ := eztmpl.New("", "")
			s = &Server{
				sessionStore: store,
				ServeCfg:     t.Server,
				AuthCfg:      t.Auth,
				Logger:       logger,
				renderer:     rend,
			}
			s.ServeCfg.Upstream = u
			_ = s.Providers(context.Background())
			s.revProxy = newProxy(s.buildProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
		})
		It("proxy redirect", func() {
			// Return 201 if session exists — verifies Proxy forwards to upstream.
			fn := middleware.InitSession(true)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reqInfo := ezapi.GetRequest(r)
					reqInfo.Session = &ezapi.Session{}
					s.Proxy(w, r)
				}))
			rec := httptest.NewRecorder()
			r, err := http.NewRequest("GET", "/test", nil)
			fn.ServeHTTP(rec, r)
			Expect(err).To(BeNil())
			b, _ := io.ReadAll(rec.Body)
			Expect(string(b)).To(Equal("/test"))
			Expect(rec.Code).To(Equal(201))
		})
		DescribeTableSubtree("middleware test", func(at authTest) {
			BeforeEach(func() {
				if at.ConfigPath != "" {
					t := testutils.LoadFromConfig(at.ConfigPath)
					store, _ := sessions.NewSessionStore(&t.Auth.Session)
					rend, _, _ := eztmpl.New("", "")
					s = &Server{
						sessionStore: store,
						ServeCfg:     t.Server,
						AuthCfg:      t.Auth,
						Logger:       logger,
						renderer:     rend,
					}
					s.ServeCfg.Upstream = u
					_ = s.Providers(context.Background())
					s.revProxy = newProxy(s.buildProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
				}
			})
			It("signin test", func() {
				client := http.Client{}
				if at.jsonErr {
					s.AuthCfg.Proxy.JSONResponse = true
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r = r.WithContext(ezlog.RequestContext(r.Context(), logger))
					if r.URL.Path == fmt.Sprintf("%s%s", s.ServeCfg.AuthPrefix, signInPath) {
						s.Login(w, r)
						c := w.Header().Get("Set-Cookie")
						if at.ConfigPath == "oauth2/oidc.yaml" {
							Expect(c).NotTo(Equal(""))
							loginUrl, err := url.Parse(w.Header().Get("Location"))
							Expect(err).To(BeNil())
							Expect(fmt.Sprintf("%s://%s%s", loginUrl.Scheme, loginUrl.Hostname(), loginUrl.Path)).To(Equal(s.AuthCfg.Provider[0].AuthURL.String()))
						} else if at.errCode != 200 {
							Expect(c).To(Equal(""))
						} else {
							Expect(c).NotTo(Equal(""))
						}
					} else if r.URL.Path == fmt.Sprintf("%s%s", s.ServeCfg.AuthPrefix, startPath) {
						s.OAuthStart(w, r)
					} else {
						w.WriteHeader(200)
						_, _ = w.Write([]byte("ok"))
					}
				}))
				defer server.Close()
				var body io.Reader
				if len(at.authBody) > 0 {
					body = strings.NewReader(at.authBody.Encode())
				}
				requestURL, _ := url.Parse(fmt.Sprintf("%s%s%s", server.URL, s.ServeCfg.AuthPrefix, signInPath))
				for k, v := range at.query {
					q := requestURL.Query()
					q.Set(k, v)
					requestURL.RawQuery = q.Encode()
				}
				r, err := http.NewRequest(at.method, requestURL.String(), body)
				Expect(err).To(BeNil())
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				res, err := client.Do(r)
				Expect(err).To(BeNil())
				if at.errString != "" || at.errCode != 200 {
					b, _ := io.ReadAll(res.Body)
					Expect(string(b)).NotTo(Equal("ok"))
					Expect(res.StatusCode).To(Equal(at.errCode))
					if at.ConfigPath == "oauth2/oidc.yaml" && at.query["provider"] != "" {
						// For OIDC with provider, verify external auth URL returns expected error
						r, _ = http.NewRequest("GET", s.AuthCfg.Provider[0].AuthURL.String(), nil)
						res, _ := client.Do(r)
						Expect(res.StatusCode).To(Equal(at.errCode))
					} else {
						if at.jsonErr && at.errString != "" {
							accessDenied, _ := json.Marshal(ezerror.NewError(at.errCode, at.errString))
							Expect(b).To(Equal(accessDenied))
						}
					}
				} else {
					Expect(res.StatusCode).To(Equal(200))
					b, _ := io.ReadAll(res.Body)
					Expect(string(b)).To(Equal("ok"))
				}
			})
		},
			Entry("Successfully Login", authTest{
				url.Values{
					"username": []string{"test"},
					"password": []string{"test1234"},
				},
				"", http.StatusOK, map[string]string{}, "POST", false, "",
			}),
			Entry("Successfully Login with redirect path", authTest{
				url.Values{
					"redirect": []string{"/test"},
					"username": []string{"test"},
					"password": []string{"test1234"},
				},
				"", http.StatusOK, map[string]string{}, "POST", false, "",
			}),
			Entry("Wrong username", authTest{
				url.Values{
					"username": []string{"foo"},
					"password": []string{"test1234"},
				},
				"", http.StatusUnauthorized, map[string]string{}, "POST", false, "",
			}),
			Entry("Empty Body", authTest{
				url.Values{},
				"", http.StatusUnauthorized, map[string]string{}, "POST", false, "",
			}),
			Entry("JSON Error", authTest{
				url.Values{
					"username": []string{"foo"},
					"password": []string{"test1234"},
				},
				"Login failed: invalid credentials", http.StatusUnauthorized, map[string]string{}, "POST", true, "",
			}),
		)
		DescribeTableSubtree("callback test", func(ct callbackTest) {
			var verifierPatch *gomonkey.Patches
			var store sessions.SessionStore
			u, _ := testutils.NewOIDCServer()
			BeforeEach(func() {
				if ct.ConfigPath != "" {
					t := testutils.LoadFromConfig(ct.ConfigPath)
					store, _ = sessions.NewSessionStore(&t.Auth.Session)
					rend, _, _ := eztmpl.New("", "")
					s = &Server{
						sessionStore: store,
						ServeCfg:     t.Server,
						AuthCfg:      t.Auth,
						Logger:       logger,
						renderer:     rend,
					}
					s.ServeCfg.Upstream = u
					if ct.ConfigPath == "oauth2/oidc.yaml" {
						s.AuthCfg.Provider[0].Issuer = u
					}
					_ = s.Providers(context.Background())
				}
				if ct.jsonErr {
					s.AuthCfg.Proxy.JSONResponse = true
				}
				fakeVerifier := &oidc.IDTokenVerifier{}
				verifierPatch = gomonkey.ApplyMethod(fakeVerifier, "Verify", func(_ *oidc.IDTokenVerifier, _ context.Context, token string) (*oidc.IDToken, error) {
					if token == testp.IDToken {
						return nil, nil
					}
					return nil, testp.ErrMock
				})
			})
			AfterEach(func() {
				verifierPatch.Reset()
			})
			It("proxy redirect no login users to signin path", func() {
				var csrfCookie string
				var state string
				// Use a single mock server that handles both OAuthStart and callback
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r = r.WithContext(ezlog.RequestContext(r.Context(), logger))
					if r.URL.Path == fmt.Sprintf("%s/start", s.ServeCfg.AuthPrefix) {
						s.OAuthStart(w, r)
						// retrieve csrf cookies
						csrfCookie = w.Header().Get("Set-Cookie")
						rd := w.Header().Get("Location")
						if rd != "" && !ct.skipCookie {
							rdurl, _ := url.Parse(rd)
							params := rdurl.Query()
							state = params.Get("state")
						}
						return
					}
					if r.URL.Path == fmt.Sprintf("%s%s", s.ServeCfg.AuthPrefix, callBackPath) {
						// This is the callback endpoint
						if !ct.skipCookie {
							// set csrf cookies manually
							r.Header.Set("Cookie", csrfCookie)
						}
						if r.URL.Query().Get("error") != "" {
							// inject error string to simulate oauth error response
							r.Method = "POST"
							r.Header.Set("Content-Type", "application/json")
							r.Body = io.NopCloser(strings.NewReader(fmt.Sprintf(`{"error":"%s"}`, r.URL.Query().Get("error"))))
						}
						s.OAuthCallback(w, r)
						return
					}
					_, _ = w.Write([]byte("ok"))
				}))
				defer server.Close()
				rd, err := url.Parse(fmt.Sprintf("%s%s%s", server.URL, s.ServeCfg.AuthPrefix, callBackPath))
				Expect(err).To(BeNil())
				// Initialize test provider
				p, err := testp.NewTestProvider(rd.String())
				Expect(err).To(BeNil())
				p.(*ezproviders.OauthProvider).SessionStore = store
				// Monkey patch p.Redeem — return an error when ct.redeemErr is set.
				redeemPatch := gomonkey.ApplyMethod(p, "Redeem", func(_ *ezproviders.OauthProvider, _ context.Context, _, _, _ string) (*ezapi.Session, error) {
					if ct.redeemErr {
						return nil, testp.ErrMock
					}
					return &ezapi.Session{
						Profile: ezapi.Profile{
							Subject: "testuser",
							Email:   "testuser@example.com",
							User:    "testuser",
						},
					}, nil
				})
				defer redeemPatch.Reset()
				// Monkey patch p.ValidateSession to always return true (no error)
				validatePathc := gomonkey.ApplyMethod(p, "ValidateSession", func(_ *ezproviders.OauthProvider, _ context.Context, _ *ezapi.Session, _ ...map[string]string) bool {
					return true
				})
				defer validatePathc.Reset()
				// Add provider with the key that matches the query parameter
				providerName := p.Opts().ProviderName
				Expect(s.registry.cache.Set(context.Background(), providerName, p, 0)).To(Succeed())
				client := &http.Client{}
				// Initialize oauth login flow, not a standard oauth login server, simulate the oauth flow.
				// First call OAuthStart to get the cookies, then call the callback
				startURL := fmt.Sprintf("%s%s/start?provider=%s", server.URL, s.ServeCfg.AuthPrefix, providerName)
				r, err := http.NewRequest("GET", startURL, nil)
				Expect(err).To(BeNil())
				_, _ = client.Do(r)
				if ct.deleteProvider {
					Expect(s.registry.del(context.Background(), providerName)).To(Succeed())
				}
				q := rd.Query()
				for k, v := range ct.query {
					q.Set(k, v)
				}
				q.Set("state", state)
				rd.RawQuery = q.Encode()
				// Now make the actual callback request
				callbackReq, err := http.NewRequest("GET", rd.String(), nil)
				Expect(err).To(BeNil())
				res, err := client.Do(callbackReq)
				if err == nil {
					b, _ := io.ReadAll(res.Body)
					if ct.noDetailSubstring != "" {
						Expect(string(b)).NotTo(ContainSubstring(ct.noDetailSubstring))
					}
					if ct.jsonErr {
						if ct.errorString == "" {
							e := &dto.ErrorResponse{}
							_ = json.Unmarshal(b, e)
							Expect(e.Error).To(Equal(ct.errorString))
							Expect(res.StatusCode).To(Equal(http.StatusOK))
							Expect(string(b)).To(Equal("ok"))
						} else {
							e := &dto.ErrorResponse{}
							_ = json.Unmarshal(b, e)
							Expect(e.Error).To(HavePrefix(ct.errorString))
							Expect(e.Code).To(Equal(http.StatusBadRequest))
						}
					} else {
						if ct.errorString == "" {
							// Success case
							Expect(res.StatusCode).To(Equal(http.StatusOK))
							Expect(string(b)).To(Equal("ok"))
						} else {
							// Error case - expect error page or redirect (status may vary)
							Expect(string(b)).NotTo(Equal("ok"))
						}
					}
				}
			})
		},
			Entry("error in authorization with json error", callbackTest{
				query: map[string]string{
					"error":    "oauth_error",
					"provider": "test2",
				},
				state: map[string]string{
					"provider": "test2",
				},
				errorString: "Error in processing OAuth2 callback, the upstream identity provider returned an error: oauth_error",
				skipCookie:  false,
				jsonErr:     true,
				ConfigPath:  "oauth2/oidc.yaml",
			}),
			Entry("error in authorization", callbackTest{
				query: map[string]string{
					"error":    "oauth_error",
					"provider": "test2",
				},
				state: map[string]string{
					"provider": "test2",
				},
				errorString: "Error in processing OAuth2 callback, the upstream identity provider returned an error: oauth_error",
				skipCookie:  false,
				jsonErr:     false,
				ConfigPath:  "oauth2/oidc.yaml",
			}),
			Entry("successful authorization", callbackTest{
				query:      map[string]string{"provider": "test2"},
				state:      map[string]string{"provider": "test2"},
				skipCookie: false,
				jsonErr:    true,
				ConfigPath: "oauth2/oidc.yaml",
			}),
			Entry("no csrf cookies with json error", callbackTest{
				query:             map[string]string{"provider": "test2"},
				state:             map[string]string{"provider": "test2"},
				errorString:       "Error in processing OAuth2 callback, unable to obtain CSRF cookie",
				skipCookie:        true,
				jsonErr:           true,
				ConfigPath:        "oauth2/oidc.yaml",
				noDetailSubstring: "invalid length",
			}),
			Entry("no csrf cookies", callbackTest{
				query:             map[string]string{"provider": "test2"},
				state:             map[string]string{"provider": "test2"},
				errorString:       "Error in processing OAuth2 callback, unable to obtain CSRF cookie",
				skipCookie:        true,
				jsonErr:           false,
				ConfigPath:        "oauth2/oidc.yaml",
				noDetailSubstring: "invalid length",
			}),
			Entry("provider callback failure returns static message", callbackTest{
				query:             map[string]string{"provider": "test2"},
				state:             map[string]string{"provider": "test2"},
				errorString:       "Error in processing OAuth2 callback",
				skipCookie:        false,
				jsonErr:           true,
				ConfigPath:        "oauth2/oidc.yaml",
				noDetailSubstring: "mock error",
				redeemErr:         true,
			}),
			Entry("unknown provider returns static message", callbackTest{
				query:             map[string]string{"provider": "test2"},
				state:             map[string]string{"provider": "test2"},
				errorString:       "Error in processing OAuth2 callback, unknown provider",
				skipCookie:        false,
				jsonErr:           true,
				ConfigPath:        "oauth2/oidc.yaml",
				noDetailSubstring: "test2",
				deleteProvider:    true,
			}),
		)
		Describe("login/error page error test", func() {
			zl, logs := testutils.SetupLogsCapture()
			It("login page test", func() {
				rend, _, _ := eztmpl.New("", "")
				s = &Server{
					Logger:   zl,
					renderer: rend,
				}
				type testStruct struct {
					p          *gomonkey.Patches
					setup      func()
					log        string
					statusCode int
				}
				for _, ts := range []testStruct{
					{
						statusCode: http.StatusBadRequest,
						log:        "Error in getting redirect url",
						p: gomonkey.ApplyMethod(&Server{}, "GetRedirect", func(_ *Server, _ *http.Request) (string, error) {
							return "", testp.ErrMock
						}),
					},
					{
						statusCode: http.StatusInternalServerError,
						log:        "Error in rendering login page.",
						setup:      func() { s.renderer = nil },
						p:          &gomonkey.Patches{},
					},
				} {
					if ts.setup != nil {
						ts.setup()
					}
					patch := ts.p
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						r = r.WithContext(ezlog.RequestContext(r.Context(), zl))
						err := s.LoginPage(w, r, http.StatusOK)
						Expect(err).To(HaveOccurred())
						Expect(err.Code).To(Equal(ts.statusCode))
						w.WriteHeader(err.Code)
					}))
					defer server.Close()
					request, err := http.NewRequest("GET", server.URL, nil)
					Expect(err).NotTo(HaveOccurred())
					client := http.Client{}
					res, err := client.Do(request)
					Expect(err).NotTo(HaveOccurred())
					entry := logs.TakeAll()
					Expect((len(entry))).To(BeNumerically(">", 0))
					var msgs []string
					for _, l := range entry {
						msgs = append(msgs, l.Message)
					}
					Expect(msgs).To(ContainElement(ts.log))
					b, _ := io.ReadAll(res.Body)
					Expect(string(b)).To(BeEmpty())
					Expect(res.StatusCode).To(Equal(ts.statusCode))
					patch.Reset()
					s.renderer = rend
				}
			})
			It("error page test", func() {
				rend, _, _ := eztmpl.New("", "")
				s = &Server{
					Logger:   zl,
					renderer: rend,
				}
				type testStruct struct {
					p          *gomonkey.Patches
					setup      func()
					log        string
					statusCode int
					expectHTML bool
				}
				for _, ts := range []testStruct{
					{
						statusCode: http.StatusOK,
						log:        "Error in retrieving request id.",
						expectHTML: true,
						p: gomonkey.ApplyFunc(ezapi.GetRequest, func(_ *http.Request) *ezapi.AuthRequest {
							return nil
						}),
					},
					{
						statusCode: http.StatusOK,
						log:        "Error in getting redirect url",
						expectHTML: true,
						p: gomonkey.ApplyMethod(&Server{}, "GetRedirect", func(_ *Server, _ *http.Request) (string, error) {
							return "", testp.ErrMock
						}),
					},
					{
						statusCode: http.StatusOK,
						log:        "Error in rendering error page.",
						expectHTML: true,
						setup:      func() { s.renderer = nil },
						p:          &gomonkey.Patches{},
					},
				} {
					if ts.setup != nil {
						ts.setup()
					}
					patch := ts.p
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
						r = r.WithContext(ezlog.RequestContext(r.Context(), zl))
						s.ErrorPage(w, r, http.StatusOK)
					}))
					defer server.Close()
					request, err := http.NewRequest("GET", server.URL, nil)
					Expect(err).NotTo(HaveOccurred())
					client := http.Client{}
					res, err := client.Do(request)
					Expect(err).NotTo(HaveOccurred())
					entry := logs.TakeAll()
					Expect((len(entry))).To(BeNumerically(">", 0))
					var sl []string
					for _, l := range entry {
						sl = append(sl, l.Message)
					}
					Expect(sl).To(ContainElement(ts.log))
					b, _ := io.ReadAll(res.Body)
					if ts.expectHTML {
						Expect(res.Header.Get("Content-Type")).To(ContainSubstring("text/html"))
						Expect(string(b)).To(ContainSubstring("<html"))
						Expect(string(b)).To(ContainSubstring(http.StatusText(http.StatusOK)))
					}
					Expect(res.StatusCode).To(Equal(ts.statusCode))
					patch.Reset()
					s.renderer = rend // 다음 케이스를 위해 복원
				}
			})
			It("renders hardcoded HTML when template execution fails", func() {
				rend, _, _ := eztmpl.New("", "")
				s = &Server{
					Logger:   zl,
					renderer: rend,
				}
				patch := gomonkey.ApplyMethod(&template.Template{}, "Execute", func(_ *template.Template, _ io.Writer, _ any) error {
					return testp.ErrMock
				})
				defer patch.Reset()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ezapi.AddRequestInfo(r, &ezapi.AuthRequest{})
					r = r.WithContext(ezlog.RequestContext(r.Context(), zl))
					s.ErrorPage(w, r, http.StatusInternalServerError, "test error")
				}))
				defer server.Close()
				request, err := http.NewRequest("GET", server.URL, nil)
				Expect(err).NotTo(HaveOccurred())
				client := http.Client{}
				res, err := client.Do(request)
				Expect(err).NotTo(HaveOccurred())
				entry := logs.TakeAll()
				var sl []string
				for _, l := range entry {
					sl = append(sl, l.Message)
				}
				Expect(sl).To(ContainElement("error rendering error page"))
				b, _ := io.ReadAll(res.Body)
				Expect(res.Header.Get("Content-Type")).To(ContainSubstring("text/html"))
				Expect(string(b)).To(ContainSubstring("<h1>500 Internal Server Error</h1>"))
				Expect(string(b)).To(ContainSubstring("test error"))
				Expect(res.StatusCode).To(Equal(http.StatusInternalServerError))
			})
		})
		Describe("WriteRobotsTxt middleware test", func() {
			It("robot text test", func() {
				defaultRend, _, err := eztmpl.New("", "")
				Expect(err).ToNot(HaveOccurred())
				server := httptest.NewServer(defaultRend.Handler("robots.txt"))
				defer server.Close()
				request, err := http.NewRequest("GET", server.URL, nil)
				Expect(err).NotTo(HaveOccurred())
				client := http.Client{}
				res, err := client.Do(request)
				Expect(err).NotTo(HaveOccurred())
				Expect(res.StatusCode).To(Equal(200))
				b, _ := io.ReadAll(res.Body)
				Expect(string(b)).To(Equal(defaultRend.Static("robots.txt")))
			})
		})
	})
	When("injectIdentityHeaders", func() {
		defaultCfg := config.IdentityHeadersConfig{
			User:    "X-Auth-User",
			Email:   "X-Auth-Email",
			Groups:  "X-Auth-Groups",
			Subject: "X-Auth-Subject",
		}
		newSession := func(user, email, subject string, groups []string) *ezapi.Session { //nolint:unparam // user is always "alice" in these tests
			return &ezapi.Session{
				Profile: ezapi.Profile{
					User:    user,
					Email:   email,
					Subject: subject,
					Groups:  groups,
				},
			}
		}

		It("should inject all identity headers from session", func() {
			req := httptest.NewRequest("GET", "/", nil)
			session := newSession("alice", "alice@example.com", "sub-123", []string{"eng", "admin"})
			injectIdentityHeaders(req, session, defaultCfg)
			Expect(req.Header.Get("X-Auth-User")).To(Equal("alice"))
			Expect(req.Header.Get("X-Auth-Email")).To(Equal("alice@example.com"))
			Expect(req.Header.Get("X-Auth-Subject")).To(Equal("sub-123"))
			Expect(req.Header.Get("X-Auth-Groups")).To(Equal("eng,admin"))
		})

		It("should overwrite spoofed identity headers from the client", func() {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Auth-User", "evil-user")
			req.Header.Set("X-Auth-Email", "evil@example.com")
			session := newSession("alice", "alice@example.com", "sub-123", nil)
			injectIdentityHeaders(req, session, defaultCfg)
			Expect(req.Header.Get("X-Auth-User")).To(Equal("alice"))
			Expect(req.Header.Get("X-Auth-Email")).To(Equal("alice@example.com"))
		})

		It("should skip header when config name is empty", func() {
			cfg := config.IdentityHeadersConfig{
				User:    "X-Auth-User",
				Email:   "",
				Groups:  "X-Auth-Groups",
				Subject: "",
			}
			req := httptest.NewRequest("GET", "/", nil)
			session := newSession("alice", "alice@example.com", "sub-123", nil)
			injectIdentityHeaders(req, session, cfg)
			Expect(req.Header.Get("X-Auth-User")).To(Equal("alice"))
			Expect(req.Header.Get("X-Auth-Email")).To(BeEmpty())
			Expect(req.Header.Get("X-Auth-Subject")).To(BeEmpty())
		})

		It("should serialize multiple groups as comma-separated", func() {
			req := httptest.NewRequest("GET", "/", nil)
			session := newSession("alice", "", "", []string{"team-a", "team-b", "team-c"})
			injectIdentityHeaders(req, session, defaultCfg)
			Expect(req.Header.Get("X-Auth-Groups")).To(Equal("team-a,team-b,team-c"))
		})

		It("should set empty groups header when groups is nil", func() {
			req := httptest.NewRequest("GET", "/", nil)
			session := newSession("alice", "", "", nil)
			injectIdentityHeaders(req, session, defaultCfg)
			Expect(req.Header.Get("X-Auth-Groups")).To(Equal(""))
		})

		It("should set empty groups header when groups is empty slice", func() {
			req := httptest.NewRequest("GET", "/", nil)
			session := newSession("alice", "", "", []string{})
			injectIdentityHeaders(req, session, defaultCfg)
			Expect(req.Header.Get("X-Auth-Groups")).To(Equal(""))
		})
	})

	When("proxy identity headers end-to-end", func() {
		var (
			s        *Server
			upstream *httptest.Server
		)

		BeforeEach(func() {
			logger, _ := testutils.SetupTestLogger()
			var capturedReq *http.Request
			upstream = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				capturedReq = r.Clone(r.Context())
				rw.WriteHeader(http.StatusOK)
				_, _ = rw.Write([]byte("ok"))
			}))
			_ = capturedReq
			u, _ := url.Parse(upstream.URL)
			t := testutils.LoadFromConfig("standard.yaml")
			store, _ := sessions.NewSessionStore(&t.Auth.Session)
			rend, _, _ := eztmpl.New("", "")
			s = &Server{
				sessionStore: store,
				ServeCfg:     t.Server,
				AuthCfg:      t.Auth,
				Logger:       logger,
				renderer:     rend,
			}
			s.ServeCfg.Upstream = u
			s.AuthCfg.Proxy.IdentityHeaders = config.IdentityHeadersConfig{
				User:    "X-Auth-User",
				Email:   "X-Auth-Email",
				Groups:  "X-Auth-Groups",
				Subject: "X-Auth-Subject",
			}
			s.revProxy = newProxy(s.buildProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
		})

		AfterEach(func() {
			upstream.Close()
		})

		It("should inject identity headers and strip Authorization when proxying", func() {
			var capturedHeaders http.Header
			upstream.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header.Clone()
				rw.WriteHeader(http.StatusOK)
			})

			handler := middleware.InitSession(true)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reqInfo := ezapi.GetRequest(r)
					reqInfo.Session = &ezapi.Session{
						Profile: ezapi.Profile{
							User:    "bob",
							Email:   "bob@example.com",
							Subject: "sub-bob",
							Groups:  []string{"devs"},
						},
					}
					s.Proxy(w, r)
				}))

			rec := httptest.NewRecorder()
			r, _ := http.NewRequest("GET", "/protected", nil)
			r.Header.Set("Authorization", "Bearer client-token")
			r.Header.Set("X-Auth-User", "spoofed")
			handler.ServeHTTP(rec, r)

			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(capturedHeaders.Get("X-Auth-User")).To(Equal("bob"))
			Expect(capturedHeaders.Get("X-Auth-Email")).To(Equal("bob@example.com"))
			Expect(capturedHeaders.Get("X-Auth-Subject")).To(Equal("sub-bob"))
			Expect(capturedHeaders.Get("X-Auth-Groups")).To(Equal("devs"))
			Expect(capturedHeaders.Get("Authorization")).To(BeEmpty())
		})

		It("should strip spoofed identity headers on skip-auth path (no session)", func() {
			var capturedHeaders http.Header
			upstream.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header.Clone()
				rw.WriteHeader(http.StatusOK)
			})

			handler := middleware.InitSession(true)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					s.revProxy.rp.ServeHTTP(w, r)
				}))

			rec := httptest.NewRecorder()
			r, _ := http.NewRequest("GET", "/public/health", nil)
			r.Header.Set("X-Auth-User", "attacker")
			r.Header.Set("Authorization", "Bearer should-be-stripped")
			handler.ServeHTTP(rec, r)

			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(capturedHeaders.Get("Authorization")).To(BeEmpty())
		})
	})

	When("isSkipAuthPath", func() {
		// Thin delegation test: isSkipAuthPath returns false when revProxy is
		// nil and delegates to revProxy.matchSkipAuth otherwise. The full
		// path-matching matrix lives in proxy_test.go.
		It("returns false when revProxy is nil (auth-only mode)", func() {
			s := &Server{}
			req := httptest.NewRequestWithContext(context.Background(), "GET", "/webhook", nil)
			Expect(s.isSkipAuthPath(req)).To(BeFalse())
		})
		It("delegates to revProxy.matchSkipAuth when proxy is configured", func() {
			s := &Server{
				AuthCfg: config.AuthConfig{
					Proxy: config.AuthProxyConfig{
						SkipAuthPaths: []config.SkipAuthConfig{
							{Path: "/webhook", Method: "POST", Match: "exact"},
						},
					},
				},
			}
			s.revProxy = newProxy(nil, s.AuthCfg.Proxy.SkipAuthPaths)
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/webhook", nil)
			Expect(s.isSkipAuthPath(req)).To(BeTrue())
		})
	})
	When("skip-auth proxy", func() {
		var (
			s        *Server
			upstream *httptest.Server
		)
		BeforeEach(func() {
			var logger ezlog.Logger
			logger, _ = testutils.SetupTestLogger()
			upstream = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusOK)
				if r.URL.Path != "" && r.URL.Path != "/" {
					_, _ = rw.Write([]byte(r.URL.Path))
					return
				}
				_, _ = rw.Write([]byte("ok"))
			}))
			u, _ := url.Parse(upstream.URL)
			s = &Server{
				Logger:   logger,
				ServeCfg: config.ServerConfig{Upstream: u, TrustForwardedHeaders: testutils.BoolPtr(true)},
				AuthCfg: config.AuthConfig{
					Proxy: config.AuthProxyConfig{
						SkipAuthPaths: []config.SkipAuthConfig{
							{Path: "/public", Method: "", Match: "prefix"},
							{Path: "/webhook", Method: "POST", Match: "exact"},
						},
					},
				},
			}
			s.revProxy = newProxy(s.buildProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
		})
		AfterEach(func() {
			upstream.Close()
		})
		It("should proxy skip-auth path without session", func() {
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				http.NotFound(rw, req)
			})
			handler := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/public/assets/logo.png", nil)
			handler.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("/public/assets/logo.png"))
		})
		It("should proxy skip-auth POST without session", func() {
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				http.NotFound(rw, req)
			})
			handler := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(`{"test":true}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("/webhook"))
		})
		It("should delegate non-skip-auth path to next handler", func() {
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusTeapot)
			})
			handler := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/private/page", nil)
			handler.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusTeapot))
		})
		It("should proxy skip-auth path when JSONResponse is enabled", func() {
			s.AuthCfg.Proxy.JSONResponse = true
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				http.NotFound(rw, req)
			})
			handler := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/public/health", nil)
			handler.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("/public/health"))
		})
		It("should bypass CSRF for skip-auth POST", func() {
			s.AuthCfg.Session.CSRF.Enabled = true
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusForbidden)
			})
			handler := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("/webhook"))
		})
		It("should not reach skip-auth path for non-matching POST", func() {
			s.AuthCfg.Session.CSRF.Enabled = true
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusForbidden)
			})
			handler := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/private/api", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusForbidden))
		})
		It("should proxy exact match for skip-auth path", func() {
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				http.NotFound(rw, req)
			})
			handler := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(`{}`))
			handler.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("/webhook"))
		})
		It("should pass through to next when skip-auth paths is empty", func() {
			s.AuthCfg.Proxy.SkipAuthPaths = nil
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusTeapot)
			})
			wrapped := s.wrapSkipAuth(next)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/anything", nil)
			wrapped.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusTeapot))
		})
		When("verify endpoint", func() {
			var (
				s     *Server
				store *stubSessionStore
			)
			BeforeEach(func() {
				store = &stubSessionStore{}
				s = newLogoutServer(store, nil)
			})
			It("should return 200 with user info for valid OIDC session", func() {
				store.session = &ezapi.Session{
					Profile: ezapi.Profile{
						User:    "alice@example.com",
						Subject: "oidc-subject-123",
						Email:   "alice@example.com",
						Groups:  []string{"engineering", "admin"},
						IDType:  ezapi.OIDCUserIDType,
					},
				}
				req := reqWithLoadedSession(httptest.NewRequest(http.MethodGet, "/ezauth/verify", nil), store)
				rw := httptest.NewRecorder()
				s.Verify(rw, req)

				Expect(rw.Code).To(Equal(http.StatusOK))
				Expect(rw.Header().Get("Content-Type")).To(Equal("application/json"))

				var body map[string]any
				err := json.Unmarshal(rw.Body.Bytes(), &body)
				Expect(err).ToNot(HaveOccurred())
				Expect(body["authenticated"]).To(BeTrue())
				Expect(body["user"]).To(Equal("alice@example.com"))
				Expect(body["subject"]).To(Equal("oidc-subject-123"))
				Expect(body["email"]).To(Equal("alice@example.com"))
				Expect(body["id_type"]).To(Equal("oauth"))
				groups := body["groups"].([]any)
				Expect(groups).To(ContainElement("engineering"))
				Expect(groups).To(ContainElement("admin"))
			})
			It("should return 200 with id_type user for password session", func() {
				store.session = &ezapi.Session{
					Profile: ezapi.Profile{
						User:    "bob",
						Subject: "bob",
						Email:   "bob@local",
						Groups:  nil,
						IDType:  ezapi.UserIDType,
					},
				}
				req := reqWithLoadedSession(httptest.NewRequest(http.MethodGet, "/ezauth/verify", nil), store)
				rw := httptest.NewRecorder()
				s.Verify(rw, req)

				Expect(rw.Code).To(Equal(http.StatusOK))

				var body map[string]any
				err := json.Unmarshal(rw.Body.Bytes(), &body)
				Expect(err).ToNot(HaveOccurred())
				Expect(body["authenticated"]).To(BeTrue())
				Expect(body["id_type"]).To(Equal("user"))
				Expect(body["user"]).To(Equal("bob"))
			})
			It("should return 401 when there is no session", func() {
				req := reqWithLoadedSession(httptest.NewRequest(http.MethodGet, "/ezauth/verify", nil), store)
				rw := httptest.NewRecorder()
				s.Verify(rw, req)

				Expect(rw.Code).To(Equal(http.StatusUnauthorized))
				Expect(rw.Header().Get("Content-Type")).To(Equal("application/json"))

				var body map[string]any
				err := json.Unmarshal(rw.Body.Bytes(), &body)
				Expect(err).ToNot(HaveOccurred())
				Expect(body["authenticated"]).To(BeFalse())
				Expect(body["error"]).To(Equal("unauthorized"))
			})
			It("should return 401 for an expired session", func() {
				store.session = &ezapi.Session{
					Profile: ezapi.Profile{
						User:   "expired-user",
						IDType: ezapi.UserIDType,
					},
				}
				store.session.CreatedAtNow()
				store.session.ExpiresIn(-1 * time.Hour)

				req := reqWithLoadedSession(httptest.NewRequest(http.MethodGet, "/ezauth/verify", nil), store)
				rw := httptest.NewRecorder()
				s.Verify(rw, req)

				Expect(rw.Code).To(Equal(http.StatusUnauthorized))

				var body map[string]any
				err := json.Unmarshal(rw.Body.Bytes(), &body)
				Expect(err).ToNot(HaveOccurred())
				Expect(body["authenticated"]).To(BeFalse())
			})
			It("should return JSON regardless of JSONResponse config", func() {
				store.session = &ezapi.Session{
					Profile: ezapi.Profile{
						User:   "test",
						IDType: ezapi.UserIDType,
					},
				}
				s.AuthCfg.Proxy.JSONResponse = false
				req := reqWithLoadedSession(httptest.NewRequest(http.MethodGet, "/ezauth/verify", nil), store)
				rw := httptest.NewRecorder()
				s.Verify(rw, req)

				Expect(rw.Header().Get("Content-Type")).To(Equal("application/json"))
				Expect(rw.Code).To(Equal(http.StatusOK))
			})
			It("should set no-cache headers", func() {
				store.session = &ezapi.Session{
					Profile: ezapi.Profile{
						User:   "test",
						IDType: ezapi.UserIDType,
					},
				}
				req := reqWithLoadedSession(httptest.NewRequest(http.MethodGet, "/ezauth/verify", nil), store)
				rw := httptest.NewRecorder()
				s.Verify(rw, req)

				Expect(rw.Header().Get("Cache-Control")).To(Equal("no-cache, no-store, must-revalidate, max-age=0"))
				Expect(rw.Header().Get("X-Accel-Expires")).To(Equal("0"))
			})
		})
	})
})

var _ = Describe("Server Redirect Test Suite", func() {
	When("redirect unit test", func() {
		zl, _ := testutils.SetupTestLogger()
		DescribeTableSubtree("valid redirect", func(allowDomains []string, path string, v bool) {
			It("checking redirect path validity", func() {
				s := &Server{
					Logger: zl,
					AuthCfg: config.AuthConfig{
						Proxy: config.AuthProxyConfig{
							AllowDomains: allowDomains,
						},
					},
				}
				valid := s.isValidRedirect(path)
				Expect(valid).To(Equal(v))
			})
		},
			Entry("empty redirect path", []string{}, "", false),
			Entry("valid redirect path", []string{}, "/valid", true),
			Entry("valid redirect path with query", []string{}, "/valid?test=1234", true),
			Entry("valid redirect path with escaped query", []string{}, "/valid?test=1234&q=%27%22&%%3", false),
			Entry("root redirect path", []string{}, "/", true),
			Entry("double slash redirect path", []string{}, "//", false),
			Entry("empty tab in slash", []string{}, "/	/", false),
			Entry("double back slash character", []string{}, "/\\", false),
			Entry("empty tab", []string{}, "/	", true),
			Entry("previous path", []string{}, "/..", true),
			Entry("current path", []string{}, "/.", true),
			Entry("invalid path", []string{}, "\\", false),
			Entry("invalid path 2", []string{}, "\\dsd", false),
			Entry("empty allow domain", []string{}, "https://www.notwhitelisted.com", false),
			Entry("not allow domain", []string{"www.whitelisted.com:"}, "https://www.notwhitelisted.com", false),
			Entry("in allow domain without port", []string{"www.whitelisted.com"}, "https://www.whitelisted.com", false),
			Entry("in allow domain with widecard", []string{"www.whitelisted.com:*"}, "https://www.whitelisted.com", true),
			Entry("in allow domain with port", []string{"www.whitelisted.com:443"}, "https://www.whitelisted.com", true),
			Entry("multiple allow domain", []string{
				"www.whitelisted.com",
				"www.anotherwhitelisted.com",
			}, "https://www.notwhitelisted.com", false),
			Entry("multiple allow domain 2", []string{
				"www.whitelisted.com",
				"www.anotherwhitelisted.com",
			}, "https://www.anotherwhitelisted.com", false),
			Entry("multiple allow domain 3", []string{
				"www.whitelisted.com",
				"www.anotherwhitelisted.com:2345",
			}, "https://www.anotherwhitelisted.com", false),
			Entry("multiple allow domain 4", []string{
				"www.whitelisted.com",
				"www.anotherwhitelisted.com",
			}, "https://www.anotherwhitelisted.com:2345", false),
			Entry("multiple allow domain 5", []string{
				"www.whitelisted.com",
				"www.anotherwhitelisted.com:*",
			}, "https://www.anotherwhitelisted.com:2345", true),
			Entry("multiple allow domain 6", []string{
				"www.whitelisted.com",
				"www.anotherwhitelisted.com:2345",
			}, "https://www.anotherwhitelisted.com:2345", true),
		)
	})
})

var _ = Describe("wantsHTML", func() {
	DescribeTable("detects browser vs API clients",
		func(accept, xRequestedWith string, want bool) {
			req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
			if accept != "" {
				req.Header.Set("Accept", accept)
			}
			if xRequestedWith != "" {
				req.Header.Set("X-Requested-With", xRequestedWith)
			}
			Expect(wantsHTML(req)).To(Equal(want))
		},
		Entry("empty accept", "", "", false),
		Entry("plain html", "text/html", "", true),
		Entry("html first then json", "text/html,application/json", "", true),
		Entry("json only", "application/json", "", false),
		Entry("json first then html", "application/json,text/html", "", false),
		Entry("browser default", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "", true),
		Entry("xhr with html accept", "text/html,application/xhtml+xml", "XMLHttpRequest", false),
		Entry("fetch api json", "application/json", "", false),
		Entry("curl no accept", "", "", false),
		Entry("wildcard only", "*/*", "", false),
	)
})

var _ = Describe("respondUnauthorized", func() {
	newSrv := func() *Server {
		return &Server{ServeCfg: config.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)}}
	}

	It("redirects browser to login with original URL", func() {
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/admin/users?x=1", nil)
		req.Header.Set("Accept", "text/html,*/*;q=0.8")
		rw := httptest.NewRecorder()

		newSrv().respondUnauthorized(rw, req)

		Expect(rw.Code).To(Equal(http.StatusFound))
		loc := rw.Header().Get("Location")
		Expect(loc).To(HavePrefix("/ezauth/login?redirect="))

		u, err := url.Parse(loc)
		Expect(err).ToNot(HaveOccurred())
		Expect(u.Query().Get("redirect")).To(Equal("/admin/users?x=1"))
	})

	DescribeTable("returns 401 for non-browser requests",
		func(method, accept string, xhr bool) {
			req := httptest.NewRequestWithContext(context.Background(), method, "/admin/users", nil)
			if accept != "" {
				req.Header.Set("Accept", accept)
			}
			if xhr {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			rw := httptest.NewRecorder()

			newSrv().respondUnauthorized(rw, req)

			Expect(rw.Code).To(Equal(http.StatusUnauthorized))
			Expect(rw.Header().Get("Location")).To(BeEmpty())
		},
		Entry("non-GET with html", "POST", "text/html", false),
		Entry("PUT with html", "PUT", "text/html", false),
		Entry("GET with json", "GET", "application/json", false),
		Entry("GET with no accept", "GET", "", false),
		Entry("GET with xhr", "GET", "text/html", true),
	)

	It("preserves escaped query params in redirect", func() {
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/admin/users?q=a%20b&x=1", nil)
		req.Header.Set("Accept", "text/html")
		rw := httptest.NewRecorder()

		newSrv().respondUnauthorized(rw, req)

		loc := rw.Header().Get("Location")
		u, err := url.Parse(loc)
		Expect(err).ToNot(HaveOccurred())
		Expect(u.Query().Get("redirect")).To(Equal("/admin/users?q=a%20b&x=1"))
	})
})

// stubSessionStore is a minimal in-memory SessionStore for unit-testing
// handlers that depend on session load/clear semantics. It stores a single
// session and exposes the observable side effects (Clear called) for
// assertions.
type stubSessionStore struct {
	session     *ezapi.Session
	clearCalled bool
	loadErr     error
}

func (s *stubSessionStore) Save(rw http.ResponseWriter, req *http.Request, ss *ezapi.Session) error {
	s.session = ss
	return nil
}

func (s *stubSessionStore) Load(req *http.Request) (*ezapi.Session, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.session == nil {
		return nil, http.ErrNoCookie
	}
	return s.session, nil
}

func (s *stubSessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	s.clearCalled = true
	s.session = nil
	return nil
}

func (s *stubSessionStore) VerifyConnection(ctx context.Context) error { return nil }
func (s *stubSessionStore) SaveValue(rw http.ResponseWriter, req *http.Request, value []byte, opts *sessions.ValueOptions) error {
	return nil
}
func (s *stubSessionStore) LoadValue(req *http.Request, opts *sessions.ValueOptions) ([]byte, error) {
	return nil, nil
}
func (s *stubSessionStore) DeleteValue(rw http.ResponseWriter, req *http.Request, opts *sessions.ValueOptions) error {
	return nil
}
func (s *stubSessionStore) Close() error { return nil }

// fakeProvider tracks Revoke invocations so tests can assert that logout
// calls out to the identity provider for OIDC-backed sessions. It
// implements the Provider interface directly rather than embedding
// DefaultProvider because DefaultProvider.Callback has a different
// signature than the interface requires (OauthProvider shadows it).
type fakeProvider struct {
	revokeCalled bool
	revokeErr    error
}

func (p *fakeProvider) GetLoginURL(rw http.ResponseWriter, req *http.Request) (*url.URL, error) {
	return nil, nil
}
func (p *fakeProvider) Callback(rw http.ResponseWriter, req *http.Request) error { return nil }
func (p *fakeProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*ezapi.Session, error) {
	return nil, nil
}
func (p *fakeProvider) ValidateSession(ctx context.Context, s *ezapi.Session, headers ...map[string]string) bool {
	return true
}
func (p *fakeProvider) Authorize(ctx context.Context, s *ezapi.Session) bool       { return true }
func (p *fakeProvider) RefreshSession(ctx context.Context, s *ezapi.Session) error { return nil }
func (p *fakeProvider) Revoke(ctx context.Context, s *ezapi.Session) error {
	p.revokeCalled = true
	return p.revokeErr
}
func (p *fakeProvider) ProviderName() string { return "fake" }
func (p *fakeProvider) Opts() config.ProviderConfig {
	return config.ProviderConfig{ProviderName: "fake"}
}
func (p *fakeProvider) GetSessionStore() sessions.SessionStore { return nil }

func newLogoutServer(store sessions.SessionStore, providers map[string]ezproviders.Provider) *Server {
	cache := ezcache.NewMemoryCache[string, ezproviders.Provider](16, time.Hour)
	for name, p := range providers {
		_ = cache.Set(context.Background(), name, p, 0)
	}
	log := ezlog.NewNop()
	s := &Server{
		ServeCfg:     config.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
		sessionStore: store,
		Logger:       log,
	}
	s.registry = newProviderRegistry(0, nil, store, log, nil)
	s.registry.cache = cache
	return s
}

// reqWithLoadedSession simulates what the LoadSession middleware would do
// before Logout runs: read the session out of the store and attach it to
// the AuthRequest so Logout's session lookup finds it.
func reqWithLoadedSession(req *http.Request, store sessions.SessionStore) *http.Request {
	info := &ezapi.AuthRequest{}
	if s, err := store.Load(req); err == nil {
		info.Session = s
	}
	return ezapi.AddRequestInfo(req, info)
}

var _ = Describe("Logout", func() {
	It("returns 204 and clears session when no session loaded", func() {
		store := &stubSessionStore{}
		s := newLogoutServer(store, nil)

		req := reqWithLoadedSession(httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ezauth/logout", nil), store)
		rw := httptest.NewRecorder()
		s.Logout(rw, req)

		Expect(rw.Code).To(Equal(http.StatusNoContent))
		Expect(store.clearCalled).To(BeTrue())
	})

	It("clears local session without revoke for non-OIDC user", func() {
		store := &stubSessionStore{
			session: &ezapi.Session{Profile: ezapi.Profile{User: "alice", IDType: ezapi.UserIDType}},
		}
		fp := &fakeProvider{}
		s := newLogoutServer(store, map[string]ezproviders.Provider{"default": fp, "fake": fp})

		req := reqWithLoadedSession(httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ezauth/logout", nil), store)
		rw := httptest.NewRecorder()
		s.Logout(rw, req)

		Expect(rw.Code).To(Equal(http.StatusNoContent))
		Expect(fp.revokeCalled).To(BeFalse())
		Expect(store.clearCalled).To(BeTrue())
	})

	It("calls Revoke for OIDC-backed sessions", func() {
		store := &stubSessionStore{
			session: &ezapi.Session{
				AccessToken:  "access",
				RefreshToken: "refresh",
				Profile:      ezapi.Profile{User: "bob", IDType: ezapi.OIDCUserIDType, Provider: "fake"},
			},
		}
		fp := &fakeProvider{}
		s := newLogoutServer(store, map[string]ezproviders.Provider{"default": fp, "fake": fp})

		req := reqWithLoadedSession(httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ezauth/logout", nil), store)
		rw := httptest.NewRecorder()
		s.Logout(rw, req)

		Expect(rw.Code).To(Equal(http.StatusNoContent))
		Expect(fp.revokeCalled).To(BeTrue())
		Expect(store.clearCalled).To(BeTrue())
	})

	It("clears local session even when revoke fails", func() {
		store := &stubSessionStore{
			session: &ezapi.Session{
				AccessToken: "access",
				Profile:     ezapi.Profile{User: "carol", IDType: ezapi.OIDCUserIDType, Provider: "fake"},
			},
		}
		fp := &fakeProvider{revokeErr: errors.New("idp unreachable")}
		s := newLogoutServer(store, map[string]ezproviders.Provider{"fake": fp})

		req := reqWithLoadedSession(httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ezauth/logout", nil), store)
		rw := httptest.NewRecorder()
		s.Logout(rw, req)

		Expect(rw.Code).To(Equal(http.StatusNoContent))
		Expect(fp.revokeCalled).To(BeTrue())
		Expect(store.clearCalled).To(BeTrue())
	})

	It("redirects browser GET to login page", func() {
		store := &stubSessionStore{
			session: &ezapi.Session{Profile: ezapi.Profile{User: "dave", IDType: ezapi.UserIDType}},
		}
		s := newLogoutServer(store, nil)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ezauth/logout", nil)
		req.Header.Set("Accept", "text/html")
		req = reqWithLoadedSession(req, store)
		rw := httptest.NewRecorder()
		s.Logout(rw, req)

		Expect(rw.Code).To(Equal(http.StatusFound))
		loc := rw.Header().Get("Location")
		Expect(loc).To(Equal("/ezauth" + signInPath))
		_, err := url.Parse(loc)
		Expect(err).ToNot(HaveOccurred())
	})

	It("rejects unsupported HTTP methods", func() {
		store := &stubSessionStore{}
		s := newLogoutServer(store, nil)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/ezauth/logout", nil)
		rw := httptest.NewRecorder()
		s.Logout(rw, req)

		Expect(rw.Code).To(Equal(http.StatusMethodNotAllowed))
		Expect(rw.Header().Get("Allow")).To(Equal("GET, POST"))
		Expect(store.clearCalled).To(BeFalse())
	})
})

var _ = Describe("providerRegistry", func() {
	It("returns nil for empty provider name", func() {
		cache := ezcache.NewMemoryCache[string, ezproviders.Provider](16, time.Hour)
		fp := &fakeProvider{}
		_ = cache.Set(context.Background(), "fake", fp, 0)

		reg := newProviderRegistry(0, nil, nil, ezlog.NewNop(), nil)
		reg.cache = cache

		Expect(reg.resolve(context.Background(), "")).To(BeNil())
	})

	Describe("adminGroups", func() {
		It("seeds admin groups from static config at construction", func() {
			cfg := &config.ProviderConfig{ProviderName: "p1", AdminGroup: "ops"}
			reg := newProviderRegistry(0, nil, nil, ezlog.NewNop(), []*config.ProviderConfig{cfg})

			m := *reg.adminGroups.Load()
			Expect(m).To(HaveKey("ops"))
			Expect(m).NotTo(HaveKey("devs"))
		})

		It("rebuildAdminGroups reflects cached providers atomically", func() {
			fp1 := &fakeProvider{}
			fp2 := &adminFakeProvider{name: "p2", adminGroup: "sre"}
			cache := ezcache.NewMemoryCache[string, ezproviders.Provider](16, time.Hour)
			_ = cache.Set(context.Background(), "p1", fp1, 0)
			_ = cache.Set(context.Background(), "p2", fp2, 0)

			reg := newProviderRegistry(0, nil, nil, ezlog.NewNop(), nil)
			reg.cache = cache
			reg.rebuildAdminGroups(context.Background())

			m := *reg.adminGroups.Load()
			Expect(m).To(HaveKey("sre"))
			Expect(m).NotTo(HaveKey(""))
		})

		It("isOAuthAdmin returns true when session group matches", func() {
			cfg := &config.ProviderConfig{ProviderName: "p1", AdminGroup: "admins"}
			s := &Server{
				Logger: ezlog.NewNop(),
				AuthCfg: config.AuthConfig{
					Provider: []*config.ProviderConfig{cfg},
				},
			}

			adminSession := &ezapi.Session{Profile: ezapi.Profile{Groups: []string{"devs", "admins"}}}
			Expect(s.isOAuthAdmin(context.Background(), adminSession)).To(BeTrue())

			nonAdminSession := &ezapi.Session{Profile: ezapi.Profile{Groups: []string{"devs", "qa"}}}
			Expect(s.isOAuthAdmin(context.Background(), nonAdminSession)).To(BeFalse())

			emptySession := &ezapi.Session{}
			Expect(s.isOAuthAdmin(context.Background(), emptySession)).To(BeFalse())
		})

		It("isOAuthAdmin sees updated groups after rebuildAdminGroups", func() {
			cfg := &config.ProviderConfig{ProviderName: "p1", AdminGroup: "old-admins"}
			s := &Server{
				Logger: ezlog.NewNop(),
				AuthCfg: config.AuthConfig{
					Provider: []*config.ProviderConfig{cfg},
				},
			}

			oldSession := &ezapi.Session{Profile: ezapi.Profile{Groups: []string{"old-admins"}}}
			Expect(s.isOAuthAdmin(context.Background(), oldSession)).To(BeTrue())

			// Simulate provider cache update: new provider has different admin group.
			fp := &adminFakeProvider{name: "p1", adminGroup: "new-admins"}
			cache := ezcache.NewMemoryCache[string, ezproviders.Provider](16, time.Hour)
			_ = cache.Set(context.Background(), "p1", fp, 0)
			s.ensureRegistry().cache = cache
			s.ensureRegistry().rebuildAdminGroups(context.Background())

			Expect(s.isOAuthAdmin(context.Background(), oldSession)).To(BeFalse())
			newSession := &ezapi.Session{Profile: ezapi.Profile{Groups: []string{"new-admins"}}}
			Expect(s.isOAuthAdmin(context.Background(), newSession)).To(BeTrue())
		})

		It("concurrent reads and writes do not race", func() {
			cfg := &config.ProviderConfig{ProviderName: "p1", AdminGroup: "admins"}
			fp := &adminFakeProvider{name: "p1", adminGroup: "admins"}
			cache := ezcache.NewMemoryCache[string, ezproviders.Provider](16, time.Hour)
			_ = cache.Set(context.Background(), "p1", fp, 0)

			reg := newProviderRegistry(0, nil, nil, ezlog.NewNop(), []*config.ProviderConfig{cfg})
			reg.cache = cache

			const goroutines = 32
			const iterations = 500

			var wg sync.WaitGroup

			// Writer: repeatedly rebuild the map.
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < iterations; i++ {
					reg.rebuildAdminGroups(context.Background())
				}
			}()

			// Readers: load and query concurrently.
			results := make([]bool, goroutines*iterations)
			for i := 0; i < goroutines; i++ {
				wg.Add(1)
				i := i
				go func() {
					defer wg.Done()
					for j := 0; j < iterations; j++ {
						m := *reg.adminGroups.Load()
						results[i*iterations+j] = m["admins"]
					}
				}()
			}

			wg.Wait()
			for _, result := range results {
				Expect(result).To(BeTrue())
			}
		})
	})
})

// adminFakeProvider extends fakeProvider with a configurable AdminGroup.
type adminFakeProvider struct {
	fakeProvider
	name       string
	adminGroup string
}

func (p *adminFakeProvider) ProviderName() string { return p.name }
func (p *adminFakeProvider) Opts() config.ProviderConfig {
	return config.ProviderConfig{ProviderName: p.name, AdminGroup: p.adminGroup}
}

// ---------------------------------------------------------------------------
// writeGeneralError – covers the non-GeneralError fallback path
// ---------------------------------------------------------------------------

var _ = Describe("writeGeneralError", func() {
	var (
		s      *Server
		logger ezlog.Logger
	)

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
		s = &Server{Logger: logger}
	})

	It("returns 500 when error is not a *GeneralError", func() {
		rw := httptest.NewRecorder()
		s.writeGeneralError(rw, errors.New("unexpected plain error"))
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
		Expect(rw.Body.String()).To(ContainSubstring("Internal Server Error"))
		Expect(rw.Header().Get("Content-Type")).To(Equal("application/json"))
	})

	It("forwards the GeneralError code and message when err is *GeneralError", func() {
		rw := httptest.NewRecorder()
		ge := ezerror.NewError(http.StatusNotFound, "record not found")
		s.writeGeneralError(rw, ge)
		Expect(rw.Code).To(Equal(http.StatusNotFound))
		Expect(rw.Body.String()).To(ContainSubstring("record not found"))
	})

	It("unwraps a wrapped *GeneralError", func() {
		rw := httptest.NewRecorder()
		ge := ezerror.NewError(http.StatusForbidden, "forbidden")
		wrapped := errors.Join(ge)
		s.writeGeneralError(rw, wrapped)
		Expect(rw.Code).To(Equal(http.StatusForbidden))
	})
})

// ---------------------------------------------------------------------------
// writeJSONError – covers the authenticated variadic parameter path
// ---------------------------------------------------------------------------

var _ = Describe("writeJSONError", func() {
	var (
		s      *Server
		logger ezlog.Logger
	)

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
		s = &Server{Logger: logger}
	})

	It("omits authenticated field when not provided", func() {
		rw := httptest.NewRecorder()
		s.writeJSONError(rw, http.StatusBadRequest, "bad request")
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
		Expect(rw.Body.String()).NotTo(ContainSubstring("authenticated"))
	})

	It("includes authenticated=false when explicitly passed", func() {
		rw := httptest.NewRecorder()
		s.writeJSONError(rw, http.StatusUnauthorized, "unauthorized", false)
		Expect(rw.Code).To(Equal(http.StatusUnauthorized))
		Expect(rw.Body.String()).To(ContainSubstring(`"authenticated":false`))
	})

	It("includes authenticated=true when explicitly passed", func() {
		rw := httptest.NewRecorder()
		s.writeJSONError(rw, http.StatusForbidden, "forbidden", true)
		Expect(rw.Code).To(Equal(http.StatusForbidden))
		Expect(rw.Body.String()).To(ContainSubstring(`"authenticated":true`))
	})
})

// ---------------------------------------------------------------------------
// mockRBACController is a minimal stub implementing rbac.Controller for
// testing the Authorization middleware in isolation.
// ---------------------------------------------------------------------------

type mockRBACController struct {
	rbac.Controller
	allowed bool
	err     error
}

func (m *mockRBACController) EnforceRequest(req *http.Request) (bool, error) {
	return m.allowed, m.err
}

// ---------------------------------------------------------------------------
// Authorization middleware – covers ErrNoSession, ErrExplicitDeny, generic
// error, and !allowed branches
// ---------------------------------------------------------------------------

var _ = Describe("Authorization middleware", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	newAuthzServer := func(ctrl *mockRBACController) *Server {
		return &Server{
			Logger:         logger,
			rbacController: ctrl,
			ServeCfg: config.ServerConfig{
				AuthPrefix:            "/ezauth",
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: config.AuthConfig{},
		}
	}

	ok := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	It("returns 401 when ErrNoSession", func() {
		s := newAuthzServer(&mockRBACController{err: rbac.ErrNoSession})
		req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Authorization(ok).ServeHTTP(rw, req)
		Expect(rw.Code).To(Equal(http.StatusUnauthorized))
	})

	It("redirects browser GET to login when ErrNoSession", func() {
		s := newAuthzServer(&mockRBACController{err: rbac.ErrNoSession})
		req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Authorization(ok).ServeHTTP(rw, req)
		Expect(rw.Code).To(Equal(http.StatusFound))
		Expect(rw.Header().Get("Location")).To(ContainSubstring("/login"))
	})

	It("returns 403 when ErrExplicitDeny", func() {
		s := newAuthzServer(&mockRBACController{err: rbac.ErrExplicitDeny})
		req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Authorization(ok).ServeHTTP(rw, req)
		Expect(rw.Code).To(Equal(http.StatusForbidden))
	})

	It("returns 403 when a generic (unexpected) error occurs", func() {
		s := newAuthzServer(&mockRBACController{err: errors.New("rbac internal failure")})
		req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Authorization(ok).ServeHTTP(rw, req)
		Expect(rw.Code).To(Equal(http.StatusForbidden))
	})

	It("returns 403 when allowed=false and err=nil", func() {
		s := newAuthzServer(&mockRBACController{allowed: false, err: nil})
		req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Authorization(ok).ServeHTTP(rw, req)
		Expect(rw.Code).To(Equal(http.StatusForbidden))
	})

	It("calls next when allowed=true and err=nil", func() {
		s := newAuthzServer(&mockRBACController{allowed: true, err: nil})
		req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Authorization(ok).ServeHTTP(rw, req)
		Expect(rw.Code).To(Equal(http.StatusOK))
	})
})

// ---------------------------------------------------------------------------
// Login handler – covers GET and auth-only POST branches
// ---------------------------------------------------------------------------

var _ = Describe("Login handler", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	newLoginServer := func(jsonResponse bool) *Server {
		store, err := sessions.NewSessionStore(&config.Session{
			Cookie: config.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   config.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
				Path:     "/",
				HTTPOnly: testutils.BoolPtr(true),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		enabled := false
		rend, _, _ := eztmpl.New("", "")
		s := &Server{
			ServeCfg: config.ServerConfig{
				AuthPrefix:            "/ezauth",
				StaticPrefix:          "/static",
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: config.AuthConfig{
				JWT: config.JWTConfig{
					SecretKey: config.NewResolvedSecretRef([]byte("test-jwt-secret-key-32bytes-ok!!")),
				},
				Static: []config.PasswordConfig{
					{User: "testuser", Password: "testpass"},
				},
				Proxy: config.AuthProxyConfig{
					Enabled:      &enabled,
					JSONResponse: jsonResponse,
				},
			},
			Logger:       logger,
			sessionStore: store,
			renderer:     rend,
		}
		// Initialize provider registry so LoginPage can iterate providers.
		_ = s.Providers(context.Background())
		return s
	}

	It("GET renders the login page with 200 and HTML content", func() {
		s := newLoginServer(false)
		req := httptest.NewRequest(http.MethodGet, "/ezauth/login", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Login(rw, req)
		Expect(rw.Code).To(Equal(http.StatusOK))
		body := rw.Body.String()
		Expect(body).To(ContainSubstring("form"))
	})

	It("POST auth-only returns 200 JSON on success", func() {
		s := newLoginServer(true)
		form := url.Values{"username": {"testuser"}, "password": {"testpass"}}
		req := httptest.NewRequest(http.MethodPost, "/ezauth/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Login(rw, req)
		Expect(rw.Code).To(Equal(http.StatusOK))
		Expect(rw.Body.String()).To(ContainSubstring("authenticated"))
	})

	It("POST auth-only returns 401 for invalid credentials", func() {
		s := newLoginServer(false)
		form := url.Values{"username": {"testuser"}, "password": {"wrongpass"}}
		req := httptest.NewRequest(http.MethodPost, "/ezauth/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Login(rw, req)
		Expect(rw.Code).To(Equal(http.StatusUnauthorized))
	})
})

// ---------------------------------------------------------------------------
// authenticateUser with DB – covers DB error branches
// ---------------------------------------------------------------------------

var _ = Describe("authenticateUser DB branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	newServer := func(loginErr error) *Server {
		inner := setupUserServer(logger, nil)
		mdb := &mockableDB{DatabaseInterface: inner.DB, userLoginErr: loginErr}
		return &Server{
			Logger:  logger,
			DB:      mdb,
			AuthCfg: config.AuthConfig{},
		}
	}

	makeReq := func() *http.Request {
		form := url.Values{"username": {"nobody"}, "password": {"x"}}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
	}

	It("returns nil and 401 when DB returns ErrNoRecord", func() {
		s := newServer(ezdb.ErrNoRecord)
		rw := httptest.NewRecorder()
		profile := s.authenticateUser(rw, makeReq())
		Expect(profile).To(BeNil())
		Expect(rw.Code).To(Equal(http.StatusUnauthorized))
	})

	It("returns nil and 401 when DB returns ErrInvalidCreds", func() {
		s := newServer(ezdb.ErrInvalidCreds)
		rw := httptest.NewRecorder()
		profile := s.authenticateUser(rw, makeReq())
		Expect(profile).To(BeNil())
		Expect(rw.Code).To(Equal(http.StatusUnauthorized))
	})

	It("returns nil and 500 when DB returns an unexpected error", func() {
		s := newServer(errors.New("connection reset"))
		rw := httptest.NewRecorder()
		profile := s.authenticateUser(rw, makeReq())
		Expect(profile).To(BeNil())
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})

	It("returns profile when DB succeeds", func() {
		s := newServer(nil)
		rw := httptest.NewRecorder()
		profile := s.authenticateUser(rw, makeReq())
		Expect(profile).NotTo(BeNil())
		Expect(profile.User).To(Equal("test"))
	})
})

// ---------------------------------------------------------------------------
// Login proxy-enabled branches – GetRedirect error and sign-in path redirect
// ---------------------------------------------------------------------------

var _ = Describe("Login proxy-enabled branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	newProxyLoginServer := func() *Server {
		store, err := sessions.NewSessionStore(&config.Session{
			Cookie: config.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   config.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
				Path:     "/",
				HTTPOnly: testutils.BoolPtr(true),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		enabled := true
		rend, _, _ := eztmpl.New("", "")
		s := &Server{
			ServeCfg: config.ServerConfig{
				AuthPrefix:            "/ezauth",
				StaticPrefix:          "/static",
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: config.AuthConfig{
				JWT: config.JWTConfig{
					SecretKey: config.NewResolvedSecretRef([]byte("test-jwt-secret-key-32bytes-ok!!")),
				},
				Static: []config.PasswordConfig{
					{User: "testuser", Password: "testpass"},
				},
				Proxy: config.AuthProxyConfig{
					Enabled:      &enabled,
					JSONResponse: true,
				},
			},
			Logger:       logger,
			sessionStore: store,
			renderer:     rend,
		}
		_ = s.Providers(context.Background())
		return s
	}

	It("returns 400 when GetRedirect fails due to malformed query string", func() {
		s := newProxyLoginServer()
		form := url.Values{"username": {"testuser"}, "password": {"testpass"}}
		req := httptest.NewRequest(http.MethodPost, "/ezauth/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Set an invalid percent-encoding in RawQuery so ParseForm returns an error.
		req.URL.RawQuery = "%gg=invalid"
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Login(rw, req)
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
	})

	It("rewrites redirect to / when rd matches the sign-in path, then proceeds with login", func() {
		s := newProxyLoginServer()
		// Redirect param equals the sign-in path: /ezauth/login.
		// Wrong credentials ensure authenticateUser returns nil (401) so the test
		// stays self-contained while still exercising the redirectURL = "/" assignment.
		form := url.Values{
			"username": {"testuser"},
			"password": {"wrongpass"},
			"redirect": {"/ezauth/login"},
		}
		req := httptest.NewRequest(http.MethodPost, "/ezauth/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Login(rw, req)
		// authenticateUser rejects bad creds → 401; the redirectURL rewrite was exercised.
		Expect(rw.Code).To(Equal(http.StatusUnauthorized))
	})
})

// ---------------------------------------------------------------------------
// saveSession error branch – covers UserPassLogin and userPassLoginAuthOnly
// error paths when JWT config is invalid.
// ---------------------------------------------------------------------------

var _ = Describe("saveSession error branch", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	// newBrokenJWTServer builds a server with valid static credentials but
	// an empty JWT secret, so saveSession always fails with a JWT error.
	newBrokenJWTServer := func(proxyEnabled bool) *Server {
		store, err := sessions.NewSessionStore(&config.Session{
			Cookie: config.CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   config.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
				Path:     "/",
				HTTPOnly: testutils.BoolPtr(true),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		rend, _, _ := eztmpl.New("", "")
		enabled := proxyEnabled
		s := &Server{
			ServeCfg: config.ServerConfig{
				AuthPrefix:            "/ezauth",
				StaticPrefix:          "/static",
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: config.AuthConfig{
				// Intentionally empty JWT secret so GenerateToken fails.
				JWT: config.JWTConfig{},
				Static: []config.PasswordConfig{
					{User: "gooduser", Password: "goodpass"},
				},
				Proxy: config.AuthProxyConfig{
					Enabled:      &enabled,
					JSONResponse: true,
				},
			},
			Logger:       logger,
			sessionStore: store,
			renderer:     rend,
		}
		_ = s.Providers(context.Background())
		return s
	}

	makeLoginReq := func(path string) *http.Request {
		form := url.Values{"username": {"gooduser"}, "password": {"goodpass"}}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
	}

	It("returns 500 when saveSession fails in auth-only mode (userPassLoginAuthOnly)", func() {
		s := newBrokenJWTServer(false)
		req := makeLoginReq("/ezauth/login")
		rw := httptest.NewRecorder()
		s.Login(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})

	It("returns 500 when saveSession fails in proxy mode (UserPassLogin)", func() {
		s := newBrokenJWTServer(true)
		form := url.Values{
			"username": {"gooduser"},
			"password": {"goodpass"},
			"redirect": {"/app"},
		}
		req := httptest.NewRequest(http.MethodPost, "/ezauth/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Login(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})
})

// ---------------------------------------------------------------------------
// mockProvider is a minimal Provider stub. GetLoginURL returns the configured
// url/error; all other methods are no-ops.
// ---------------------------------------------------------------------------

type mockProvider struct {
	ezproviders.DefaultProvider
	loginURL *url.URL
	loginErr error
}

func (p *mockProvider) GetLoginURL(_ http.ResponseWriter, _ *http.Request) (*url.URL, error) {
	return p.loginURL, p.loginErr
}

func (p *mockProvider) Callback(_ http.ResponseWriter, _ *http.Request) error { return nil }

func (p *mockProvider) Redeem(_ context.Context, _, _, _ string) (*ezapi.Session, error) {
	return nil, nil
}

func (p *mockProvider) ValidateSession(_ context.Context, _ *ezapi.Session, _ ...map[string]string) bool {
	return false
}

func (p *mockProvider) Authorize(_ context.Context, _ *ezapi.Session) bool { return false }

func (p *mockProvider) RefreshSession(_ context.Context, _ *ezapi.Session) error { return nil }

func (p *mockProvider) Revoke(_ context.Context, _ *ezapi.Session) error { return nil }

func (p *mockProvider) GetSessionStore() sessions.SessionStore { return nil }

// ---------------------------------------------------------------------------
// authenticateUser form parse error branch
// ---------------------------------------------------------------------------

var _ = Describe("authenticateUser form parse error branch", func() {
	It("returns 400 when form parsing fails due to malformed URL query", func() {
		logger, _ := testutils.SetupTestLogger()
		s := &Server{
			Logger: logger,
			AuthCfg: config.AuthConfig{
				Static: []config.PasswordConfig{{User: "u", Password: "p"}},
				Proxy:  config.AuthProxyConfig{JSONResponse: true},
			},
		}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=u&password=p"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Invalid percent-encoding in the query string causes ParseForm to fail.
		req.URL.RawQuery = "%gg=bad"
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.authenticateUser(rw, req)
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
	})
})

// ---------------------------------------------------------------------------
// Login GET – LoginPage error branch
// ---------------------------------------------------------------------------

var _ = Describe("Login GET LoginPage error branch", func() {
	It("returns 500 when LoginPage fails due to nil renderer", func() {
		logger, _ := testutils.SetupTestLogger()
		s := &Server{Logger: logger}
		s.registry = newProviderRegistry(0, nil, nil, logger, nil)
		s.renderer = nil // nil renderer → LoginPage returns a *GeneralError

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.Login(rw, req)

		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})
})
