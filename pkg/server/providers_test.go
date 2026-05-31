package server

import (
	"context"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/lib/pq"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	"github.com/flipcloud-ai/ezauth/pkg/providers"
	eztmpl "github.com/flipcloud-ai/ezauth/pkg/server/templates"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	dbProviderName = "database-provider"
)

// newServerWithCache creates a Server with the given cache wired into its registry.
func newServerWithCache(cache ezcache.Cache[string, providers.Provider], log ezlog.Logger, db database.DatabaseInterface) *Server {
	s := &Server{Logger: log, DB: db}
	s.registry = newProviderRegistry(0, db, nil, log, nil)
	s.registry.cache = cache
	return s
}

// providerColumns returns the full list of provider columns for mock rows
func providerColumns() []string {
	return []string{
		"provider_name", "type", "redirect_url", "device_auth_url", "validate_url",
		"allowed_groups", "admin_group", "claims_from_profile",
		"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
		"userinfo_endpoint", "revocation_endpoint", "code_challenge_methods_supported",
		"id_token_signing_alg_values_supported", "protected_resource",
		"scope", "client_id", "client_secret", "user_claim", "skip_nonce",
		"login_parameters", "created_at", "updated_at", "enabled",
	}
}

// createProviderRow creates a mock row for a given provider name
func createProviderRow(providerName string) []driver.Value {
	switch providerName {
	case "google":
		return []driver.Value{
			"google", "oidc",
			"https://example.com/callback", "https://device.auth.url", "https://validate.url",
			pq.StringArray{"admin", "users"}, "", true,
			"https://issuer.url", "https://auth.url", "https://token.url", "https://jwks.url",
			"https://userinfo.url", nil, pq.StringArray{"S256"}, pq.StringArray{"RS256"}, "https://resource.url",
			"openid profile", "client-id-123", "secret-456", "sub", false,
			"{}", time.Now(), time.Now(), true,
		}
	case "okta":
		return []driver.Value{
			"okta", "oidc",
			"https://example.okta.com/callback", "https://device.okta.url", "https://validate.okta.url",
			pq.StringArray{"admin", "users"}, "", false,
			"https://okta.issuer.url", "https://okta.auth.url", "https://okta.token.url", "https://okta.jwks.url",
			"https://okta.userinfo.url", nil, pq.StringArray{"S256"}, pq.StringArray{"RS256"}, "https://okta.resource.url",
			"openid profile email", "okta-client-id-123", "okta-secret-456", "sub", false,
			"{}", time.Now(), time.Now(), true,
		}
	case "database-provider":
		return []driver.Value{
			"database-provider", "oidc",
			"https://db.example.com/callback", "https://device.db.url", "https://validate.db.url",
			pq.StringArray{"users"}, "", true,
			"https://db.issuer.url", "https://db.auth.url", "https://db.token.url", "https://db.jwks.url",
			"https://db.userinfo.url", nil, pq.StringArray{"S256"}, pq.StringArray{"RS256"}, "https://db.resource.url",
			"openid profile", "db-client-id", "db-secret", "sub", false,
			"{}", time.Now(), time.Now(), true,
		}
	case "test-provider":
		return []driver.Value{
			"test-provider", "oidc",
			"https://test.example.com/callback", "https://device.test.url", "https://validate.test.url",
			pq.StringArray{"users"}, "", true,
			"https://test.issuer.url", "https://test.auth.url", "https://test.token.url", "https://test.jwks.url",
			"https://test.userinfo.url", nil, pq.StringArray{"S256"}, pq.StringArray{"RS256"}, "https://test.resource.url",
			"openid profile", "test-client-id", "test-secret", "sub", false,
			"{}", time.Now(), time.Now(), true,
		}
	default:
		return nil
	}
}

// mockOauthProvider is a monkey patch wrapper for OauthProvider
type mockOauthProvider struct {
	*providers.OauthProvider
}

func (p *mockOauthProvider) Opts() ezcfg.ProviderConfig {
	opts := ezcfg.ProviderConfig{}
	opts.ProviderName = dbProviderName
	return opts
}

type providerTestCase struct {
	name           string
	providerName   string
	expectedName   string
	cacheProviders []string
	dbProviderName string
	findInDB       bool
	hasProvider    bool
}

var _ = Describe("Server Provider Method Test Suite", func() {
	var opts ezcfg.Options
	var sessionStore sessions.SessionStore

	BeforeEach(func() {
		opts = testutils.LoadFromConfig("oauth2/oidc.yaml")
		var err error
		sessionStore, err = sessions.NewSessionStore(&opts.Auth.Session)
		Expect(err).To(BeNil())
	})

	DescribeTableSubtree("s.provider method tests",
		func(tc providerTestCase) {
			var mockDB *pgx.PGxDB
			logger, _ := testutils.SetupTestLogger()

			BeforeEach(func() {
				gormDB, mockSQL, err := testutils.MockSQLPool()
				Expect(err).ToNot(HaveOccurred())

				mockDB = &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB

				if tc.dbProviderName != "" {
					providerRow := createProviderRow(tc.dbProviderName)
					if providerRow != nil {
						rows := mockSQL.NewRows(providerColumns()).AddRow(providerRow...)
						mockSQL.ExpectQuery(`SELECT \* FROM "providers"`).
							WithArgs(tc.dbProviderName, 1).WillReturnRows(rows)
					}
				}
			})

			It(tc.name, func(ctx SpecContext) {
				issuerURL, _ := url.Parse("https://dev-z3tqqsmunxppeufg.us.auth0.com")
				var cache ezcache.Cache[string, providers.Provider]
				var patch *gomonkey.Patches

				if tc.hasProvider && len(tc.cacheProviders) > 0 {
					providerConfigs := make([]*ezcfg.ProviderConfig, 0, len(tc.cacheProviders))
					for _, name := range tc.cacheProviders {
						providerConfigs = append(providerConfigs, &ezcfg.ProviderConfig{
							ProviderName: name, Type: "oidc",
							OIDCConfig:  ezcfg.OIDCConfig{Issuer: issuerURL},
							RedirectURL: &url.URL{Path: "https://127.0.0.1:8443/oauth2/callback"},
							ClientID:    "test-client-id",
						})
					}
					ps, err := providers.NewProvider(providerConfigs, sessionStore)
					Expect(err).To(BeNil())

					mc := ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour)
					for name, p := range ps {
						_ = mc.Set(context.Background(), name, p, 0)
					}
					cache = mc
				}

				if patch != nil {
					patch.Reset()
				}

				logger, _ := testutils.SetupTestLogger()
				s := &Server{Logger: logger, sessionStore: sessionStore, AuthCfg: opts.Auth}
				s.registry = newProviderRegistry(10, nil, sessionStore, logger, nil)

				if tc.hasProvider && cache != nil {
					s.registry.cache = cache
				}

				if tc.findInDB {
					patch = gomonkey.ApplyFunc(providers.NewProvider, func(opts []*ezcfg.ProviderConfig, sessionStore sessions.SessionStore, ctxArgs ...context.Context) (map[string]providers.Provider, error) {
						return map[string]providers.Provider{tc.providerName: &mockOauthProvider{}}, nil
					})
					defer patch.Reset()
					s.DB = mockDB
					s.registry.db = mockDB
				}

				result := s.registry.resolve(context.Background(), tc.providerName)
				if tc.expectedName == "" {
					Expect(result).To(BeNil())
				} else {
					Expect(result).ToNot(BeNil())
					Expect(result.Opts().ProviderName).To(Equal(tc.expectedName))
				}
			})
		},
		Entry("should return provider by name from cache", providerTestCase{
			name: "should return provider by name from cache", providerName: "google",
			expectedName: "google", cacheProviders: []string{"google"}, hasProvider: true,
		}),
		Entry("should return provider from database when not in cache", providerTestCase{
			name: "should return provider from database when not in cache", providerName: "google",
			expectedName: dbProviderName, cacheProviders: []string{"cached-provider"}, dbProviderName: "google", findInDB: true, hasProvider: true,
		}),
		Entry("should return nil when provider not found in cache and no database", providerTestCase{
			name: "should return nil when provider not found in cache and no database", providerName: "nonexistent",
			expectedName: "", cacheProviders: []string{"cached-provider"}, hasProvider: true,
		}),
		Entry("should return nil when provider not found in cache and not found in database", providerTestCase{
			name: "should return nil when provider not found in cache and not found in database", providerName: "nonexistent",
			expectedName: "", cacheProviders: []string{"cached-provider"}, dbProviderName: "google", hasProvider: true,
		}),
		Entry("should return nil when Provider is nil", providerTestCase{
			name: "should return nil when Provider is nil", providerName: "",
			expectedName: "", hasProvider: false,
		}),
	)
})

var _ = Describe("Server Provider API Test Suite", func() {
	var opts ezcfg.Options
	var sessionStore sessions.SessionStore
	var testRedirectURL *url.URL
	logger, _ := testutils.SetupTestLogger()

	BeforeEach(func() {
		opts = testutils.LoadFromConfig("oauth2/oidc.yaml")
		var err error
		sessionStore, err = sessions.NewSessionStore(&opts.Auth.Session)
		Expect(err).To(BeNil())
		testRedirectURL, _ = url.Parse("https://127.0.0.1:8443" + opts.Server.AuthPrefix + "/callback")
	})

	DescribeTableSubtree("GetProvider API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, func(s *Server, r *mux.Router) { s.providerRouter(r) }, logger) })
		},
		Entry("should return 404 when provider not found and no database", apiTestCase{
			name: "should return 404 when provider not found and no database", method: http.MethodGet,
			path: "/nonexistent",
			setupServer: func() *Server {
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, nil)
			},
			expectedStatus: http.StatusNotFound, expectedBody: "provider not found",
		}),
		Entry("should return 404 when provider not found in cache and DB", apiTestCase{
			name: "should return 404 when provider not found in cache and DB", method: http.MethodGet,
			path: "/missing-provider",
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				mockSQL.ExpectQuery(`SELECT \* FROM "providers"`).
					WithArgs("missing-provider", 1).WillReturnRows(mockSQL.NewRows(providerColumns()))
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, mockDB)
			},
			expectedStatus: http.StatusNotFound, expectedBody: "provider not found",
		}),
		Entry("should return 200 with provider from cache", apiTestCase{
			name: "should return 200 with provider from cache", method: http.MethodGet,
			path: "/test-provider",
			setupServer: func() *Server {
				issuerURL, _ := url.Parse("https://dev-z3tqqsmunxppeufg.us.auth0.com")
				providerConfigs := []*ezcfg.ProviderConfig{{
					ProviderName: "test-provider", Type: "oauth2",
					OIDCConfig:  ezcfg.OIDCConfig{Issuer: issuerURL},
					RedirectURL: testRedirectURL, ClientID: "test-client-id",
				}}
				ps, _ := providers.NewProvider(providerConfigs, sessionStore)
				cache := ezcache.NewMemoryCache[string, providers.Provider](10, 0)
				for name, p := range ps {
					_ = cache.Set(context.Background(), name, p, 0)
				}
				return newServerWithCache(cache, logger, nil)
			},
			expectedStatus: http.StatusOK, expectedBody: "test-provider",
		}),
		Entry("should return 200 with provider from database when not in cache", apiTestCase{
			name: "should return 200 with provider from database when not in cache", method: http.MethodGet,
			path:      "/database-provider",
			setupMock: func() {},
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				rows := mockSQL.NewRows(providerColumns()).AddRow(createProviderRow("database-provider")...)
				mockSQL.ExpectQuery(`SELECT \* FROM "providers"`).
					WithArgs("database-provider", 1).WillReturnRows(rows)
				cache := ezcache.NewMemoryCache[string, providers.Provider](10, 0)
				return newServerWithCache(cache, logger, mockDB)
			},
			expectedStatus: http.StatusOK, expectedBody: "database-provider",
		}),
	)

	DescribeTableSubtree("ListProviders API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, func(s *Server, r *mux.Router) { s.providerRouter(r) }, logger) })
		},
		Entry("should return static providers even with no database", apiTestCase{
			name: "should return static providers even with no database", method: http.MethodGet,
			path: "/",
			setupServer: func() *Server {
				s := &Server{Logger: logger}
				s.AuthCfg = opts.Auth
				return s
			},
			expectedStatus: http.StatusOK, expectedBody: `"static":true`,
		}),
		Entry("should return static providers and db providers together", apiTestCase{
			name: "should return static providers and db providers together", method: http.MethodGet,
			path: "/",
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				rows := mockSQL.NewRows(providerColumns()).AddRow(createProviderRow(dbProviderName)...)
				mockSQL.ExpectQuery(`SELECT \* FROM "providers"`).WillReturnRows(rows)
				s := &Server{Logger: logger, DB: mockDB}
				s.AuthCfg = opts.Auth
				return s
			},
			expectedStatus: http.StatusOK, expectedBody: dbProviderName,
		}),
		Entry("should mark db providers as non-static", apiTestCase{
			name: "should mark db providers as non-static", method: http.MethodGet,
			path: "/",
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				rows := mockSQL.NewRows(providerColumns()).AddRow(createProviderRow(dbProviderName)...)
				mockSQL.ExpectQuery(`SELECT \* FROM "providers"`).WillReturnRows(rows)
				s := &Server{Logger: logger, DB: mockDB}
				s.AuthCfg.Provider = nil
				return s
			},
			expectedStatus: http.StatusOK, expectedBody: `"static":false`,
		}),
	)

	DescribeTableSubtree("AddProvider API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, func(s *Server, r *mux.Router) { s.providerRouter(r) }, logger) })
		},
		Entry("should return 404 when no database configured", apiTestCase{
			name: "should return 404 when no database configured", method: http.MethodPost,
			path:           "/",
			body:           `{"provider_name":"test"}`,
			setupServer:    func() *Server { return &Server{Logger: logger} },
			expectedStatus: http.StatusNotFound,
		}),
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/",
			body: `invalid json`,
			setupServer: func() *Server {
				gormDB, _, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				return &Server{Logger: logger, DB: mockDB}
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "Bad Request",
		}),
		Entry("should return 201 when provider added successfully", apiTestCase{
			name: "should return 201 when provider added successfully", method: http.MethodPost,
			path:      "/",
			body:      `{"provider_name":"database-provider","type":"oauth2","client_id":"test","client_secret":"ttttt","issuer_url":"https://example.com","cookie":{"secret":"defaultcookiecrd123456"}}`,
			setupMock: func() {},
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				mockSQL.ExpectBegin()
				mockSQL.ExpectQuery(`INSERT INTO "providers"`).
					WillReturnRows(mockSQL.NewRows(providerColumns()).AddRow(createProviderRow("database-provider")...))
				mockSQL.ExpectCommit()
				return &Server{Logger: logger, DB: mockDB}
			},
			expectedStatus: http.StatusCreated,
		}),
		Entry("should return 409 when provider name conflicts with static config", apiTestCase{
			name: "should return 409 when provider name conflicts with static config", method: http.MethodPost,
			path: "/",
			body: `{"provider_name":"test2","type":"oidc"}`,
			setupServer: func() *Server {
				gormDB, _, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				s := &Server{Logger: logger, DB: mockDB}
				s.AuthCfg = opts.Auth
				return s
			},
			expectedStatus: http.StatusConflict, expectedBody: "conflicts with a statically configured provider",
		}),
	)

	DescribeTableSubtree("UpdateProvider API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, func(s *Server, r *mux.Router) { s.providerRouter(r) }, logger) })
		},
		Entry("should return 404 when no database configured", apiTestCase{
			name: "should return 404 when no database configured", method: http.MethodPut,
			path: "/test-provider",
			body: `{"provider_name":"test"}`,
			setupServer: func() *Server {
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, nil)
			},
			expectedStatus: http.StatusNotFound,
		}),
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPut,
			path: "/test-provider",
			body: `invalid json`,
			setupServer: func() *Server {
				gormDB, _, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, mockDB)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "Bad Request",
		}),
		Entry("should return 404 when provider not found in database", apiTestCase{
			name: "should return 404 when provider not found in database", method: http.MethodPut,
			path:      "/nonexistent",
			body:      `{"provider_name":"nonexistent"}`,
			setupMock: func() {},
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`UPDATE "providers"`).WillReturnResult(sqlmock.NewResult(0, 0))
				mockSQL.ExpectCommit()
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, mockDB)
			},
			expectedStatus: http.StatusNotFound, expectedBody: "provider not found",
		}),
		Entry("should return 200 when provider updated successfully", apiTestCase{
			name: "should return 200 when provider updated successfully", method: http.MethodPut,
			path:      "/existing-provider",
			body:      `{"provider_name":"existing-provider","type":"oauth2","client_id":"updated","client_secret":"test","issuer_url":"https://example.com"}`,
			setupMock: func() {},
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`UPDATE "providers"`).WillReturnResult(sqlmock.NewResult(1, 1))
				mockSQL.ExpectCommit()
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, mockDB)
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 409 when updating a static provider", apiTestCase{
			name: "should return 409 when updating a static provider", method: http.MethodPut,
			path: "/test2",
			body: `{"type":"oauth2"}`,
			setupServer: func() *Server {
				gormDB, _, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				s := &Server{Logger: logger, DB: mockDB}
				s.AuthCfg = opts.Auth
				return s
			},
			expectedStatus: http.StatusConflict, expectedBody: "statically configured",
		}),
	)

	DescribeTableSubtree("DeleteProvider API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, func(s *Server, r *mux.Router) { s.providerRouter(r) }, logger) })
		},
		Entry("should return 404 when no database configured", apiTestCase{
			name: "should return 404 when no database configured", method: http.MethodDelete,
			path: "/test-provider",
			body: "",
			setupServer: func() *Server {
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, nil)
			},
			expectedStatus: http.StatusNotFound,
		}),
		Entry("should return 404 when provider not found in database", apiTestCase{
			name: "should return 404 when provider not found in database", method: http.MethodDelete,
			path:      "/nonexistent",
			body:      "",
			setupMock: func() {},
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`DELETE FROM "providers"`).WillReturnResult(sqlmock.NewResult(0, 0))
				mockSQL.ExpectCommit()
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, mockDB)
			},
			expectedStatus: http.StatusNotFound, expectedBody: "provider not found",
		}),
		Entry("should return 200 when provider deleted successfully", apiTestCase{
			name: "should return 200 when provider deleted successfully", method: http.MethodDelete,
			path:      "/test-provider",
			body:      "",
			setupMock: func() {},
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`DELETE FROM "providers"`).WillReturnResult(sqlmock.NewResult(1, 1))
				mockSQL.ExpectCommit()
				return newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, mockDB)
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 200 deleting a static provider (DB-only removal, cache survives)", apiTestCase{
			// Static providers are defined in config; the API does not block the DELETE
			// because the OIDC instance in the cache will continue to serve requests.
			// This test documents the current behaviour: the handler succeeds as long as
			// the DB row exists, and the cache entry persists.
			name: "should return 200 deleting a static provider (DB-only removal, cache survives)", method: http.MethodDelete,
			path:      "/test2",
			body:      "",
			setupMock: func() {},
			setupServer: func() *Server {
				gormDB, mockSQL, _ := testutils.MockSQLPool()
				mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
				mockDB.DB = gormDB
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`DELETE FROM "providers"`).WillReturnResult(sqlmock.NewResult(1, 1))
				mockSQL.ExpectCommit()
				s := newServerWithCache(ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour), logger, mockDB)
				s.AuthCfg = opts.Auth
				return s
			},
			expectedStatus: http.StatusOK,
		}),
	)
})

var _ = Describe("GetProvider nil cache guard", func() {
	logger, _ := testutils.SetupTestLogger()

	It("returns 404 when s.Provider is nil", func() {
		s := &Server{Logger: logger}
		router := mux.NewRouter()
		s.providerRouter(router)

		req, _ := http.NewRequest(http.MethodGet, "/some-provider", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusNotFound))
		Expect(rr.Body.String()).To(ContainSubstring("provider not found"))
	})
})

var _ = Describe("Server Providers Initialization Test Suite", func() {
	var opts ezcfg.Options
	var sessionStore sessions.SessionStore
	logger, _ := testutils.SetupTestLogger()

	BeforeEach(func() {
		opts = testutils.LoadFromConfig("oauth2/oidc.yaml")
		var err error
		sessionStore, err = sessions.NewSessionStore(&opts.Auth.Session)
		Expect(err).To(BeNil())
	})

	It("should initialize providers from config", func() {
		issuerURL, _ := url.Parse("https://dev-z3tqqsmunxppeufg.us.auth0.com")
		opts.Auth.Provider = []*ezcfg.ProviderConfig{{
			ProviderName: "test-provider", Type: "oauth2",
			OIDCConfig:  ezcfg.OIDCConfig{Issuer: issuerURL},
			RedirectURL: &url.URL{Path: "https://127.0.0.1:8443/oauth2/callback"},
			ClientID:    "test-client-id",
		}}
		opts.Auth.ProviderCache.Size = 10
		s := &Server{Logger: logger, sessionStore: sessionStore, AuthCfg: opts.Auth, DB: nil}
		err := s.Providers(context.Background())
		Expect(err).To(BeNil())
		Expect(s.registry).NotTo(BeNil())
		Expect(s.registry.cache).NotTo(BeNil())
	})

	It("should initialize providers with empty config", func() {
		opts.Auth.Provider = []*ezcfg.ProviderConfig{}
		opts.Auth.ProviderCache.Size = 10
		s := &Server{Logger: logger, sessionStore: sessionStore, AuthCfg: opts.Auth, DB: nil}
		err := s.Providers(context.Background())
		Expect(err).To(BeNil())
		Expect(s.registry).NotTo(BeNil())
	})

	It("should load providers from database when DB is configured", func() {
		gormDB, mockSQL, _ := testutils.MockSQLPool()
		mockSQL.ExpectQuery(`SELECT \* FROM "providers"`).
			WillReturnRows(mockSQL.NewRows(providerColumns()))
		mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
		mockDB.DB = gormDB
		opts.Auth.ProviderCache.Size = 10
		s := &Server{Logger: logger, sessionStore: sessionStore, AuthCfg: opts.Auth, DB: mockDB}
		err := s.Providers(context.Background())
		Expect(err).To(BeNil())
		Expect(s.registry).NotTo(BeNil())
		Expect(s.registry.cache).NotTo(BeNil())
	})
})

var _ = Describe("GetProvider JSON Response Test", func() {
	var opts ezcfg.Options
	var sessionStore sessions.SessionStore

	BeforeEach(func() {
		opts = testutils.LoadFromConfig("oauth2/oidc.yaml")
		var err error
		sessionStore, err = sessions.NewSessionStore(&opts.Auth.Session)
		Expect(err).To(BeNil())
	})

	It("should return valid JSON response with correct content type", func() {
		issuerURL, _ := url.Parse("https://dev-z3tqqsmunxppeufg.us.auth0.com")
		providerConfigs := []*ezcfg.ProviderConfig{{
			ProviderName: "json-test-provider", Type: "oauth2",
			OIDCConfig:  ezcfg.OIDCConfig{Issuer: issuerURL},
			RedirectURL: &url.URL{Path: "https://127.0.0.1:8443/oauth2/callback"},
			ClientID:    "test-client-id",
		}}
		ps, err := providers.NewProvider(providerConfigs, sessionStore)
		Expect(err).To(BeNil())

		cache := ezcache.NewMemoryCache[string, providers.Provider](10, 0)
		for name, p := range ps {
			_ = cache.Set(context.Background(), name, p, 0)
		}
		logger, _ := testutils.SetupTestLogger()
		s := newServerWithCache(cache, logger, nil)

		router := mux.NewRouter()
		s.providerRouter(router)

		req, _ := http.NewRequest("GET", "/json-test-provider", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Header().Get("Content-Type")).To(Equal("application/json"))
		body := rr.Body.Bytes()
		Expect(string(body)).To(ContainSubstring("json-test-provider"))
		Expect(string(body)).To(ContainSubstring("oauth2"))
	})
})

// ---------------------------------------------------------------------------
// oauthSubrouter – builds without panic when rate limiting is disabled
// ---------------------------------------------------------------------------

var _ = Describe("oauthSubrouter builds without panic", func() {
	It("does not panic when rate limiting is disabled and globalCache is nil", func() {
		logger, _ := testutils.SetupTestLogger()
		rend, _, _ := eztmpl.New("", "")
		s := &Server{
			Logger:   logger,
			renderer: rend,
			ServeCfg: ezcfg.ServerConfig{
				AuthPrefix:            "/ezauth",
				StaticPrefix:          "/static",
				TrustForwardedHeaders: testutils.BoolPtr(true),
			},
			AuthCfg: ezcfg.AuthConfig{
				OAuthRateLimit: ezcfg.RateLimitConfig{Enabled: false},
				LoginRateLimit: ezcfg.RateLimitConfig{Enabled: false},
			},
		}
		Expect(func() {
			r := mux.NewRouter()
			sub := r.PathPrefix(s.ServeCfg.AuthPrefix).Subrouter()
			s.oauthSubrouter(sub)
		}).NotTo(Panic())
	})
})

// ---------------------------------------------------------------------------
// ListProviders extra branches – pagination error, DB error, limit default
// ---------------------------------------------------------------------------

var _ = Describe("ListProviders extra branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	newProviderServer := func(db database.DatabaseInterface) *Server {
		s := &Server{
			Logger: logger,
			DB:     db,
		}
		s.registry = newProviderRegistry(0, db, nil, logger, nil)
		return s
	}

	providerRouter := func(s *Server, r *mux.Router) {
		s.providerRouter(r)
	}

	It("returns 400 for invalid pagination params when DB is set", func() {
		tc := apiTestCase{
			name: "invalid pagination", method: http.MethodGet,
			path: "/?limit=bad",
			setupServer: func() *Server {
				return newProviderServer(&mockDBListProviders{})
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid pagination parameters",
		}
		runAPITest(tc, providerRouter, logger)
	})

	It("returns 500 when DB.ListProviders returns error", func() {
		tc := apiTestCase{
			name: "db error", method: http.MethodGet,
			path: "/",
			setupServer: func() *Server {
				return newProviderServer(&mockDBListProviders{
					err: errors.New("db connection lost"),
				})
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, providerRouter, logger)
	})

	It("returns 200 and defaults limit to 100 when limit param is 0", func() {
		tc := apiTestCase{
			name: "limit zero defaults to 100", method: http.MethodGet,
			path: "/?limit=0",
			setupServer: func() *Server {
				return newProviderServer(&mockDBListProviders{
					result: nil,
				})
			},
			expectedStatus: http.StatusOK,
		}
		runAPITest(tc, providerRouter, logger)
	})
})

// ---------------------------------------------------------------------------
// DeleteProvider DB error branch – non-ErrNoRecord error returns 500
// ---------------------------------------------------------------------------

var _ = Describe("DeleteProvider extra branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	It("returns 500 when DB.DeleteProvider returns non-ErrNoRecord error", func() {
		db := &mockDBDeleteProvider{err: database.ErrOperation}
		s := &Server{
			Logger: logger,
			DB:     db,
		}
		s.registry = newProviderRegistry(0, db, nil, logger, nil)

		req := httptest.NewRequest(http.MethodDelete, "/some-provider", nil)
		req = mux.SetURLVars(req, map[string]string{"name": "some-provider"})
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.DeleteProvider(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
		Expect(rw.Body.String()).To(ContainSubstring("Internal Server Error"))
	})
})

// ---------------------------------------------------------------------------
// OAuthStart extra branches – GetLoginURL error, loginURL with empty Host
// ---------------------------------------------------------------------------

var _ = Describe("OAuthStart extra branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	newOAuthServer := func(mp *mockProvider) *Server {
		rend, _, _ := eztmpl.New("", "")
		store, err := sessions.NewSessionStore(&ezcfg.Session{
			Cookie: ezcfg.CookieStoreOptions{
				Name:   "_ez_proxy",
				Secret: ezcfg.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		s := &Server{
			Logger:   logger,
			renderer: rend,
			ServeCfg: ezcfg.ServerConfig{AuthPrefix: "/ezauth", StaticPrefix: "/static", TrustForwardedHeaders: testutils.BoolPtr(true)},
			AuthCfg: ezcfg.AuthConfig{
				Proxy: ezcfg.AuthProxyConfig{JSONResponse: true},
			},
			sessionStore: store,
		}
		s.registry = newProviderRegistry(10, nil, nil, logger, nil)
		if mp != nil {
			cache := ezcache.NewMemoryCache[string, providers.Provider](10, time.Hour)
			_ = cache.Set(context.Background(), "testprovider", mp, 0)
			s.registry.cache = cache
		}
		return s
	}

	It("returns 500 when provider.GetLoginURL returns an error", func() {
		mp := &mockProvider{loginErr: errors.New("idp unreachable")}
		s := newOAuthServer(mp)
		req := httptest.NewRequest(http.MethodGet, "/ezauth/start?provider=testprovider", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.OAuthStart(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})

	It("renders login page with error when loginURL has empty host", func() {
		// loginURL with no host causes the redirect branch to be skipped;
		// the handler falls through to LoginPage with "No identity provider found".
		// LoginPage renders the embedded login.html template and responds 400.
		relativeURL := &url.URL{Path: "/relative/path"}
		mp := &mockProvider{loginURL: relativeURL}
		s := newOAuthServer(mp)
		req := httptest.NewRequest(http.MethodGet, "/ezauth/start?provider=testprovider", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.OAuthStart(rw, req)
		// Provider returns a relative URL (empty Host), so GetLoginURL yields an error;
		// OAuthStart falls through to LoginPage which renders 400.
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
	})
})

// ---------------------------------------------------------------------------
// AddProvider DB error branch
// ---------------------------------------------------------------------------

var _ = Describe("AddProvider DB error branch", func() {
	It("returns 500 when DB.AddProvider returns error", func() {
		logger, _ := testutils.SetupTestLogger()
		tc := apiTestCase{
			name: "db error", method: http.MethodPost,
			path: "/",
			body: `{"provider_name":"newprovider","type":"oidc","client_id":"id","client_secret":"s"}`,
			setupServer: func() *Server {
				s := &Server{
					Logger: logger,
					DB:     &mockDBPAT{addProviderErr: errors.New("db write failed")},
				}
				s.registry = newProviderRegistry(0, s.DB, nil, logger, nil)
				return s
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, func(s *Server, r *mux.Router) {
			s.providerRouter(r)
		}, logger)
	})
})

// ---------------------------------------------------------------------------
// UpdateProvider non-ErrNoRecord DB error branch
// ---------------------------------------------------------------------------

var _ = Describe("UpdateProvider DB error branch", func() {
	It("returns 500 when DB.UpdateProvider returns a non-ErrNoRecord error", func() {
		logger, _ := testutils.SetupTestLogger()
		tc := apiTestCase{
			name: "db error", method: http.MethodPut,
			path: "/someprovider",
			body: `{"redirect_url":"https://example.com/callback"}`,
			setupServer: func() *Server {
				s := &Server{
					Logger: logger,
					DB:     &mockDBPAT{updateProviderErr: errors.New("db write failed")},
				}
				s.registry = newProviderRegistry(0, s.DB, nil, logger, nil)
				return s
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, func(s *Server, r *mux.Router) {
			s.providerRouter(r)
		}, logger)
	})
})

// ---------------------------------------------------------------------------
// OAuthStart – LoginPage error branch
// ---------------------------------------------------------------------------

var _ = Describe("OAuthStart LoginPage error branch", func() {
	It("returns 500 when LoginPage fails due to nil renderer after provider fallthrough", func() {
		logger, _ := testutils.SetupTestLogger()
		s := &Server{Logger: logger}
		s.registry = newProviderRegistry(0, nil, nil, logger, nil)
		s.renderer = nil // nil renderer → LoginPage returns a *GeneralError

		req := httptest.NewRequest(http.MethodGet, "/start?provider=nonexistent", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.OAuthStart(rw, req)

		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})
})
