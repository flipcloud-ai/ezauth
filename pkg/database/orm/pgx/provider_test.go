package pgx

import (
	"fmt"
	"net/url"
	"reflect"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
	"gorm.io/datatypes"
	"moul.io/zapgorm2"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// pgErrorWrapper wraps pgconn.PgError to support error unwrapping
type pgErrorWrapper struct {
	err   error
	pgErr *pgconn.PgError
}

func (e *pgErrorWrapper) Error() string {
	return e.err.Error()
}

func (e *pgErrorWrapper) Unwrap() error {
	return e.pgErr
}

func newPgError(code string) error {
	return &pgErrorWrapper{
		err:   fmt.Errorf("postgres error: %s", code),
		pgErr: &pgconn.PgError{Code: code},
	}
}

var _ = Describe("PGX provider interface Test Suite", func() {
	Context("model to config conversion", func() {
		DescribeTableSubtree("conversion test",
			func(desc string, model *models.ProviderDB, expect *ezcfg.ProviderConfig, check func(*ezcfg.ProviderConfig)) {
				It(desc, func() {
					result, err := convertToProviderConfig(model)
					Expect(err).ToNot(HaveOccurred())
					Expect(result).ToNot(BeNil())

					// Compare all fields using reflection
					expectEqual(result, expect)

					// Custom assertions
					if check != nil {
						check(result)
					}
				})
			},
			// Full OIDC provider
			Entry("basic OIDC provider with all fields set",
				"should convert all fields correctly",
				MB().Set("ProviderName", "google").Set("Type", "oidc").Set("ClientID", "client-id-123").Set("ClientSecret", "secret-456").
					Set("RedirectURL", dataURL("https://example.com/callback")).Set("DeviceAuthURL", dataURL("https://deviceauth.example.com")).
					Set("ValidateURL", dataURL("https://validate.example.com")).Set("AllowedGroups", pq.StringArray{"admin", "users"}).
					Set("ClaimsFromProfile", true).Set("Scope", "openid profile email").Set("UserClaim", "sub").Set("SkipNonce", true).
					Set("Issuer", dataURL("https://accounts.google.com")).Set("AuthURL", dataURL("https://accounts.google.com/o/oauth2/v2/auth")).
					Set("TokenURL", dataURL("https://oauth2.googleapis.com/token")).Set("JWKsURL", dataURL("https://www.googleapis.com/oauth2/v3/certs")).
					Set("UserInfoURL", dataURL("https://oauth2.googleapis.com/userinfo")).Set("CodeChallengeMethod", pq.StringArray{"S256"}).
					Set("SupportedSigningAlgs", pq.StringArray{"RS256"}).Set("ProtectedResource", dataURL("https://graph.microsoft.com")).
					Set("LoginParameters", map[string][]string{"key1": {"value1"}, "key2": {"value2"}}).
					Build(),
				CB().Set("ProviderName", "google").Set("Type", "oidc").Set("ClientID", "client-id-123").Set("ClientSecret", "secret-456").
					Set("RedirectURL", stdURL("https://example.com/callback")).Set("DeviceAuthURL", stdURL("https://deviceauth.example.com")).
					Set("ValidateURL", stdURL("https://validate.example.com")).Set("AllowedGroups", []string{"admin", "users"}).
					Set("ClaimsFromProfile", true).Set("Scope", "openid profile email").Set("UserClaim", "sub").Set("SkipNonce", true).
					Set("Issuer", stdURL("https://accounts.google.com")).Set("AuthURL", stdURL("https://accounts.google.com/o/oauth2/v2/auth")).
					Set("TokenURL", stdURL("https://oauth2.googleapis.com/token")).Set("JWKsURL", stdURL("https://www.googleapis.com/oauth2/v3/certs")).
					Set("UserInfoURL", stdURL("https://oauth2.googleapis.com/userinfo")).Set("CodeChallengeMethod", []string{"S256"}).
					Set("SupportedSigningAlgs", []string{"RS256"}).Set("ProtectedResource", stdURL("https://graph.microsoft.com")).
					Set("LoginParameters", map[string][]string{"key1": {"value1"}, "key2": {"value2"}}).
					Build(),
				nil,
			),

			// Minimal provider
			Entry("minimal OIDC provider with only required fields",
				"should convert required fields",
				MB().Set("ProviderName", "minimal").Set("Type", "oidc").Set("ClientID", "client-id").Set("ClientSecret", "client-secret").Set("Scope", "openid").Build(),
				CB().Set("ProviderName", "minimal").Set("Type", "oidc").Set("ClientID", "client-id").Set("ClientSecret", "client-secret").Set("Scope", "openid").Build(),
				nil,
			),

			// OAuth2 provider
			Entry("OAuth2 provider with login parameters",
				"should convert OAuth2 fields",
				MB().Set("ProviderName", "oauth2").Set("Type", "oauth2").Set("ClientID", "oauth-client").Set("ClientSecret", "oauth-secret").
					Set("RedirectURL", dataURL("https://app.example.com/auth/callback")).
					Set("LoginParameters", map[string][]string{"response_type": {"code"}, "state": {"xyz"}}).
					Set("AllowedGroups", pq.StringArray{"developers"}).Set("ClaimsFromProfile", false).Set("Scope", "user:email").Build(),
				CB().Set("ProviderName", "oauth2").Set("Type", "oauth2").Set("ClientID", "oauth-client").Set("ClientSecret", "oauth-secret").
					Set("RedirectURL", stdURL("https://app.example.com/auth/callback")).
					Set("LoginParameters", map[string][]string{"response_type": {"code"}, "state": {"xyz"}}).
					Set("AllowedGroups", []string{"developers"}).Set("ClaimsFromProfile", false).Set("Scope", "user:email").Build(),
				nil,
			),

			// Empty arrays
			Entry("provider with empty string arrays",
				"should handle empty arrays",
				MB().Set("ProviderName", "empty-arrays").Set("CodeChallengeMethod", pq.StringArray{}).Set("SupportedSigningAlgs", pq.StringArray{}).Build(),
				CB().Set("ProviderName", "empty-arrays").Set("CodeChallengeMethod", []string{}).Set("SupportedSigningAlgs", []string{}).Build(),
				nil,
			),

			// Single element arrays
			Entry("provider with single element arrays",
				"should handle single element arrays",
				MB().Set("ProviderName", "single-element").Set("AllowedGroups", pq.StringArray{"only-admin"}).
					Set("CodeChallengeMethod", pq.StringArray{"plain"}).Set("SupportedSigningAlgs", pq.StringArray{"RS384"}).Build(),
				CB().Set("ProviderName", "single-element").Set("AllowedGroups", []string{"only-admin"}).
					Set("CodeChallengeMethod", []string{"plain"}).Set("SupportedSigningAlgs", []string{"RS384"}).Build(),
				nil,
			),

			// Nil URLs
			Entry("provider with all URL fields nil",
				"should handle nil URLs",
				MB().Set("ProviderName", "nil-urls").Set("Type", "oidc").Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				CB().Set("ProviderName", "nil-urls").Set("Type", "oidc").Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				nil,
			),

			// Zero cookie
			Entry("provider with zero value cookie durations",
				"should handle zero duration cookies",
				MB().Set("ProviderName", "zero-cookie").Build(),
				CB().Set("ProviderName", "zero-cookie").Build(),
				nil,
			),

			// Special chars
			Entry("provider with special characters in login parameters",
				"should handle special chars",
				MB().Set("ProviderName", "special-chars").Set("Type", "oauth2").
					Set("LoginParameters", map[string][]string{"scope": {"read:user write:repo"}, "audience": {"api://myapp"}}).Build(),
				CB().Set("ProviderName", "special-chars").Set("Type", "oauth2").
					Set("LoginParameters", map[string][]string{"scope": {"read:user write:repo"}, "audience": {"api://myapp"}}).Build(),
				nil,
			),

			// Complex cookie
			Entry("provider with complex cookie configuration",
				"should handle complex cookie",
				MB().Set("ProviderName", "complex-cookie").Build(),
				CB().Set("ProviderName", "complex-cookie").Build(),
				nil,
			),

			// Full OIDC
			Entry("provider with all OIDC fields populated",
				"should convert all OIDC fields",
				MB().Set("ProviderName", "full-oidc").Set("ClientID", "full-client-id").Set("ClientSecret", "full-client-secret").
					Set("Issuer", dataURL("https://issuer.example.com")).Set("AuthURL", dataURL("https://issuer.example.com/authorize")).
					Set("TokenURL", dataURL("https://issuer.example.com/token")).Set("JWKsURL", dataURL("https://issuer.example.com/.well-known/jwks.json")).
					Set("UserInfoURL", dataURL("https://issuer.example.com/userinfo")).
					Set("CodeChallengeMethod", pq.StringArray{"S256", "plain"}).Set("SupportedSigningAlgs", pq.StringArray{"RS256", "RS384", "RS512", "ES256"}).
					Set("ProtectedResource", dataURL("https://api.example.com")).Build(),
				CB().Set("ProviderName", "full-oidc").Set("ClientID", "full-client-id").Set("ClientSecret", "full-client-secret").
					Set("Issuer", stdURL("https://issuer.example.com")).Set("AuthURL", stdURL("https://issuer.example.com/authorize")).
					Set("TokenURL", stdURL("https://issuer.example.com/token")).Set("JWKsURL", stdURL("https://issuer.example.com/.well-known/jwks.json")).
					Set("UserInfoURL", stdURL("https://issuer.example.com/userinfo")).
					Set("CodeChallengeMethod", []string{"S256", "plain"}).Set("SupportedSigningAlgs", []string{"RS256", "RS384", "RS512", "ES256"}).
					Set("ProtectedResource", stdURL("https://api.example.com")).Build(),
				nil,
			),

			// Empty login params
			Entry("provider with empty login parameters",
				"should handle nil login params",
				MB().Set("ProviderName", "empty-login-params").Set("Type", "oauth2").Build(),
				CB().Set("ProviderName", "empty-login-params").Set("Type", "oauth2").Build(),
				nil,
			),

			// Skip nonce false
			Entry("provider with skip nonce false",
				"should handle skip nonce false",
				MB().Set("ProviderName", "skip-nonce-false").Set("Type", "oidc").Set("SkipNonce", false).Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				CB().Set("ProviderName", "skip-nonce-false").Set("Type", "oidc").Set("SkipNonce", false).Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				nil,
			),

			// Claims false
			Entry("provider with claims from profile false",
				"should handle claims false",
				MB().Set("ProviderName", "claims-false").Set("Type", "oidc").Set("ClaimsFromProfile", false).Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				CB().Set("ProviderName", "claims-false").Set("Type", "oidc").Set("ClaimsFromProfile", false).Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				nil,
			),

			// Edge cases
			Entry("empty ProviderName", "should handle empty name",
				MB().Set("ProviderName", "").Set("Type", "oidc").Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				nil, func(c *ezcfg.ProviderConfig) { Expect(c.ProviderName).To(Equal("")) },
			),
			Entry("user claim set", "should handle user claim",
				MB().Set("ProviderName", "test").Set("Type", "oidc").Set("UserClaim", "email").Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				nil, func(c *ezcfg.ProviderConfig) { Expect(c.UserClaim).To(Equal("email")) },
			),
			Entry("array to array conversion", "should convert string array to string slice",
				MB().Set("ProviderName", "str-array-test").Set("Type", "oidc").Set("ClientID", "id").Set("ClientSecret", "secret").
					Set("AllowedGroups", pq.StringArray{"group1", "group2", "group3"}).Build(),
				nil, func(c *ezcfg.ProviderConfig) {
					Expect(c.AllowedGroups).To(HaveLen(3))
					Expect(c.AllowedGroups).To(ContainElements([]string{"group1", "group2", "group3"}))
				},
			),
			Entry("user claim empty", "should handle empty user claim",
				MB().Set("ProviderName", "test").Set("Type", "oidc").Set("UserClaim", "").Set("ClientID", "id").Set("ClientSecret", "secret").Build(),
				nil, func(c *ezcfg.ProviderConfig) { Expect(c.UserClaim).To(Equal("")) },
			),
			Entry("large number of allowed groups", "should handle 100 groups",
				MB().Set("AllowedGroups", genGroups(100, "group-")).Build(),
				nil, func(c *ezcfg.ProviderConfig) { Expect(len(c.AllowedGroups)).To(Equal(100)) },
			),
			Entry("nil redirect URL", "should handle nil redirect URL",
				MB().Build(),
				nil, func(c *ezcfg.ProviderConfig) { Expect(c.RedirectURL).To(BeNil()) },
			),
			Entry("URL with query parameters", "should preserve query params",
				MB().Set("RedirectURL", dataURL("https://example.com/callback?state=abc&code=123")).Build(),
				nil, func(c *ezcfg.ProviderConfig) {
					Expect(c.RedirectURL.Query().Get("state")).To(Equal("abc"))
					Expect(c.RedirectURL.Query().Get("code")).To(Equal("123"))
				},
			),
			Entry("URL with fragment", "should handle fragment",
				MB().Set("RedirectURL", dataURL("https://example.com/callback#fragment")).Build(),
				nil, func(c *ezcfg.ProviderConfig) { Expect(c.RedirectURL).ToNot(BeNil()) },
			),
		)
	})

	Context("model to config conversion errors", func() {
		It("nil model should not panic", func() {
			Expect(func() { _, _ = convertToProviderConfig(nil) }).NotTo(Panic())
			_, err := convertToProviderConfig(nil)
			Expect(err).To(HaveOccurred())
		})

		It("empty redirect URL should be nil", func() {
			model := &models.ProviderDB{ProviderName: "empty-url", RedirectURL: &datatypes.URL{}}
			result, err := convertToProviderConfig(model)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.RedirectURL).To(BeNil())
		})

		It("empty OIDC issuer URL should be nil", func() {
			model := &models.ProviderDB{ProviderName: "empty-oidc", OIDCDB: models.OIDCDB{Issuer: &datatypes.URL{}}}
			result, err := convertToProviderConfig(model)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.OIDCConfig.Issuer).To(BeNil())
		})

		It("empty OIDC auth URL should be nil", func() {
			model := &models.ProviderDB{ProviderName: "empty-auth", OIDCDB: models.OIDCDB{AuthURL: &datatypes.URL{}}}
			result, err := convertToProviderConfig(model)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.OIDCConfig.AuthURL).To(BeNil())
		})

		It("empty revocation URL should be nil", func() {
			model := &models.ProviderDB{ProviderName: "empty-revocation", OIDCDB: models.OIDCDB{RevocationURL: &datatypes.URL{}}}
			result, err := convertToProviderConfig(model)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.OIDCConfig.RevocationURL).To(BeNil())
		})

		It("empty device auth URL should be nil", func() {
			model := &models.ProviderDB{ProviderName: "empty-device", DeviceAuthURL: &datatypes.URL{}}
			result, err := convertToProviderConfig(model)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.DeviceAuthURL).To(BeNil())
		})

		It("empty validate URL should be nil", func() {
			model := &models.ProviderDB{ProviderName: "empty-validate", ValidateURL: &datatypes.URL{}}
			result, err := convertToProviderConfig(model)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.ValidateURL).To(BeNil())
		})
	})
})

// Compare all fields using grouped helpers - reduces repetitive assertions
func expectEqual(got, expected *ezcfg.ProviderConfig) {
	if expected == nil {
		return
	}

	// Basic fields - single assertions for simple types
	Expect(got.ProviderName).To(Equal(expected.ProviderName))
	Expect(got.Type).To(Equal(expected.Type))
	Expect(got.Scope).To(Equal(expected.Scope))
	Expect(got.ClientID).To(Equal(expected.ClientID))
	Expect(got.ClientSecret).To(Equal(expected.ClientSecret))
	Expect(got.UserClaim).To(Equal(expected.UserClaim))
	Expect(got.SkipNonce).To(Equal(expected.SkipNonce))
	Expect(got.ClaimsFromProfile).To(Equal(expected.ClaimsFromProfile))
	Expect(got.AllowedGroups).To(Equal(expected.AllowedGroups))
	Expect(got.LoginParameters).To(Equal(expected.LoginParameters))

	// URL fields - grouped
	expectURLs(got, expected)

	// OIDC config - grouped
	expectOIDC(got.OIDCConfig, expected.OIDCConfig)
}

func expectURLs(got, expected *ezcfg.ProviderConfig) {
	ExpectURLPair(got.RedirectURL, expected.RedirectURL)
	ExpectURLPair(got.DeviceAuthURL, expected.DeviceAuthURL)
	ExpectURLPair(got.ValidateURL, expected.ValidateURL)
}

func expectOIDC(got, expected ezcfg.OIDCConfig) {
	// URL fields in OIDC
	ExpectURLPair(got.Issuer, expected.Issuer)
	ExpectURLPair(got.AuthURL, expected.AuthURL)
	ExpectURLPair(got.TokenURL, expected.TokenURL)
	ExpectURLPair(got.JWKsURL, expected.JWKsURL)
	ExpectURLPair(got.UserInfoURL, expected.UserInfoURL)
	ExpectURLPair(got.ProtectedResource, expected.ProtectedResource)

	// Array fields
	Expect(got.CodeChallengeMethod).To(Equal(expected.CodeChallengeMethod))
	Expect(got.SupportedSigningAlgs).To(Equal(expected.SupportedSigningAlgs))
}

// URL comparison helper
func ExpectURLPair(got, expected *url.URL) {
	if expected == nil {
		Expect(got).To(BeNil())
	} else {
		Expect(got).ToNot(BeNil())
		Expect(got.String()).To(Equal(expected.String()))
	}
}

// Helper to generate groups
func genGroups(count int, prefix string) pq.StringArray {
	groups := make(pq.StringArray, count)
	for i := 0; i < count; i++ {
		groups[i] = prefix
	}
	return groups
}

// === Generic Model Builder ===
type modelBuilder struct {
	v *models.ProviderDB
}

func MB() *modelBuilder {
	return &modelBuilder{v: &models.ProviderDB{Type: "oidc", ClientID: "default-id", ClientSecret: "default-secret"}}
}

func (b *modelBuilder) Set(field string, value any) *modelBuilder {
	setField(reflect.ValueOf(b.v), field, value)
	return b
}

func (b *modelBuilder) Build() *models.ProviderDB {
	return b.v
}

// === Generic Config Builder ===
type configBuilder struct {
	v *ezcfg.ProviderConfig
}

func CB() *configBuilder {
	return &configBuilder{v: &ezcfg.ProviderConfig{Type: "oidc", ClientID: "default-id", ClientSecret: "default-secret"}}
}

func (b *configBuilder) Set(field string, value any) *configBuilder {
	setField(reflect.ValueOf(b.v), field, value)
	return b
}

func (b *configBuilder) Build() *ezcfg.ProviderConfig {
	return b.v
}

// Generic field setter using reflection
func setField(v reflect.Value, field string, value any) {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if !v.IsValid() {
		return
	}
	f := v.FieldByName(field)
	if !f.IsValid() || !f.CanSet() {
		return
	}
	f.Set(reflect.ValueOf(value))
}

// URL helpers
func dataURL(raw string) *datatypes.URL {
	u, _ := url.Parse(raw)
	dataURL := datatypes.URL(*u)
	return &dataURL
}
func stdURL(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}

// === CRUD Tests using MockSQLPool ===

var _ = Describe("Provider CRUD operations", func() {
	var db *PGxDB
	var mock testutils.MockDBStruct

	BeforeEach(func() {
		gormDB, mockSQL, err := testutils.MockSQLPool()
		Expect(err).ToNot(HaveOccurred())
		Expect(gormDB).ToNot(BeNil())

		logger, err := testutils.SetupTestLogger()
		Expect(err).ToNot(HaveOccurred())
		gormDB.Logger = zapgorm2.New(logger.Zap())
		db = &PGxDB{
			Database: ezdb.Database{
				Logger: logger,
			},
		}
		db.DB = gormDB

		mock = testutils.MockDBStruct{
			DB:   gormDB,
			Mock: mockSQL,
		}
	})

	Describe("GetProvider", func() {
		It("returns provider when found", func() {
			// Set up mock to return a provider row
			rows := mock.Mock.NewRows([]string{
				"provider_name", "type", "client_id", "client_secret",
				"redirect_url", "scope", "user_claim", "skip_nonce",
				"claims_from_profile", "allowed_groups",
			}).AddRow("google", "oidc", "client-id-123", "secret-456",
				"https://example.com/callback", "openid profile", "sub", false,
				true, pq.StringArray{"admin", "users"})
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs("google", 1).
				WillReturnRows(rows)

			result, err := db.GetProvider(context.Background(), "google")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.ProviderName).To(Equal("google"))
			Expect(result.Type).To(Equal("oidc"))
			Expect(result.ClientID).To(Equal("client-id-123"))
			Expect(result.ClientSecret).To(Equal("secret-456"))
			Expect(result.RedirectURL.String()).To(Equal("https://example.com/callback"))
			Expect(result.Scope).To(Equal("openid profile"))
			Expect(result.UserClaim).To(Equal("sub"))
			Expect(result.SkipNonce).To(BeFalse())
			Expect(result.ClaimsFromProfile).To(BeTrue())
			Expect(result.AllowedGroups).To(Equal([]string{"admin", "users"}))
		})

		It("returns nil when provider not found", func() {
			// Set up mock to return empty result
			rows := mock.Mock.NewRows([]string{
				"provider_name", "type", "client_id", "client_secret",
			})
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs("nonexistent", 1).
				WillReturnRows(rows)

			_, err := db.GetProvider(context.Background(), "nonexistent")
			Expect(err).To(HaveOccurred())
		})

		It("returns error on database error", func() {
			// Set up mock to return error
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs("google", 1).
				WillReturnError(fmt.Errorf("database connection failed"))

			_, err := db.GetProvider(context.Background(), "google")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("ScanProviders", func() {
		It("returns list of providers", func() {
			scanRows := mock.Mock.NewRows([]string{
				"provider_name", "type", "client_id", "client_secret",
				"redirect_url", "scope", "user_claim", "skip_nonce",
				"claims_from_profile", "allowed_groups", "enabled",
			}).
				AddRow("google", "oidc", "client-id-1", "secret-1",
					"https://google.com/callback", "openid", "sub", false, true, pq.StringArray{"admin"}, true).
				AddRow("okta", "oidc", "client-id-2", "secret-2",
					"https://okta.com/callback", "openid profile", "email", false, true, pq.StringArray{"users"}, true)
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(true, 30).
				WillReturnRows(scanRows)

			result, err := db.ScanProviders(context.Background(), 30)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(HaveLen(2))

			// First provider
			Expect(result[0].ProviderName).To(Equal("google"))
			Expect(result[0].Type).To(Equal("oidc"))
			Expect(result[0].ClientID).To(Equal("client-id-1"))
			Expect(result[0].ClientSecret).To(Equal("secret-1"))
			Expect(result[0].RedirectURL.String()).To(Equal("https://google.com/callback"))
			Expect(result[0].Scope).To(Equal("openid"))
			Expect(result[0].UserClaim).To(Equal("sub"))
			Expect(result[0].SkipNonce).To(BeFalse())
			Expect(result[0].ClaimsFromProfile).To(BeTrue())
			Expect(result[0].AllowedGroups).To(Equal([]string{"admin"}))

			// Second provider
			Expect(result[1].ProviderName).To(Equal("okta"))
			Expect(result[1].Type).To(Equal("oidc"))
			Expect(result[1].ClientID).To(Equal("client-id-2"))
			Expect(result[1].ClientSecret).To(Equal("secret-2"))
			Expect(result[1].RedirectURL.String()).To(Equal("https://okta.com/callback"))
			Expect(result[1].Scope).To(Equal("openid profile"))
			Expect(result[1].UserClaim).To(Equal("email"))
			Expect(result[1].SkipNonce).To(BeFalse())
			Expect(result[1].ClaimsFromProfile).To(BeTrue())
			Expect(result[1].AllowedGroups).To(Equal([]string{"users"}))
		})

		It("returns empty list when no providers", func() {
			scanRows := mock.Mock.NewRows([]string{"provider_name", "type", "client_id", "client_secret"})
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(true, 30).
				WillReturnRows(scanRows)

			result, err := db.ScanProviders(context.Background(), 30)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(BeEmpty())
		})

		It("returns error on database failure", func() {
			dbErr := fmt.Errorf("database connection failed")
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(true, 30).
				WillReturnError(dbErr)

			result, err := db.ScanProviders(context.Background(), 30)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(dbErr))
			Expect(result).To(BeNil())
		})

		It("returns error when table does not exist", func() {
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(true, 30).
				WillReturnError(newPgError("42P01"))

			result, err := db.ScanProviders(context.Background(), 30)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ezdb.ErrNeedInit))
			Expect(result).To(BeNil())
		})

		It("defaults size to 30 when size is 0", func() {
			scanRows := mock.Mock.NewRows([]string{"provider_name", "type", "client_id", "client_secret"})
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(true, 30).
				WillReturnRows(scanRows)

			result, err := db.ScanProviders(context.Background(), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(BeEmpty())
			Expect(mock.Mock.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("AddProvider", func() {
		It("adds provider successfully", func() {
			// Set up mock for create
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectQuery(`INSERT INTO "providers"`).
				WillReturnRows(sqlmock.NewRows([]string{"provider_name"}).AddRow("new-provider"))
			mock.Mock.ExpectCommit()

			provider := &models.ProviderDB{
				ProviderName: "new-provider",
				Type:         "oidc",
				ClientID:     "new-client-id",
				ClientSecret: "new-secret",
			}

			err := db.AddProvider(context.Background(), provider)
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns error on duplicate provider", func() {
			// Set up mock for create failure with duplicate key error (code 23505)
			// Create error that wraps pgconn.PgError for proper error type detection
			pgErr := &pgconn.PgError{Code: "23505"}
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectQuery("INSERT INTO \"providers\"").
				WillReturnError(fmt.Errorf("%w: duplicate key value violates unique constraint", pgErr))
			mock.Mock.ExpectRollback()

			provider := &models.ProviderDB{
				ProviderName: "existing-provider",
				Type:         "oidc",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			}

			err := db.AddProvider(context.Background(), provider)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ezdb.ErrConflict))
		})

		It("returns error on database operation failure", func() {
			// Set up mock for generic database error
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectQuery("INSERT INTO \"providers\"").
				WillReturnError(fmt.Errorf("database connection failed"))
			mock.Mock.ExpectRollback()

			provider := &models.ProviderDB{
				ProviderName: "test-provider",
				Type:         "oidc",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			}

			err := db.AddProvider(context.Background(), provider)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ezdb.ErrOperation))
		})

		It("returns error on not-null constraint violation", func() {
			// Set up mock for not-null constraint violation (code 23502)
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectQuery("INSERT INTO \"providers\"").
				WillReturnError(newPgError("23502"))
			mock.Mock.ExpectRollback()

			provider := &models.ProviderDB{
				ProviderName: "",
				Type:         "oidc",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			}

			err := db.AddProvider(context.Background(), provider)
			Expect(err).To(HaveOccurred())
			Expect(err).ToNot(Equal(ezdb.ErrOperation))
			Expect(err).ToNot(Equal(ezdb.ErrConflict))
		})
	})

	Describe("UpdateProvider", func() {
		It("updates provider successfully", func() {
			// Set up mock for update
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectExec("UPDATE \"providers\"").
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.Mock.ExpectCommit()

			provider := &models.ProviderDB{
				ProviderName: "google",
				Type:         "oidc",
				ClientID:     "updated-client-id",
			}

			err := db.UpdateProvider(context.Background(), provider)
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns error when provider not found", func() {
			// Set up mock for update that affects 0 rows
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectExec("UPDATE \"providers\"").
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.Mock.ExpectCommit()

			provider := &models.ProviderDB{
				ProviderName: "nonexistent",
			}

			err := db.UpdateProvider(context.Background(), provider)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns error on database operation failure", func() {
			// Set up mock for database error
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectExec("UPDATE \"providers\"").
				WillReturnError(fmt.Errorf("database connection failed"))
			mock.Mock.ExpectRollback()

			provider := &models.ProviderDB{
				ProviderName: "test-provider",
			}

			err := db.UpdateProvider(context.Background(), provider)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("DeleteProvider", func() {
		It("deletes provider successfully", func() {
			// Set up mock for delete
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectExec("DELETE FROM \"providers\"").
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.Mock.ExpectCommit()

			err := db.DeleteProvider(context.Background(), "google")
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns error when provider not found", func() {
			// Set up mock for delete that affects 0 rows
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectExec("DELETE FROM \"providers\"").
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.Mock.ExpectCommit()

			// DeleteProvider returns error when no rows are affected
			err := db.DeleteProvider(context.Background(), "nonexistent")
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns error on database operation failure", func() {
			// Set up mock for database error
			mock.Mock.ExpectBegin()
			mock.Mock.ExpectExec("DELETE FROM \"providers\"").
				WillReturnError(fmt.Errorf("database connection failed"))
			mock.Mock.ExpectRollback()

			err := db.DeleteProvider(context.Background(), "test-provider")
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("ListProviders", func() {
		It("lists providers with pagination", func() {
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{"provider_name", "type", "client_id", "client_secret"}).
					AddRow("google", "oidc", "c1", "s1").
					AddRow("okta", "oidc", "c2", "s2"))

			result, err := db.ListProviders(context.Background(), 10, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(HaveLen(2))
		})

		It("returns empty list when no providers exist", func() {
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"provider_name", "type"}))

			result, err := db.ListProviders(context.Background(), 0, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(BeEmpty())
		})

		It("returns error on database failure", func() {
			mock.Mock.ExpectQuery(`SELECT \* FROM "providers"`).
				WithArgs(10).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.ListProviders(context.Background(), 10, 0)
			Expect(err).To(HaveOccurred())
		})
	})
})
