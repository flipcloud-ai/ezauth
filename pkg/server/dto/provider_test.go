package dto

import (
	"encoding/json"
	"net/url"
	"time"

	"gorm.io/datatypes"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

var _ = Describe("Provider DTO", func() {
	Describe("UpdateProviderRequest", func() {
		It("should marshal and unmarshal correctly", func() {
			redirectURL := "https://example.com/callback"
			deviceAuthURL := "https://example.com/device"
			validateURL := "https://example.com/validate"
			claimsFromProfile := true
			issuer := "https://accounts.google.com"
			authURL := "https://accounts.google.com/o/oauth2/v2/auth"
			tokenURL := "https://oauth2.googleapis.com/token"
			jwksURL := "https://www.googleapis.com/oauth2/v3/certs"
			userInfoURL := "https://openidconnect.googleapis.com/userinfo"
			protectedResource := "https://example.com/api"
			scope := "openid email profile"
			clientID := "client-id"
			clientSecret := "client-secret"
			userClaim := "email"
			skipNonce := false
			req := UpdateProviderRequest{
				ProviderName:      "google",
				RedirectURL:       &redirectURL,
				DeviceAuthURL:     &deviceAuthURL,
				ValidateURL:       &validateURL,
				AllowedGroups:     &[]string{"admins", "users"},
				ClaimsFromProfile: &claimsFromProfile,
				OIDCConfigRequest: OIDCConfigRequest{
					Issuer:               &issuer,
					AuthURL:              &authURL,
					TokenURL:             &tokenURL,
					JWKsURL:              &jwksURL,
					UserInfoURL:          &userInfoURL,
					CodeChallengeMethod:  &[]string{"S256"},
					SupportedSigningAlgs: &[]string{"RS256"},
					ProtectedResource:    &protectedResource,
				},
				Scope:        &scope,
				ClientID:     &clientID,
				ClientSecret: &clientSecret,
				UserClaim:    &userClaim,
				SkipNonce:    &skipNonce,
				LoginParameters: map[string][]string{
					"prompt": {"consent"},
				},
			}

			data, err := json.Marshal(req)
			Expect(err).ToNot(HaveOccurred())

			var result UpdateProviderRequest
			err = json.Unmarshal(data, &result)
			Expect(err).ToNot(HaveOccurred())
			// ProviderName is json:"-" — set from path param, never serialised/deserialised.
			Expect(result.ProviderName).To(BeEmpty())
			Expect(*result.RedirectURL).To(Equal("https://example.com/callback"))
			Expect(*result.AllowedGroups).To(ContainElements("admins", "users"))
			Expect(*result.ClaimsFromProfile).To(BeTrue())
			Expect(*result.OIDCConfigRequest.Issuer).To(Equal("https://accounts.google.com"))
			Expect(*result.ClientID).To(Equal("client-id"))
			Expect(result.LoginParameters["prompt"]).To(ContainElements("consent"))
		})

		It("should handle empty request", func() {
			req := UpdateProviderRequest{}

			data, err := json.Marshal(req)
			Expect(err).ToNot(HaveOccurred())

			var result UpdateProviderRequest
			err = json.Unmarshal(data, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.ProviderName).To(BeEmpty())
			Expect(result.AllowedGroups).To(BeNil())
			Expect(result.OIDCConfigRequest.Issuer).To(BeNil())
		})
	})

	Describe("OIDCConfigRequest", func() {
		It("should marshal and unmarshal correctly", func() {
			issuer := "https://issuer.example.com"
			authURL := "https://issuer.example.com/auth"
			tokenURL := "https://issuer.example.com/token"
			jwksURL := "https://issuer.example.com/jwks"
			userInfoURL := "https://issuer.example.com/userinfo"
			protectedResource := "https://api.example.com"
			req := OIDCConfigRequest{
				Issuer:               &issuer,
				AuthURL:              &authURL,
				TokenURL:             &tokenURL,
				JWKsURL:              &jwksURL,
				UserInfoURL:          &userInfoURL,
				CodeChallengeMethod:  &[]string{"S256", "plain"},
				SupportedSigningAlgs: &[]string{"RS256", "HS256"},
				ProtectedResource:    &protectedResource,
			}

			data, err := json.Marshal(req)
			Expect(err).ToNot(HaveOccurred())

			var result OIDCConfigRequest
			err = json.Unmarshal(data, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(*result.Issuer).To(Equal("https://issuer.example.com"))
			Expect(*result.AuthURL).To(Equal("https://issuer.example.com/auth"))
			Expect(*result.TokenURL).To(Equal("https://issuer.example.com/token"))
			Expect(*result.JWKsURL).To(Equal("https://issuer.example.com/jwks"))
			Expect(*result.UserInfoURL).To(Equal("https://issuer.example.com/userinfo"))
			Expect(*result.CodeChallengeMethod).To(ContainElements("S256", "plain"))
			Expect(*result.SupportedSigningAlgs).To(ContainElements("RS256", "HS256"))
			Expect(*result.ProtectedResource).To(Equal("https://api.example.com"))
		})
	})

	Describe("UpdateProviderRequest.ConvertToDB", func() {
		It("should convert to ProviderDB", func() {
			redirectURL := "https://app.example.com/callback"
			deviceAuthURL := "https://auth0.example.com/device"
			validateURL := "https://auth0.example.com/validate"
			claimsFromProfile := true
			issuer := "https://auth0.example.com"
			authURL := "https://auth0.example.com/authorize"
			tokenURL := "https://auth0.example.com/token"
			jwksURL := "https://auth0.example.com/.well-known/jwks.json"
			userInfoURL := "https://auth0.example.com/userinfo"
			protectedResource := "https://api.auth0.com"
			scope := "openid email"
			clientID := "auth0-client"
			clientSecret := "auth0-secret"
			userClaim := "email"
			skipNonce := true
			req := UpdateProviderRequest{
				ProviderName:      "auth0",
				RedirectURL:       &redirectURL,
				DeviceAuthURL:     &deviceAuthURL,
				ValidateURL:       &validateURL,
				AllowedGroups:     &[]string{"admins", "guests"},
				ClaimsFromProfile: &claimsFromProfile,
				OIDCConfigRequest: OIDCConfigRequest{
					Issuer:               &issuer,
					AuthURL:              &authURL,
					TokenURL:             &tokenURL,
					JWKsURL:              &jwksURL,
					UserInfoURL:          &userInfoURL,
					CodeChallengeMethod:  &[]string{"S256"},
					SupportedSigningAlgs: &[]string{"RS256"},
					ProtectedResource:    &protectedResource,
				},
				Scope:        &scope,
				ClientID:     &clientID,
				ClientSecret: &clientSecret,
				UserClaim:    &userClaim,
				SkipNonce:    &skipNonce,
				LoginParameters: map[string][]string{
					"audience": {"api.auth0.com"},
				},
			}

			db, err := req.ConvertToDB()
			Expect(err).ToNot(HaveOccurred())

			Expect(db.ProviderName).To(Equal("auth0"))
			Expect(db.RedirectURL.String()).To(Equal("https://app.example.com/callback"))
			Expect(db.DeviceAuthURL.String()).To(Equal("https://auth0.example.com/device"))
			Expect(db.ValidateURL.String()).To(Equal("https://auth0.example.com/validate"))
			Expect(db.AllowedGroups).To(ContainElements("admins", "guests"))
			Expect(db.ClaimsFromProfile).To(BeTrue())
			Expect(db.OIDCDB.Issuer.String()).To(Equal("https://auth0.example.com"))
			Expect(db.OIDCDB.AuthURL.String()).To(Equal("https://auth0.example.com/authorize"))
			Expect(db.OIDCDB.TokenURL.String()).To(Equal("https://auth0.example.com/token"))
			Expect(db.OIDCDB.JWKsURL.String()).To(Equal("https://auth0.example.com/.well-known/jwks.json"))
			Expect(db.OIDCDB.UserInfoURL.String()).To(Equal("https://auth0.example.com/userinfo"))
			Expect(db.OIDCDB.CodeChallengeMethod).To(ContainElements("S256"))
			Expect(db.OIDCDB.SupportedSigningAlgs).To(ContainElements("RS256"))
			Expect(db.OIDCDB.ProtectedResource.String()).To(Equal("https://api.auth0.com"))
			Expect(db.Scope).To(Equal("openid email"))
			Expect(db.ClientID).To(Equal("auth0-client"))
			Expect(db.ClientSecret).To(Equal("auth0-secret"))
			Expect(db.UserClaim).To(Equal("email"))
			Expect(db.SkipNonce).To(BeTrue())
			Expect(db.LoginParameters["audience"]).To(ContainElements("api.auth0.com"))
		})

		It("should handle empty URLs", func() {
			req := UpdateProviderRequest{
				ProviderName: "test",
			}

			db, err := req.ConvertToDB()
			Expect(err).ToNot(HaveOccurred())

			Expect(db.ProviderName).To(Equal("test"))
			Expect(db.Type).To(BeEmpty())
			Expect(db.RedirectURL).To(BeNil())
			Expect(db.OIDCDB.Issuer).To(BeNil())
		})

		It("should handle nil slices and maps", func() {
			req := UpdateProviderRequest{
				ProviderName: "nil-fields",
			}

			db, err := req.ConvertToDB()
			Expect(err).ToNot(HaveOccurred())

			Expect(db.AllowedGroups).To(BeNil())
			Expect(db.OIDCDB.CodeChallengeMethod).To(BeNil())
			Expect(db.OIDCDB.SupportedSigningAlgs).To(BeNil())
			Expect(db.LoginParameters).To(BeNil())
		})

		It("should be nil for unset fields", func() {
			req := UpdateProviderRequest{
				ProviderName: "error-test",
			}

			db, err := req.ConvertToDB()
			Expect(err).ToNot(HaveOccurred())
			Expect(db).ToNot(BeNil())
			Expect(db.ClientID).To(BeEmpty())
			Expect(db.OIDCDB.Issuer).To(BeNil())
			Expect(db.OIDCDB.AuthURL).To(BeNil())
			Expect(db.OIDCDB.TokenURL).To(BeNil())
			Expect(db.OIDCDB.JWKsURL).To(BeNil())
			Expect(db.OIDCDB.UserInfoURL).To(BeNil())
			Expect(db.OIDCDB.CodeChallengeMethod).To(BeNil())
			Expect(db.OIDCDB.SupportedSigningAlgs).To(BeNil())
			Expect(db.OIDCDB.ProtectedResource).To(BeNil())
		})

		It("should not set empty string values", func() {
			req := UpdateProviderRequest{
				ProviderName:      "test",
				RedirectURL:       nil,
				ClaimsFromProfile: nil,
				SkipNonce:         nil,
			}

			db, err := req.ConvertToDB()
			Expect(err).ToNot(HaveOccurred())

			Expect(db.Type).To(BeEmpty())
			Expect(db.RedirectURL).To(BeNil())
			Expect(db.ClaimsFromProfile).To(BeFalse())
			Expect(db.SkipNonce).To(BeFalse())
		})

	})
})

var _ = Describe("ProviderListItemFromDB", func() {
	It("should convert a full ProviderDB record", func() {
		now := time.Now()
		p := &models.ProviderDB{
			ProviderName: "google",
			Type:         "oidc",
			Scope:        "openid email",
			Enabled:      true,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		issuerURL := mustParseURL("https://accounts.example.com")
		p.Issuer = (*datatypes.URL)(issuerURL)

		item := ProviderListItemFromDB(p)
		Expect(item.ProviderName).To(Equal("google"))
		Expect(item.Type).To(Equal("oidc"))
		Expect(item.Scope).To(Equal("openid email"))
		Expect(item.Enabled).To(BeTrue())
		Expect(item.Static).To(BeFalse())
		Expect(item.Issuer).To(Equal("https://accounts.example.com"))
		Expect(item.CreatedAt).NotTo(BeNil())
		Expect(item.UpdatedAt).NotTo(BeNil())
	})

	It("should handle nil issuer and zero timestamps", func() {
		p := &models.ProviderDB{
			ProviderName: "local",
			Type:         "oauth2",
		}

		item := ProviderListItemFromDB(p)
		Expect(item.Issuer).To(BeEmpty())
		Expect(item.CreatedAt).To(BeNil())
		Expect(item.UpdatedAt).To(BeNil())
	})
})

var _ = Describe("StaticProviderListItem", func() {
	It("should convert a ProviderConfig with issuer", func() {
		cfg := &ezcfg.ProviderConfig{
			ProviderName: "azure",
			Type:         "oidc",
			Scope:        "openid",
		}
		cfg.Issuer = mustParseURL("https://login.example.com")

		item := StaticProviderListItem(cfg)
		Expect(item.ProviderName).To(Equal("azure"))
		Expect(item.Type).To(Equal("oidc"))
		Expect(item.Scope).To(Equal("openid"))
		Expect(item.Issuer).To(Equal("https://login.example.com"))
		Expect(item.Static).To(BeTrue())
		Expect(item.Enabled).To(BeTrue())
	})

	It("should handle nil issuer", func() {
		cfg := &ezcfg.ProviderConfig{
			ProviderName: "github",
			Type:         "oauth2",
		}

		item := StaticProviderListItem(cfg)
		Expect(item.Issuer).To(BeEmpty())
	})
})
