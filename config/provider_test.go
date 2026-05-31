package config_test

import (
	"encoding/json"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
)

var _ = Describe("ProviderConfig MarshalJSON", func() {
	DescribeTable("marshal scenarios",
		func(cfg ezcfg.ProviderConfig, check func(map[string]any)) {
			data, err := json.Marshal(&cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).ToNot(BeEmpty())

			result := make(map[string]any)
			err = json.Unmarshal(data, &result)
			Expect(err).ToNot(HaveOccurred())
			check(result)
		},
		Entry("full config with all fields", ezcfg.ProviderConfig{
			ProviderName:      "google",
			Type:              "oidc",
			RedirectURL:       mustParseURL("https://app.example.com/callback"),
			DeviceAuthURL:     mustParseURL("https://example.com/device"),
			ValidateURL:       mustParseURL("https://example.com/validate"),
			AllowedGroups:     []string{"group1", "group2"},
			ClaimsFromProfile: true,
			OIDCConfig: ezcfg.OIDCConfig{
				Issuer:               mustParseURL("https://example.com"),
				AuthURL:              mustParseURL("https://example.com/auth"),
				TokenURL:             mustParseURL("https://example.com/token"),
				JWKsURL:              mustParseURL("https://example.com/.well-known/jwks.json"),
				UserInfoURL:          mustParseURL("https://example.com/userinfo"),
				RevocationURL:        mustParseURL("https://example.com/revoke"),
				CodeChallengeMethod:  []string{"S256", "plain"},
				SupportedSigningAlgs: []string{"RS256", "ES256"},
				ProtectedResource:    mustParseURL("https://example.com/resource"),
			},
			Scope:           "openid profile email",
			ClientID:        "my-client-id",
			ClientSecret:    "my-client-secret",
			UserClaim:       "sub",
			SkipNonce:       false,
			LoginParameters: map[string][]string{"prompt": {"consent"}},
		}, func(result map[string]any) {
			Expect(result["provider_name"]).To(Equal("google"))
			Expect(result["type"]).To(Equal("oidc"))
			Expect(result["redirect_url"]).To(Equal("https://app.example.com/callback"))
			Expect(result["device_auth_url"]).To(Equal("https://example.com/device"))
			Expect(result["validate_url"]).To(Equal("https://example.com/validate"))
			Expect(result["allowed_groups"]).To(ContainElements("group1", "group2"))
			Expect(result["claim_from_profile"]).To(BeTrue())
			Expect(result["issuer"]).To(Equal("https://example.com"))
			Expect(result["authorization_endpoint"]).To(Equal("https://example.com/auth"))
			Expect(result["token_endpoint"]).To(Equal("https://example.com/token"))
			Expect(result["jwks_uri"]).To(Equal("https://example.com/.well-known/jwks.json"))
			Expect(result["userinfo_endpoint"]).To(Equal("https://example.com/userinfo"))
			Expect(result["revocation_endpoint"]).To(Equal("https://example.com/revoke"))
			Expect(result["code_challenge_methods_supported"]).To(ContainElements("S256", "plain"))
			Expect(result["id_token_signing_alg_values_supported"]).To(ContainElements("RS256", "ES256"))
			Expect(result["resource"]).To(Equal("https://example.com/resource"))
			Expect(result["scopes"]).To(Equal("openid profile email"))
			Expect(result["client_id"]).To(Equal("my-client-id"))
			Expect(result["user_claim"]).To(Equal("sub"))
			Expect(result["skip_nonce"]).To(BeFalse())
			Expect(result["login_parameters"]).To(HaveKeyWithValue("prompt", ContainElements("consent")))
		}),

		Entry("minimal config with required fields only", ezcfg.ProviderConfig{
			ProviderName: "google",
			Type:         "oidc",
		}, func(result map[string]any) {
			Expect(result["provider_name"]).To(Equal("google"))
			Expect(result["type"]).To(Equal("oidc"))
			// Empty URL fields are serialized as empty strings
			Expect(result["redirect_url"]).To(Equal(""))
			Expect(result["issuer"]).To(Equal(""))
		}),

		Entry("empty arrays", ezcfg.ProviderConfig{
			ProviderName:  "google",
			Type:          "oidc",
			AllowedGroups: []string{},
			OIDCConfig: ezcfg.OIDCConfig{
				CodeChallengeMethod:  []string{},
				SupportedSigningAlgs: []string{},
			},
			LoginParameters: map[string][]string{},
		}, func(result map[string]any) {
			Expect(result["allowed_groups"]).To(BeEmpty())
			Expect(result["login_parameters"]).To(BeEmpty())
		}),
	)
})

var _ = Describe("OIDCConfig DecodeOIDC", func() {
	It("returns error on incompatible type", func() {
		var result ezcfg.OIDCConfig
		err := ezcfg.DecodeOIDC(map[string]any{"issuer": 42}, &result)
		Expect(err).To(HaveOccurred())
	})
	DescribeTable("decode scenarios",
		func(input map[string]any, check func(ezcfg.OIDCConfig)) {
			var result ezcfg.OIDCConfig
			err := ezcfg.DecodeOIDC(input, &result)
			Expect(err).ToNot(HaveOccurred())
			check(result)
		},
		Entry("full OIDC config", map[string]any{
			"issuer":                                "https://example.com",
			"authorization_endpoint":                "https://example.com/auth",
			"token_endpoint":                        "https://example.com/token",
			"jwks_uri":                              "https://example.com/.well-known/jwks.json",
			"userinfo_endpoint":                     "https://example.com/userinfo",
			"code_challenge_methods_supported":      "S256,plain",
			"id_token_signing_alg_values_supported": "RS256,ES256",
			"resource":                              "https://example.com/resource",
		}, func(result ezcfg.OIDCConfig) {
			Expect(result.Issuer.String()).To(Equal("https://example.com"))
			Expect(result.AuthURL.String()).To(Equal("https://example.com/auth"))
			Expect(result.TokenURL.String()).To(Equal("https://example.com/token"))
			Expect(result.JWKsURL.String()).To(Equal("https://example.com/.well-known/jwks.json"))
			Expect(result.UserInfoURL.String()).To(Equal("https://example.com/userinfo"))
			Expect(result.CodeChallengeMethod).To(ContainElements("S256", "plain"))
			Expect(result.SupportedSigningAlgs).To(ContainElements("RS256", "ES256"))
			Expect(result.ProtectedResource.String()).To(Equal("https://example.com/resource"))
		}),

		Entry("nil values", map[string]any{
			"issuer":   nil,
			"jwks_uri": nil,
		}, func(result ezcfg.OIDCConfig) {
			Expect(result.Issuer).To(BeNil())
			Expect(result.JWKsURL).To(BeNil())
		}),

		Entry("empty map", map[string]any{}, func(result ezcfg.OIDCConfig) {
			Expect(result.Issuer).To(BeNil())
			Expect(result.AuthURL).To(BeNil())
			Expect(result.TokenURL).To(BeNil())
			Expect(result.JWKsURL).To(BeNil())
			Expect(result.UserInfoURL).To(BeNil())
			Expect(result.CodeChallengeMethod).To(BeNil())
			Expect(result.SupportedSigningAlgs).To(BeNil())
			Expect(result.ProtectedResource).To(BeNil())
		}),
	)
})

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
