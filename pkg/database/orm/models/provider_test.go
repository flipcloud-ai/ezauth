package models

import (
	"database/sql/driver"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/lib/pq"
	"gorm.io/datatypes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ProviderDB JSON Unmarshal", func() {
	Describe("OIDCDB", func() {
		It("should unmarshal OIDC config with URLs", func() {
			jsonData := `{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/.well-known/jwks.json",
				"userinfo_endpoint": "https://example.com/userinfo",
				"code_challenge_methods_supported": ["S256", "plain"],
				"id_token_signing_alg_values_supported": ["RS256", "ES256"],
				"protected_resource": "https://example.com/resource"
			}`

			var oidc OIDCDB
			err := json.Unmarshal([]byte(jsonData), &oidc)
			Expect(err).ToNot(HaveOccurred())
			Expect(oidc.Issuer.String()).To(Equal("https://example.com"))
			Expect(oidc.AuthURL.String()).To(Equal("https://example.com/auth"))
			Expect(oidc.TokenURL.String()).To(Equal("https://example.com/token"))
			Expect(oidc.JWKsURL.String()).To(Equal("https://example.com/.well-known/jwks.json"))
			Expect(oidc.UserInfoURL.String()).To(Equal("https://example.com/userinfo"))
			Expect(oidc.CodeChallengeMethod).To(ContainElements("S256", "plain"))
			Expect(oidc.SupportedSigningAlgs).To(ContainElements("RS256", "ES256"))
			Expect(oidc.ProtectedResource.String()).To(Equal("https://example.com/resource"))
		})

		It("should handle null URLs", func() {
			jsonData := `{
				"issuer": null,
				"auth_url": null,
				"code_challenge_methods_supported": null,
				"id_token_signing_alg_values_supported": null
			}`

			var oidc OIDCDB
			err := json.Unmarshal([]byte(jsonData), &oidc)
			Expect(err).ToNot(HaveOccurred())
			Expect(oidc.Issuer).To(BeNil())
			Expect(oidc.AuthURL).To(BeNil())
			Expect(oidc.CodeChallengeMethod).To(BeNil())
			Expect(oidc.SupportedSigningAlgs).To(BeNil())
		})

		It("should handle empty arrays", func() {
			jsonData := `{
				"code_challenge_methods_supported": [],
				"id_token_signing_alg_values_supported": []
			}`

			var oidc OIDCDB
			err := json.Unmarshal([]byte(jsonData), &oidc)
			Expect(err).ToNot(HaveOccurred())
			Expect(oidc.CodeChallengeMethod).To(BeEmpty())
			Expect(oidc.SupportedSigningAlgs).To(BeEmpty())
		})
	})

	Describe("ProviderDB", func() {
		It("should unmarshal full provider config", func() {
			jsonData := `{
				"provider_name": "google",
				"type": "oidc",
				"redirect_url": "https://app.example.com/callback",
				"device_auth_url": "https://example.com/device",
				"validate_url": "https://example.com/validate",
				"allowed_groups": ["group1", "group2"],
				"claims_from_profile": true,
				"issuer": "https://example.com",
				"auth_url": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/.well-known/jwks.json",
				"userinfo_endpoint": "https://example.com/userinfo",
				"code_challenge_methods_supported": ["S256"],
				"id_token_signing_alg_values_supported": ["RS256"],
				"protected_resource": "https://example.com/resource",
				"scope": "openid profile email",
				"client_id": "my-client-id",
				"client_secret": "my-client-secret",
				"user_claim": "sub",
				"skip_nonce": false,
				"login_parameters": {
					"prompt": ["consent"],
					"access_type": ["offline"]
				}
			}`

			var provider ProviderDB
			err := json.Unmarshal([]byte(jsonData), &provider)
			Expect(err).ToNot(HaveOccurred())
			Expect(provider.ProviderName).To(Equal("google"))
			Expect(provider.Type).To(Equal("oidc"))
			Expect(provider.RedirectURL.String()).To(Equal("https://app.example.com/callback"))
			Expect(provider.DeviceAuthURL.String()).To(Equal("https://example.com/device"))
			Expect(provider.ValidateURL.String()).To(Equal("https://example.com/validate"))
			Expect(provider.AllowedGroups).To(ContainElements("group1", "group2"))
			Expect(provider.ClaimsFromProfile).To(BeTrue())
			Expect(provider.Issuer.String()).To(Equal("https://example.com"))
			Expect(provider.Scope).To(Equal("openid profile email"))
			Expect(provider.ClientID).To(Equal("my-client-id"))
			Expect(provider.ClientSecret).To(Equal("my-client-secret"))
			Expect(provider.UserClaim).To(Equal("sub"))
			Expect(provider.SkipNonce).To(BeFalse())
			Expect(provider.LoginParameters).To(HaveKeyWithValue("prompt", ContainElements("consent")))
			Expect(provider.LoginParameters).To(HaveKeyWithValue("access_type", ContainElements("offline")))
		})

		It("should handle null cookie object", func() {
			jsonData := `{
				"provider_name": "google",
				"type": "oidc",
				"redirect_url": "https://app.example.com/callback",
				"allowed_groups": null,
				"issuer": null,
				"scope": "openid",
				"client_id": "my-client-id",
				"client_secret": "my-client-secret",
				"login_parameters": null
			}`

			var provider ProviderDB
			err := json.Unmarshal([]byte(jsonData), &provider)
			Expect(err).ToNot(HaveOccurred())
			Expect(provider.ProviderName).To(Equal("google"))
			Expect(provider.AllowedGroups).To(BeNil())
			Expect(provider.Issuer).To(BeNil())
			Expect(provider.LoginParameters).To(BeNil())
		})

		It("should handle empty arrays and objects", func() {
			jsonData := `{
				"provider_name": "google",
				"type": "oidc",
				"redirect_url": "https://app.example.com/callback",
				"allowed_groups": [],
				"code_challenge_methods_supported": [],
				"id_token_signing_alg_values_supported": [],
				"scope": "openid",
				"client_id": "my-client-id",
				"client_secret": "my-client-secret",
				"login_parameters": {}
			}`

			var provider ProviderDB
			err := json.Unmarshal([]byte(jsonData), &provider)
			Expect(err).ToNot(HaveOccurred())
			Expect(provider.AllowedGroups).To(BeEmpty())
			Expect(provider.LoginParameters).To(BeEmpty())
		})

		It("should handle empty JSON object", func() {
			jsonData := `{}`

			var provider ProviderDB
			err := json.Unmarshal([]byte(jsonData), &provider)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("LoginParameters GORM marshal/unmarshal", func() {
		It("should return JSONB as GormDataType", func() {
			var params LoginParameters
			Expect(params.GormDataType()).To(Equal("JSONB"))
		})

		It("should scan JSONB bytes into LoginParameters", func() {
			jsonData := []byte(`{"prompt":["consent"],"access_type":["offline"],"extra_param":["value1","value2"]}`)
			var params LoginParameters
			err := params.Scan(jsonData)
			Expect(err).ToNot(HaveOccurred())
			Expect(params["prompt"]).To(ContainElements("consent"))
			Expect(params["access_type"]).To(ContainElements("offline"))
			Expect(params["extra_param"]).To(ContainElements("value1", "value2"))
		})

		It("should scan JSONB string into LoginParameters", func() {
			jsonStr := `{"prompt":["login"],"domain":["example.com"]}`
			var params LoginParameters
			err := params.Scan(jsonStr)
			Expect(err).ToNot(HaveOccurred())
			Expect(params["prompt"]).To(ContainElements("login"))
			Expect(params["domain"]).To(ContainElements("example.com"))
		})

		It("should return error when scanning nil value", func() {
			var params LoginParameters
			err := params.Scan(nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to unmarshal"))
		})

		It("should return error for invalid JSONB value", func() {
			var params LoginParameters
			err := params.Scan(12345)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to unmarshal"))
		})

		It("should marshal LoginParameters to driver.Value", func() {
			params := LoginParameters{
				"prompt":      {"consent", "select_account"},
				"access_type": {"offline"},
				"domain_hint": {"example.com"},
			}
			value, err := params.Value()
			Expect(err).ToNot(HaveOccurred())
			Expect(value).ToNot(BeNil())

			// Verify the marshaled value can be unmarshaled back
			var result LoginParameters
			err = json.Unmarshal(value.([]byte), &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result["prompt"]).To(ContainElements("consent", "select_account"))
			Expect(result["access_type"]).To(ContainElements("offline"))
			Expect(result["domain_hint"]).To(ContainElements("example.com"))
		})

		It("should marshal empty LoginParameters to driver.Value", func() {
			params := LoginParameters{}
			value, err := params.Value()
			Expect(err).ToNot(HaveOccurred())
			Expect(value).ToNot(BeNil())

			// Verify it's valid empty JSON
			var result LoginParameters
			err = json.Unmarshal(value.([]byte), &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(BeEmpty())
		})

		It("should handle scan and value round-trip", func() {
			// Create original LoginParameters
			original := LoginParameters{
				"prompt":          {"consent"},
				"access_type":     {"offline"},
				"include_granted": {"true"},
			}

			// Marshal to Value (simulating GORM write to DB)
			value, err := original.Value()
			Expect(err).ToNot(HaveOccurred())

			// Scan from Value (simulating GORM read from DB)
			var scanned LoginParameters
			err = scanned.Scan(value)
			Expect(err).ToNot(HaveOccurred())

			// Verify data integrity
			Expect(scanned).To(HaveKeyWithValue("prompt", ContainElements("consent")))
			Expect(scanned).To(HaveKeyWithValue("access_type", ContainElements("offline")))
			Expect(scanned).To(HaveKeyWithValue("include_granted", ContainElements("true")))
		})

		It("should handle driver.Value interface", func() {
			params := LoginParameters{"key": {"value"}}
			value, err := params.Value()
			Expect(err).ToNot(HaveOccurred())

			// Verify it implements driver.Valuer
			var _ driver.Valuer = params
			Expect(value).To(BeAssignableToTypeOf([]byte{}))
		})
	})
})

func dataURL(raw string) *datatypes.URL {
	u, _ := url.Parse(raw)
	du := datatypes.URL(*u)
	return &du
}

var _ = Describe("ProviderDB TableName", func() {
	It("should return providers", func() {
		p := ProviderDB{}
		Expect(p.TableName()).To(Equal("providers"))
	})
})

var _ = Describe("ProviderDB BeforeCreate", func() {
	It("should pass with valid provider", func() {
		p := &ProviderDB{
			ProviderName: "test",
			Type:         "oidc",
			ClientID:     "my-client-id",
			ClientSecret: "my-client-secret",
		}
		err := p.BeforeCreate(nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should fail when provider name is empty", func() {
		p := &ProviderDB{
			ProviderName: "",
			ClientID:     "id",
			ClientSecret: "secret",
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid provider name"))
	})

	It("should fail when provider name contains spaces", func() {
		p := &ProviderDB{
			ProviderName: "invalid name",
			ClientID:     "id",
			ClientSecret: "secret",
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid provider name"))
	})

	It("should fail when provider name contains special characters", func() {
		p := &ProviderDB{
			ProviderName: "name;drop",
			ClientID:     "id",
			ClientSecret: "secret",
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid provider name"))
	})

	It("should fail when provider name exceeds 64 characters", func() {
		longName := strings.Repeat("a", 65)
		p := &ProviderDB{
			ProviderName: longName,
			ClientID:     "id",
			ClientSecret: "secret",
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid provider name"))
	})

	DescribeTable("should accept valid provider names",
		func(name string) {
			p := &ProviderDB{
				ProviderName: name,
				ClientID:     "id",
				ClientSecret: "secret",
			}
			err := p.BeforeCreate(nil)
			Expect(err).ToNot(HaveOccurred())
		},
		Entry("simple name", "google"),
		Entry("name with dots", "auth.provider"),
		Entry("name with hyphens", "my-provider"),
		Entry("name with underscores", "my_provider"),
		Entry("name with colons", "provider:v2"),
		Entry("name with digits", "provider123"),
		Entry("single character", "a"),
		Entry("exactly 64 characters", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	)

	It("should fail when issuer is nil but OIDC endpoints are provided", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "id",
			ClientSecret: "secret",
			OIDCDB: OIDCDB{
				Issuer:  nil,
				AuthURL: dataURL("https://example.com/auth"),
			},
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("issuer is required when OIDC endpoints are provided"))
	})

	It("should fail when issuer is nil but token URL is provided", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "id",
			ClientSecret: "secret",
			OIDCDB: OIDCDB{
				Issuer:   nil,
				TokenURL: dataURL("https://example.com/token"),
			},
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("issuer is required when OIDC endpoints are provided"))
	})

	It("should fail when issuer is nil but JWKs URL is provided", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "id",
			ClientSecret: "secret",
			OIDCDB: OIDCDB{
				Issuer:  nil,
				JWKsURL: dataURL("https://example.com/jwks"),
			},
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("issuer is required when OIDC endpoints are provided"))
	})

	It("should fail when issuer is nil but UserInfo URL is provided", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "id",
			ClientSecret: "secret",
			OIDCDB: OIDCDB{
				Issuer:      nil,
				UserInfoURL: dataURL("https://example.com/userinfo"),
			},
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("issuer is required when OIDC endpoints are provided"))
	})

	It("should pass when issuer is set with OIDC endpoints", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "id",
			ClientSecret: "secret",
			OIDCDB: OIDCDB{
				Issuer:  dataURL("https://example.com"),
				AuthURL: dataURL("https://example.com/auth"),
			},
		}
		err := p.BeforeCreate(nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should pass when no OIDC endpoints are provided and no issuer", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "id",
			ClientSecret: "secret",
		}
		err := p.BeforeCreate(nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should fail when client_id is empty", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "",
			ClientSecret: "secret",
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("client_id and client_secret are required"))
	})

	It("should fail when client_secret is empty", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "id",
			ClientSecret: "",
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("client_id and client_secret are required"))
	})

	It("should fail when both client_id and client_secret are empty", func() {
		p := &ProviderDB{
			ProviderName: "test",
			ClientID:     "",
			ClientSecret: "",
		}
		err := p.BeforeCreate(nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("client_id and client_secret are required"))
	})

})

var _ = Describe("ParseData", func() {
	type SimpleSource struct {
		Name  string
		Value int
	}
	type SimpleTarget struct {
		Name  string
		Value int
	}

	It("should copy matching fields between simple structs", func() {
		src := SimpleSource{Name: "test", Value: 42}
		tgt := SimpleTarget{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.Name).To(Equal("test"))
		Expect(tgt.Value).To(Equal(42))
	})

	It("should return error for nil source", func() {
		tgt := SimpleTarget{}
		err := ParseData(nil, &tgt)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("source is nil"))
	})

	It("should return error for nil target", func() {
		src := SimpleSource{Name: "test"}
		err := ParseData(&src, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("target is nil"))
	})

	It("should return error for nil source pointer", func() {
		var src *SimpleSource
		tgt := SimpleTarget{}
		err := ParseData(src, &tgt)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("source pointer is nil"))
	})

	It("should return error for nil target pointer", func() {
		src := SimpleSource{Name: "test"}
		var tgt *SimpleTarget
		err := ParseData(&src, tgt)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("target pointer is nil"))
	})

	It("should return error when source is not a struct", func() {
		src := "not a struct"
		tgt := SimpleTarget{}
		err := ParseData(&src, &tgt)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("source must be a struct"))
	})

	It("should return error when target is not a struct", func() {
		src := SimpleSource{Name: "test"}
		tgt := "not a struct"
		err := ParseData(&src, &tgt)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("target must be a struct"))
	})

	It("should convert ProviderDB to ProviderDB (identity copy)", func() {
		src := ProviderDB{
			ProviderName: "test",
			Type:         "oidc",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Scope:        "openid",
			UserClaim:    "sub",
		}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.ProviderName).To(Equal("test"))
		Expect(tgt.Type).To(Equal("oidc"))
		Expect(tgt.ClientID).To(Equal("client-id"))
		Expect(tgt.ClientSecret).To(Equal("client-secret"))
		Expect(tgt.Scope).To(Equal("openid"))
		Expect(tgt.UserClaim).To(Equal("sub"))
	})

	It("should convert pq.StringArray for direct fields in same struct type", func() {
		src := ProviderDB{
			ProviderName:  "test",
			ClientID:      "id",
			ClientSecret:  "secret",
			AllowedGroups: pq.StringArray{"group1", "group2"},
		}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.AllowedGroups).To(Equal(pq.StringArray{"group1", "group2"}))
	})

	It("should handle URL fields in ProviderDB direct fields", func() {
		src := ProviderDB{
			ProviderName: "url-test",
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  dataURL("https://example.com/callback"),
			ValidateURL:  dataURL("https://example.com/validate"),
		}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.RedirectURL.String()).To(Equal("https://example.com/callback"))
		Expect(tgt.ValidateURL.String()).To(Equal("https://example.com/validate"))
	})

	It("should handle nil URL fields", func() {
		src := ProviderDB{
			ProviderName: "nil-url-test",
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  nil,
			ValidateURL:  nil,
		}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.RedirectURL).To(BeNil())
		Expect(tgt.ValidateURL).To(BeNil())
	})

	It("should handle LoginParameters conversion", func() {
		src := ProviderDB{
			ProviderName: "login-params-test",
			ClientID:     "id",
			ClientSecret: "secret",
			LoginParameters: LoginParameters{
				"prompt":      {"consent"},
				"access_type": {"offline"},
			},
		}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.LoginParameters).To(HaveKeyWithValue("prompt", []string{"consent"}))
		Expect(tgt.LoginParameters).To(HaveKeyWithValue("access_type", []string{"offline"}))
	})

	It("should handle non-pointer source value", func() {
		src := SimpleSource{Name: "value-test", Value: 99}
		tgt := SimpleTarget{}
		err := ParseData(src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.Name).To(Equal("value-test"))
		Expect(tgt.Value).To(Equal(99))
	})

	It("should skip fields that don't exist in target", func() {
		type ExtendedSource struct {
			Name  string
			Extra string
		}
		src := ExtendedSource{Name: "test", Extra: "ignored"}
		tgt := SimpleTarget{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.Name).To(Equal("test"))
	})

	It("should handle zero-value struct copy", func() {
		src := ProviderDB{}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.ProviderName).To(BeEmpty())
		Expect(tgt.Type).To(BeEmpty())
		Expect(tgt.ClientID).To(BeEmpty())
		Expect(tgt.RedirectURL).To(BeNil())
	})

	It("should handle boolean field values", func() {
		src := ProviderDB{
			ProviderName:      "bool-test",
			ClientID:          "id",
			ClientSecret:      "secret",
			ClaimsFromProfile: true,
			SkipNonce:         true,
		}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.ClaimsFromProfile).To(BeTrue())
		Expect(tgt.SkipNonce).To(BeTrue())
	})

	It("should handle time fields", func() {
		now := time.Now()
		src := ProviderDB{
			ProviderName: "time-test",
			ClientID:     "id",
			ClientSecret: "secret",
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		tgt := ProviderDB{}
		err := ParseData(&src, &tgt)
		Expect(err).ToNot(HaveOccurred())
		Expect(tgt.CreatedAt).To(Equal(now))
		Expect(tgt.UpdatedAt).To(Equal(now))
	})
})

var _ = Describe("convertField", func() {
	It("converts pq.StringArray to comma-separated string", func() {
		src := reflect.ValueOf(pq.StringArray{"a", "b", "c"})
		var dst string
		dstVal := reflect.ValueOf(&dst).Elem()
		Expect(convertField(src, dstVal)).To(Succeed())
		Expect(dst).To(Equal("a,b,c"))
	})

	It("converts string to *datatypes.URL", func() {
		src := reflect.ValueOf("https://example.com/path")
		dstVal := reflect.New(reflect.TypeOf((*datatypes.URL)(nil))).Elem()
		Expect(convertField(src, dstVal)).To(Succeed())
		dst := dstVal.Interface().(*datatypes.URL)
		Expect(dst).ToNot(BeNil())
		Expect(dst.String()).To(Equal("https://example.com/path"))
	})

	It("converts string to time.Duration", func() {
		src := reflect.ValueOf("5s")
		var dst time.Duration
		dstVal := reflect.ValueOf(&dst).Elem()
		Expect(convertField(src, dstVal)).To(Succeed())
		Expect(dst).To(Equal(5 * time.Second))
	})

	It("returns nil for empty string to time.Duration", func() {
		src := reflect.ValueOf("")
		var dst time.Duration
		dstVal := reflect.ValueOf(&dst).Elem()
		Expect(convertField(src, dstVal)).To(Succeed())
		Expect(dst).To(Equal(time.Duration(0)))
	})

	It("returns error for invalid duration string", func() {
		src := reflect.ValueOf("invalid")
		var dst time.Duration
		dstVal := reflect.ValueOf(&dst).Elem()
		err := convertField(src, dstVal)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("parse duration"))
	})

	It("converts []string to pq.StringArray", func() {
		src := reflect.ValueOf([]string{"x", "y"})
		var dst pq.StringArray
		dstVal := reflect.ValueOf(&dst).Elem()
		Expect(convertField(src, dstVal)).To(Succeed())
		Expect([]string(dst)).To(Equal([]string{"x", "y"}))
	})

	It("returns error for invalid URL string", func() {
		src := reflect.ValueOf("http://%zz")
		dstVal := reflect.New(reflect.TypeOf((*datatypes.URL)(nil))).Elem()
		err := convertField(src, dstVal)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("parse url"))
	})
})

var _ = Describe("LoginParameters Scan/Value", func() {
	It("Scan rejects non-bytes non-string input", func() {
		var lp LoginParameters
		err := lp.Scan(42)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to unmarshal"))
	})

	It("Scan rejects invalid JSON", func() {
		var lp LoginParameters
		err := lp.Scan([]byte("not-json"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unmarshal login parameters"))
	})
})

var _ = Describe("reflectStruct", func() {
	It("returns nil when dataVal cannot be set", func() {
		type testCfg struct{ Name string }
		src := reflect.ValueOf(testCfg{Name: "test"})
		dstVal := reflect.ValueOf(testCfg{})
		// Field(0) from a non-addressable value cannot be set
		err := reflectStruct(src, dstVal.Field(0))
		Expect(err).ToNot(HaveOccurred())
	})

	It("returns nil when source pointer is nil", func() {
		type testCfg struct{ Name string }
		var src *testCfg
		dstVal := reflect.ValueOf(&testCfg{}).Elem()
		err := reflectStruct(reflect.ValueOf(src), dstVal)
		Expect(err).ToNot(HaveOccurred())
	})
})
