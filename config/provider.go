package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

// OIDCConfig holds OIDC discovery document fields decoded from the provider's issuer endpoint.
type OIDCConfig struct {
	Issuer               *url.URL `mapstructure:"issuer" json:"issuer"`
	AuthURL              *url.URL `mapstructure:"authorization_endpoint" json:"authorization_endpoint"`
	TokenURL             *url.URL `mapstructure:"token_endpoint" json:"token_endpoint"`
	JWKsURL              *url.URL `mapstructure:"jwks_uri" json:"jwks_uri"`
	UserInfoURL          *url.URL `mapstructure:"userinfo_endpoint" json:"userinfo_endpoint"`
	RevocationURL        *url.URL `mapstructure:"revocation_endpoint" json:"revocation_endpoint"`
	CodeChallengeMethod  []string `mapstructure:"code_challenge_methods_supported" json:"code_challenge_methods_supported"`
	SupportedSigningAlgs []string `mapstructure:"id_token_signing_alg_values_supported" json:"id_token_signing_alg_values_supported"`
	ProtectedResource    *url.URL `mapstructure:"resource" json:"resource"`
}

// ProviderConfig is the configuration for a single OAuth2/OIDC identity provider.
//
//nolint:revive // established API name; renaming would be a breaking change
type ProviderConfig struct {
	ProviderName      string   `mapstructure:"name" flag:"provider-name" json:"provider_name"`
	Type              string   `mapstructure:"type" flag:"provider-type" default:"oauth2" json:"type"`
	RedirectURL       *url.URL `mapstructure:"redirect_url" json:"redirect_url"`
	DeviceAuthURL     *url.URL `mapstructure:"device_auth_url" json:"device_auth_url"`
	ValidateURL       *url.URL `mapstructure:"validate_url" json:"validate_url"`
	AllowedGroups     []string `mapstructure:"allowed_groups,omitempty" json:"allowed_groups"`
	AdminGroup        string   `mapstructure:"admin_group,omitempty" json:"admin_group,omitempty"`
	ClaimsFromProfile bool     `mapstructure:"claim_from_profile" json:"claim_from_profile"`

	OIDCConfig `mapstructure:",squash" json:"-"`

	Scope        string `mapstructure:"scopes" json:"scopes"`
	ClientID     string `mapstructure:"client_id" flag:"client-id" json:"client_id"`
	ClientSecret string `mapstructure:"client_secret" flag:"client-secret" json:"client_secret"`
	UserClaim    string `mapstructure:"user_claim" json:"user_claim"`

	SkipNonce              bool                `mapstructure:"skip_nonce" json:"skip_nonce"`
	RedirectAllowedDomains []string            `mapstructure:"redirect_allowed_domains,omitempty" json:"redirect_allowed_domains,omitempty"`
	LoginParameters        map[string][]string `mapstructure:"login_parameters" json:"login_parameters"`

	CreatedAt time.Time `mapstructure:"-" json:"created_at"`
	UpdatedAt time.Time `mapstructure:"-" json:"updated_at"`
	Enabled   bool      `mapstructure:"-" json:"enabled"`
}

// MarshalJSON implements custom JSON marshaling to convert url.URL to string
func (p *ProviderConfig) MarshalJSON() ([]byte, error) {
	type Alias ProviderConfig
	aux := &struct {
		RedirectURL   string `json:"redirect_url"`
		DeviceAuthURL string `json:"device_auth_url"`
		ValidateURL   string `json:"validate_url"`
		// OIDC fields
		Issuer               string   `json:"issuer"`
		AuthURL              string   `json:"authorization_endpoint"`
		TokenURL             string   `json:"token_endpoint"`
		JWKsURL              string   `json:"jwks_uri"`
		UserInfoURL          string   `json:"userinfo_endpoint"`
		RevocationURL        string   `json:"revocation_endpoint"`
		ProtectedResource    string   `json:"resource"`
		CodeChallengeMethod  []string `json:"code_challenge_methods_supported"`
		SupportedSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if p.RedirectURL != nil {
		aux.RedirectURL = p.RedirectURL.String()
	}
	if p.DeviceAuthURL != nil {
		aux.DeviceAuthURL = p.DeviceAuthURL.String()
	}
	if p.ValidateURL != nil {
		aux.ValidateURL = p.ValidateURL.String()
	}
	if p.Issuer != nil {
		aux.Issuer = p.Issuer.String()
	}
	if p.AuthURL != nil {
		aux.AuthURL = p.AuthURL.String()
	}
	if p.TokenURL != nil {
		aux.TokenURL = p.TokenURL.String()
	}
	if p.JWKsURL != nil {
		aux.JWKsURL = p.JWKsURL.String()
	}
	if p.UserInfoURL != nil {
		aux.UserInfoURL = p.UserInfoURL.String()
	}
	if p.RevocationURL != nil {
		aux.RevocationURL = p.RevocationURL.String()
	}
	if p.ProtectedResource != nil {
		aux.ProtectedResource = p.ProtectedResource.String()
	}
	if p.CodeChallengeMethod != nil {
		aux.CodeChallengeMethod = p.CodeChallengeMethod
	}
	if p.SupportedSigningAlgs != nil {
		aux.SupportedSigningAlgs = p.SupportedSigningAlgs
	}
	b, err := json.Marshal(aux)
	if err != nil {
		return nil, fmt.Errorf("marshal provider config: %w", err)
	}
	return b, nil
}

// DecodeOIDC decodes a provider discovery document map into an OIDCConfig.
func DecodeOIDC(target map[string]any, rs *OIDCConfig) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			mapstructure.StringToURLHookFunc(),
		),
		Result: rs,
	})
	if err != nil {
		return fmt.Errorf("create decoder: %w", err)
	}
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode oidc config: %w", err)
	}
	return nil
}
