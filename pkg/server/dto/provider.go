package dto

import (
	"time"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// ProviderListItem is the summary record returned by the list providers API.
type ProviderListItem struct {
	ProviderName string     `json:"provider_name"`
	Type         string     `json:"type"`
	Issuer       string     `json:"issuer,omitempty"`
	Scope        string     `json:"scopes,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	Static       bool       `json:"static"`
	Enabled      bool       `json:"enabled"`
}

// ProviderListItemFromDB converts a ProviderDB record into a ProviderListItem.
func ProviderListItemFromDB(p *models.ProviderDB) *ProviderListItem {
	item := &ProviderListItem{
		ProviderName: p.ProviderName,
		Type:         p.Type,
		Scope:        p.Scope,
		Static:       false,
		Enabled:      p.Enabled,
	}
	if p.Issuer != nil {
		item.Issuer = p.Issuer.String()
	}
	if !p.CreatedAt.IsZero() {
		t := p.CreatedAt
		item.CreatedAt = &t
	}
	if !p.UpdatedAt.IsZero() {
		t := p.UpdatedAt
		item.UpdatedAt = &t
	}
	return item
}

// StaticProviderListItem converts a ProviderConfig (from static config) into a ProviderListItem.
func StaticProviderListItem(cfg *ezcfg.ProviderConfig) *ProviderListItem {
	item := &ProviderListItem{
		ProviderName: cfg.ProviderName,
		Type:         cfg.Type,
		Scope:        cfg.Scope,
		Static:       true,
		Enabled:      true,
	}
	if cfg.Issuer != nil {
		item.Issuer = cfg.Issuer.String()
	}
	return item
}

// UpdateProviderRequest is the request body for updating an OIDC/OAuth2 provider.
// @Description Request body for updating a provider configuration. All fields are optional; only provided fields are updated. provider_name and type cannot be changed via this API.
type UpdateProviderRequest struct {
	ProviderName      string    `json:"-"` // set from path parameter; cannot be changed via API
	RedirectURL       *string   `json:"redirect_url,omitempty"`
	DeviceAuthURL     *string   `json:"device_auth_url,omitempty"`
	ValidateURL       *string   `json:"validate_url,omitempty"`
	AllowedGroups     *[]string `json:"allowed_groups,omitempty"`
	AdminGroup        *string   `json:"admin_group,omitempty"`
	ClaimsFromProfile *bool     `json:"claims_from_profile,omitempty"`
	OIDCConfigRequest
	Scope           *string             `json:"scope,omitempty"`
	ClientID        *string             `json:"client_id,omitempty"`
	ClientSecret    *string             `json:"client_secret,omitempty"`
	UserClaim       *string             `json:"user_claim,omitempty"`
	SkipNonce       *bool               `json:"skip_nonce,omitempty"`
	LoginParameters map[string][]string `json:"login_parameters,omitempty"`
	Enabled         *bool               `json:"enabled,omitempty"`
}

// OIDCConfigRequest is the embedded OIDC discovery configuration in a provider update request.
// @Description OIDC discovery endpoint URLs and supported algorithm lists. All fields are optional — only provided fields are updated.
type OIDCConfigRequest struct {
	Issuer               *string   `json:"issuer,omitempty"`
	AuthURL              *string   `json:"authorization_endpoint,omitempty"`
	TokenURL             *string   `json:"token_endpoint,omitempty"`
	JWKsURL              *string   `json:"jwks_uri,omitempty"`
	UserInfoURL          *string   `json:"userinfo_endpoint,omitempty"`
	RevocationURL        *string   `json:"revocation_endpoint,omitempty"`
	CodeChallengeMethod  *[]string `json:"code_challenge_methods_supported,omitempty"`
	SupportedSigningAlgs *[]string `json:"id_token_signing_alg_values_supported,omitempty"`
	ProtectedResource    *string   `json:"protected_resource,omitempty"`
}

// ConvertToDB converts UpdateProviderRequest DTO to ProviderDB model.
func (req *UpdateProviderRequest) ConvertToDB() (*models.ProviderDB, error) {
	p := &models.ProviderDB{}
	err := models.ParseData(req, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}
