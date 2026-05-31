package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezproviders "github.com/flipcloud-ai/ezauth/pkg/providers"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
)

// ErrMock is a generic error used in tests.
var ErrMock = fmt.Errorf("mock error")

var (
	// OIDCClientID is a randomly generated client ID for test providers.
	OIDCClientID string
	// OIDCSecret is a randomly generated client secret for test providers.
	OIDCSecret string
)

func init() {
	var err error
	OIDCClientID, err = ezutils.NewRandomString(16)
	if err != nil {
		panic(fmt.Sprintf("generate test OIDC client ID: %v", err))
	}
	OIDCSecret, err = ezutils.NewRandomString(16)
	if err != nil {
		panic(fmt.Sprintf("generate test OIDC secret: %v", err))
	}
}

// Mock token and endpoint constants used in provider tests.
//
//nolint:gosec // test constants contain mock token values, not real credentials
const (
	IDToken               = "abCdefghi123.ranDom888.IDToken"
	AccessToken           = "abCdefghi123.ranDom888.AccessToken"
	RefreshToken          = "abCdefghi123.ranDom888.RefreshToken"
	Cookiesecret          = "cookiesecret1234"
	RedirectURL           = "https://redirect.randomcloud123.com"
	ValidateURL           = "https://validate.randomcloud123.com"
	IssuerURL             = "https://www.randomcloud123.com"
	AuthorizationEndpoint = "https://www.randomcloud123.com/authorize"
	TokenEndpoint         = "https://www.randomcloud123.com/token"
	IntrospectionEndpoint = "https://www.randomcloud123.com/introspect"
	RevocationEndpoint    = "https://www.randomcloud123.com/revoke"
	UserInfoEndpoint      = "https://www.randomcloud123.com/userinfo"
	JwksUri               = "https://www.randomcloud123.com/keys"
	DeviceCodeEndpoint    = "https://www.randomcloud123.com/devicecode"
)

// RedeemTokenResponse is the JSON body returned by a mock token endpoint.
type RedeemTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

// OIDCInfo is the JSON body returned by a mock OIDC discovery endpoint.
type OIDCInfo struct {
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

// NewOIDCServer starts a test HTTP server that serves body as a JSON response with optional middlewares.
func NewOIDCServer(body []byte, middlewares ...func(rw http.ResponseWriter, r *http.Request)) (*url.URL, *httptest.Server) {
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

// NewTestProvider creates a fully-wired OIDC provider backed by mock HTTP servers for use in tests.
func NewTestProvider(redirectURL string) (ezproviders.Provider, error) {
	if redirectURL == "" {
		redirectURL = RedirectURL
	}
	rd, _ := url.Parse(redirectURL)
	profile := ezapi.Profile{
		Subject:           "testuser@randomcloud123.com",
		Email:             "testuser@randomcloud123.com",
		User:              "testuser@randomcloud123.com",
		PreferredUsername: "testuser@randomcloud123.com",
		Groups:            []string{"test1", "test2"},
	}
	tokenBody, _ := json.Marshal(RedeemTokenResponse{ //nolint:gosec // test fixture: access_token field contains a fake token for testing only
		AccessToken:  AccessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: RefreshToken,
		IDToken:      IDToken,
	})
	code := ezutils.NewRandomXID()
	tokenUrl, _ := NewOIDCServer(tokenBody, func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != code && r.Form.Get("code") != "" {
			rw.WriteHeader(http.StatusForbidden)
			_, _ = rw.Write([]byte("invalid"))
			return
		}
	})
	profileB, _ := json.Marshal(profile)
	profileURL, _ := NewOIDCServer(profileB, func(rw http.ResponseWriter, r *http.Request) {
		t := r.Header.Get("Authorization")
		token := strings.Split(t, " ")[1]
		if token != "abCdefghi123.ranDom888.NewAccessToken" && token != AccessToken {
			rw.WriteHeader(http.StatusForbidden)
			_, _ = rw.Write([]byte("invalid"))
			return
		}
	})
	a := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		q.Set("code", code)
		http.Redirect(rw, r, fmt.Sprintf("%s?%s", redirectURL, q.Encode()), http.StatusPermanentRedirect) //nolint:gosec // test fixture: redirect target is a controlled test server URL
	}))
	body, _ := json.Marshal(OIDCInfo{
		AuthorizationEndpoint: a.URL,
		TokenEndpoint:         tokenUrl.String(),
		IntrospectionEndpoint: IntrospectionEndpoint,
		RevocationEndpoint:    RevocationEndpoint,
		UserinfoEndpoint:      profileURL.String(),
		CodeChallengeMethods:  []string{"S256", "plain"},
		JwksUri:               JwksUri,
	})
	u, _ := NewOIDCServer(body)
	opt := ezcfg.ProviderConfig{
		ProviderName: "oauth",
		RedirectURL:  rd,
		ValidateURL:  tokenUrl,
		OIDCConfig: ezcfg.OIDCConfig{
			Issuer: u,
		},
		ClientID:     OIDCClientID,
		SkipNonce:    true,
		ClientSecret: OIDCSecret,
	}
	return ezproviders.NewOauthProvider(context.Background(), &opt)
}
