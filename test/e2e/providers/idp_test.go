//go:build e2e

package providers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// mockOIDCIdP is a minimal OIDC identity provider for e2e testing.
// It serves discovery, authorization (with a simple login page), token, userinfo, and JWKS endpoints.
type mockOIDCIdP struct {
	server     *httptest.Server
	URL        string
	Issuer     string
	privateKey *rsa.PrivateKey
	kid        string
	codes      map[string]*oidcAuthCode
	mu         sync.Mutex
	users      map[string]oidcTestUser
}

type oidcTestUser struct {
	Password string
	Subject  string
	Email    string
	Name     string
	Groups   []string
}

type oidcAuthCode struct {
	clientID            string
	redirectURI         string
	codeChallenge       string
	codeChallengeMethod string
	nonce               string
	username            string
	createdAt           time.Time
}

// newMockOIDCIdP creates and starts a mock OIDC identity provider.
// users maps username -> oidcTestUser for the login page.
func newMockOIDCIdP(users map[string]oidcTestUser) *mockOIDCIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	kid := randomHex(8)

	m := &mockOIDCIdP{
		privateKey: key,
		kid:        kid,
		codes:      make(map[string]*oidcAuthCode),
		users:      users,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/authorize", m.handleAuthorize)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/userinfo", m.handleUserInfo)
	mux.HandleFunc("/jwks", m.handleJWKS)

	m.server = httptest.NewServer(mux)
	m.URL = m.server.URL
	m.Issuer = m.server.URL

	return m
}

// Close shuts down the mock IdP server.
func (m *mockOIDCIdP) Close() {
	m.server.Close()
}

// discoveryResponse is the JSON returned by /.well-known/openid-configuration.
type oidcDiscovery struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint"`
	JwksURI                string   `json:"jwks_uri"`
	RevocationEndpoint     string   `json:"revocation_endpoint"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
	CodeChallengeMethods   []string `json:"code_challenge_methods_supported"`
	TokenAuthMethods       []string `json:"token_endpoint_auth_methods_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`
	IDTokenAlgSupported    []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported        []string `json:"claims_supported"`
}

func (m *mockOIDCIdP) handleDiscovery(rw http.ResponseWriter, req *http.Request) {
	doc := oidcDiscovery{
		Issuer:                 m.Issuer,
		AuthorizationEndpoint:  m.URL + "/authorize",
		TokenEndpoint:          m.URL + "/token",
		UserinfoEndpoint:       m.URL + "/userinfo",
		JwksURI:                m.URL + "/jwks",
		RevocationEndpoint:     m.URL + "/revoke",
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		CodeChallengeMethods:   []string{"S256", "plain"},
		TokenAuthMethods:       []string{"client_secret_post", "client_secret_basic"},
		ResponseTypesSupported: []string{"code"},
		ScopesSupported:        []string{"openid", "profile", "email", "groups"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenAlgSupported:    []string{"RS256"},
		ClaimsSupported:        []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "groups", "nonce"},
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(doc)
}

// handleAuthorize: GET shows a login page, POST validates credentials and redirects back with a code.
func (m *mockOIDCIdP) handleAuthorize(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		m.serveLoginPage(rw, req)
		return
	}
	if req.Method == http.MethodPost {
		m.processLogin(rw, req)
		return
	}
	http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
}

func (m *mockOIDCIdP) serveLoginPage(rw http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	state := q.Get("state")

	page := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Mock IdP Login</title>
<style>
  body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
  .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 360px; }
  h2 { text-align: center; color: #333; }
  input { width: 100%%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
  button { width: 100%%; padding: 12px; background: #409eff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; margin-top: 10px; }
  .error { color: #e74c3c; background: #fdf0ef; padding: 8px; border-radius: 4px; margin-bottom: 10px; display: none; }
</style>
</head>
<body>
<div class="login-box">
  <h2>Mock IdP</h2>
  <div class="error" id="error">Invalid credentials</div>
  <form method="post" action="%s">
    <input type="hidden" name="state" value="%s">
    <input type="text" name="username" placeholder="Username" required autofocus>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>`, req.URL.String(), state)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write([]byte(page))
}

func (m *mockOIDCIdP) processLogin(rw http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(rw, "bad form", http.StatusBadRequest)
		return
	}

	username := req.Form.Get("username")
	password := req.Form.Get("password")
	state := req.Form.Get("state")

	user, ok := m.users[username]
	if !ok || user.Password != password {
		rw.WriteHeader(http.StatusUnauthorized)
		page := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Login Failed</title></head>
<body><h1>Login Failed</h1><p>Invalid username or password.</p><p><a href="%s">Try again</a></p></body>
</html>`, req.URL.Path+"?state="+state)
		_, _ = rw.Write([]byte(page))
		return
	}

	// Parse original authorization params from the referer or reconstruct from URL
	reqURL, err := url.Parse(req.URL.String())
	if err != nil {
		http.Error(rw, "bad url", http.StatusBadRequest)
		return
	}
	authQ := reqURL.Query()

	redirectURI := authQ.Get("redirect_uri")
	clientID := authQ.Get("client_id")
	codeChallenge := authQ.Get("code_challenge")
	codeChallengeMethod := authQ.Get("code_challenge_method")
	nonce := authQ.Get("nonce")

	code := randomHex(32)

	m.mu.Lock()
	m.codes[code] = &oidcAuthCode{
		clientID:            clientID,
		redirectURI:         redirectURI,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
		nonce:               nonce,
		username:            username,
		createdAt:           time.Now(),
	}
	m.mu.Unlock()

	redir, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(rw, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	redirQ := redir.Query()
	redirQ.Set("code", code)
	redirQ.Set("state", state)
	redir.RawQuery = redirQ.Encode()

	http.Redirect(rw, req, redir.String(), http.StatusFound)
}

// handleToken exchanges an authorization code for tokens.
func (m *mockOIDCIdP) handleToken(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(rw, "bad form", http.StatusBadRequest)
		return
	}

	codeStr := req.Form.Get("code")
	codeVerifier := req.Form.Get("code_verifier")

	m.mu.Lock()
	code, ok := m.codes[codeStr]
	if ok {
		delete(m.codes, codeStr) // one-time use
	}
	m.mu.Unlock()

	if !ok {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_grant", "error_description": "invalid or expired code"})
		return
	}

	// Verify PKCE code_verifier if code_challenge was provided
	if code.codeChallenge != "" {
		if !verifyPKCE(code.codeChallenge, code.codeChallengeMethod, codeVerifier) {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_grant", "error_description": "code_verifier mismatch"})
			return
		}
	}

	user := m.users[code.username]
	now := time.Now()

	// Build signed ID token
	claims := jwt.MapClaims{
		"iss":   m.Issuer,
		"sub":   user.Subject,
		"aud":   code.clientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"email": user.Email,
		"name":  user.Name,
	}
	if code.nonce != "" {
		claims["nonce"] = code.nonce
	}
	if len(user.Groups) > 0 {
		claims["groups"] = user.Groups
	}

	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(m.privateKey)
	if err != nil {
		http.Error(rw, "failed to sign token", http.StatusInternalServerError)
		return
	}

	accessToken := "mock_at_" + randomHex(32)

	resp := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      idToken,
		"refresh_token": "mock_rt_" + randomHex(32),
	}

	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(resp)
}

// handleUserInfo returns user claims for a given access token.
func (m *mockOIDCIdP) handleUserInfo(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || !strings.HasPrefix(token, "mock_at_") {
		// Extract the subject from the token prefix... in this mock, any mock_at_ prefix works
		rw.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_token"})
		return
	}

	// In the mock, the userinfo response is a best-effort fallback.
	// The ID token already carries the claims, so this mostly serves the ClaimsFromProfile path.
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"sub":   "default-user",
		"email": "default@mock.idp",
	})
}

// handleJWKS returns the JSON Web Key Set containing the public key.
func (m *mockOIDCIdP) handleJWKS(rw http.ResponseWriter, req *http.Request) {
	pub := &m.privateKey.PublicKey

	// Encode modulus and exponent as base64url
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": m.kid,
				"use": "sig",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}

	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(jwks)
}

// verifyPKCE checks the code_verifier against the code_challenge.
func verifyPKCE(challenge, method, verifier string) bool {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return challenge == computed
	case "plain":
		return challenge == verifier
	default:
		return false
	}
}

func randomHex(n int) string {
	b := make([]byte, n/2+1)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}

// buildProviderConfig returns an ezcfg.ProviderConfig pointing to this mock IdP.
// The caller provides the client_id, client_secret, and the ezauth server's redirect_uri.
func (m *mockOIDCIdP) buildProviderConfig(name, clientID, clientSecret, redirectURI string) map[string]any {
	return map[string]any{
		"type":                             "oauth2",
		"client_id":                        clientID,
		"client_secret":                    clientSecret,
		"redirect_url":                     redirectURI,
		"issuer":                           m.Issuer,
		"scope":                            "openid profile email groups",
		"user_claim":                       "email",
		"provider_name":                    name,
		"skip_nonce":                       false,
		"csrf":                             true,
		"code_challenge_methods_supported": []string{"S256", "plain"},
	}
}

// oidcTestUser creates a simple test user entry.
func oidcUser(password, subject, email, name string, groups ...string) oidcTestUser {
	return oidcTestUser{
		Password: password,
		Subject:  subject,
		Email:    email,
		Name:     name,
		Groups:   groups,
	}
}

var _ = uuid.Nil // ensure uuid import is used
