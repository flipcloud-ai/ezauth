package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"
)

const oidcDefaultScope = "openid email profile"
const oidcUserClaim = "sub"
const stateCookieName = "oauth_state"

var httpClient = &http.Client{Timeout: 60 * time.Second}

// OauthProvider is a concrete OAuth2/OIDC provider backed by go-oidc and golang.org/x/oauth2.
type OauthProvider struct {
	oauth2Config *oauth2.Config
	cachedKeySet oidc.KeySet
	DefaultProvider
}

// NewOauthProvider constructs an OauthProvider from the given configuration.
func NewOauthProvider(ctx context.Context, opts *ezcfg.ProviderConfig) (*OauthProvider, error) {
	if opts.Issuer == nil && (opts.AuthURL == nil || opts.TokenURL == nil) {
		return nil, fmt.Errorf("%w: provider %q: issuer or (auth_url + token_url) is required", ErrInvalidConfig, opts.ProviderName)
	}

	if opts.ProviderName == "" {
		opts.ProviderName = "oauth2"
	}

	if opts.Scope == "" {
		opts.Scope = oidcDefaultScope
	}

	if opts.UserClaim == "" {
		opts.UserClaim = oidcUserClaim
	}

	if issuerURL := opts.Issuer.String(); issuerURL != "" {
		requestURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
		httpReq, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: provider %q: create OIDC discovery request: %w", ErrInitProvider, opts.ProviderName, err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("User-Agent", "ezauth-agent")
		resp, err := httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("%w: provider %q: fetch OIDC discovery from %s: %w", ErrInitProvider, opts.ProviderName, requestURL, err)
		}
		defer func() { _ = resp.Body.Close() }()
		var providerJson map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&providerJson); err != nil {
			return nil, fmt.Errorf("%w: provider %q: decode OIDC discovery from %s: %w", ErrInitProvider, opts.ProviderName, requestURL, err)
		}
		rs := &ezcfg.OIDCConfig{}
		err = ezcfg.DecodeOIDC(providerJson, rs)
		if err != nil {
			return nil, fmt.Errorf("%w: provider %q: decode OIDC discovery: %w", ErrInitProvider, opts.ProviderName, err)
		}
		opts.OIDCConfig = *rs
	}

	p := &OauthProvider{}
	p.opts = *opts

	p.setAllowedGroups()
	p.name = opts.ProviderName
	if p.name == "" {
		return nil, ErrInvalidConfig
	}

	p.oauth2Config = &oauth2.Config{
		ClientID:     p.opts.ClientID,
		ClientSecret: p.opts.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.opts.AuthURL.String(),
			TokenURL: p.opts.TokenURL.String(),
		},
		Scopes: strings.Split(p.opts.Scope, " "),
	}
	if p.opts.DeviceAuthURL != nil {
		p.oauth2Config.Endpoint.DeviceAuthURL = p.opts.DeviceAuthURL.String()
	}

	p.cachedKeySet = oidc.NewRemoteKeySet(ctx, p.opts.JWKsURL.String())

	return p, nil
}

// Verifier constructs an oidc.IDTokenVerifier using the provider's key set and client ID.
func (p *OauthProvider) Verifier() *oidc.IDTokenVerifier {
	verifier := oidc.NewVerifier(p.opts.Issuer.String(), p.cachedKeySet, &oidc.Config{
		ClientID:             p.opts.ClientID,
		SupportedSigningAlgs: p.opts.SupportedSigningAlgs,
	})
	return verifier
}

// GetLoginURL constructs and returns the authorization redirect URL for the OAuth2 flow.
func (p *OauthProvider) GetLoginURL(rw http.ResponseWriter, req *http.Request) (*url.URL, error) {
	opts := p.opts
	params := url.Values{}
	ctx := req.Context()
	logger := ezlog.FromContext(ctx)
	var codeVerifier string
	var err error
	if len(opts.CodeChallengeMethod) >= 1 {
		logger.Debug("Generating code verifier for oauth2 login")
		codeChallengeMethod := "plain"
		if slices.Contains(opts.CodeChallengeMethod, "S256") {
			codeChallengeMethod = "S256"
		}
		codeVerifier, err = encryption.GenerateCodeVerifier(96)
		if err != nil {
			logger.Error("Error in generating code verifier", ezlog.Err(err))
			return nil, err
		}
		codeChallenge, err := encryption.GenerateCodeChallenge(codeChallengeMethod, codeVerifier)
		if err != nil {
			logger.Error("Error in generating code challenge", ezlog.Err(err))
			return nil, err
		}

		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", codeChallengeMethod)
	}

	var rawNonce []byte
	var nonceHash string
	if !opts.SkipNonce {
		logger.Debug("Generating nonce for oauth2 login")
		rawNonce, err = encryption.Nonce(32)
		if err != nil {
			logger.Error("Error generating nonce", ezlog.Err(err))
			return nil, err
		}
		nonceHash = encryption.HashNonce(rawNonce)
		params.Set("nonce", nonceHash)
	}

	redirect := req.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	state := url.Values{
		"app_redirect": {redirect},
		"provider":     {opts.ProviderName},
	}
	statecode, err := ezutils.NewRandomString(8)
	if err != nil {
		return nil, err
	}
	encodedState := ezutils.EncodeState(statecode, state)
	params.Set("state", encodedState)

	// Store statecode:codeVerifier in the session store so any instance can
	// retrieve it during callback — avoids needing a shared signing secret.
	// No browser cookie is needed; statecode travels via the OAuth state param.
	stateValue := []byte(statecode + ":" + codeVerifier)
	if len(rawNonce) > 0 {
		nonceB64 := base64.RawURLEncoding.EncodeToString(rawNonce)
		stateValue = append(stateValue, []byte(":"+nonceB64)...)
	}
	if err := p.SessionStore.SaveValue(rw, req, stateValue, &sessions.ValueOptions{
		Name:   stateCookieName + "_" + statecode,
		MaxAge: 600,
	}); err != nil {
		logger.Error("Error storing OAuth state via session store", ezlog.Err(err))
		return nil, err
	}

	for k, v := range opts.LoginParameters {
		params[k] = v
	}

	callbackRedirect, err := getOAuthRedirectURI(req, p.opts)
	if err != nil {
		logger.Error("Invalid redirect_uri", ezlog.Err(err))
		return nil, err
	}
	return makeLoginURL(p.opts, callbackRedirect, params)
}

func getOAuthRedirectURI(req *http.Request, opts ezcfg.ProviderConfig) (string, error) {
	rd := opts.RedirectURL
	if rd == nil {
		rd = &url.URL{}
	}
	if rd.Host == "" {
		rd.Host = ezutils.GetRequestHost(req)
	}
	if rd.Scheme == "" {
		rd.Scheme = schemeHTTP
	}

	if proto := ezutils.GetRequestProto(req); proto == schemeHTTPS {
		rd.Scheme = schemeHTTPS
	}

	if len(opts.RedirectAllowedDomains) > 0 {
		if !isHostAllowed(rd.Host, opts.RedirectAllowedDomains) {
			return "", fmt.Errorf("redirect_uri host %q is not in allowed domains", rd.Host)
		}
	}

	return rd.String(), nil
}

// isHostAllowed checks whether host is in the allowed domain list.
func isHostAllowed(host string, allowedDomains []string) bool {
	reqHost, reqPort, err := net.SplitHostPort(host)
	if err != nil {
		reqHost = host
	}
	for _, allowed := range allowedDomains {
		allowHost, allowPort, err := net.SplitHostPort(allowed)
		if err != nil {
			allowHost = allowed
		}
		if allowHost == reqHost {
			if allowPort == "" || allowPort == "*" || allowPort == reqPort {
				return true
			}
		}
	}
	return false
}

func makeLoginURL(opts ezcfg.ProviderConfig, redirectURI string, extraParams url.Values) (*url.URL, error) {
	a := *opts.AuthURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", opts.Scope)
	params.Set("client_id", opts.ClientID)
	params.Set("response_type", "code")

	for n, p := range extraParams {
		for _, v := range p {
			params.Set(n, v)
		}
	}
	a.RawQuery = params.Encode()
	return &a, nil
}

// Redeem exchanges an authorization code for tokens and returns a populated session.
func (p *OauthProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*ezapi.Session, error) {
	if code == "" {
		return nil, ErrEmptyCode
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.opts.ClientID)
	params.Add("client_secret", p.opts.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	body := bytes.NewBufferString(params.Encode())
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.opts.TokenURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("User-Agent", "ezauth-agent")
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	ss := &ezapi.Session{}
	type jsonResponse struct {
		ExpiresIn int64 `json:"expires_in"`
		*ezapi.Session
	}
	jsonRes := jsonResponse{
		Session: ss,
	}
	logger := ezlog.FromContext(ctx)
	if err := json.Unmarshal(respBody, &jsonRes); err != nil {
		logger.Error("Error redeeming code during OAuth2 callback, fail to parse token", ezlog.Err(err))
		return nil, ErrParseToken
	}

	if ss.AccessToken == "" {
		return nil, ErrNoAccessToken
	}

	verifier := p.Verifier()

	if _, err := verifier.Verify(ctx, ss.IDToken); err != nil {
		logger.Error("Failed to verify id token", ezlog.Err(err))
		return nil, ErrInvalidIDToken
	}

	expire := time.Duration(jsonRes.ExpiresIn) * time.Second

	ss.CreatedAtNow()
	ss.ExpiresIn(expire)

	err = p.refreshSessionFromToken(ss)
	if err != nil || p.opts.ClaimsFromProfile {
		err = p.refreshSessionFromProfile(ctx, ss)
	}

	return ss, err
}

// Callback handles the OAuth2 authorization code callback.
func (p *OauthProvider) Callback(rw http.ResponseWriter, req *http.Request) error {
	opts := p.opts

	logger := ezlog.FromContext(req.Context())

	if err := req.ParseForm(); err != nil {
		logger.Error("error parsing callback form", ezlog.Err(err))
		return fmt.Errorf("error parsing callback form: %w", err)
	}
	statecode := req.Form.Get("statecode")

	// Retrieve statecode:codeVerifier from session store using statecode as key.
	stateOpts := &sessions.ValueOptions{
		Name: stateCookieName + "_" + statecode,
	}
	stateValue, err := p.SessionStore.LoadValue(req, stateOpts)
	if err != nil {
		return fmt.Errorf("error loading OAuth state from session store: %w", err)
	}
	if len(stateValue) == 0 {
		return fmt.Errorf("state cookie not found")
	}
	parts := strings.SplitN(string(stateValue), ":", 3)
	if len(parts) < 2 {
		return fmt.Errorf("invalid state format")
	}
	if parts[0] != statecode {
		return fmt.Errorf("invalid state code")
	}
	codeVerifier := parts[1]

	// Extract nonce if present.
	var rawNonce []byte
	if !opts.SkipNonce && len(parts) > 2 && parts[2] != "" {
		var err error
		rawNonce, err = base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return fmt.Errorf("invalid nonce encoding in state: %w", err)
		}
	}

	if derr := p.SessionStore.DeleteValue(rw, req, stateOpts); derr != nil {
		logger.Warn("failed to invalidate OAuth state in session store", ezlog.Err(derr))
	}

	redirectURI, err := getOAuthRedirectURI(req, opts)
	if err != nil {
		logger.Error("Invalid redirect_uri in callback", ezlog.Err(err))
		return fmt.Errorf("invalid redirect_uri: %w", err)
	}
	session, err := p.Redeem(req.Context(), redirectURI, req.Form.Get("code"), codeVerifier)
	if err != nil {
		logger.Error("Invalid authentication via OAuth2: unable to redeem code", ezlog.Err(err))
		return err
	}

	// Verify nonce if enabled and present in state.
	if !opts.SkipNonce && len(rawNonce) > 0 {
		session.Nonce = rawNonce
		payload, err := ezutils.ParseJWT(session.IDToken)
		if err != nil {
			logger.Warn("nonce verification failed: cannot parse id token", ezlog.Err(err))
			return ErrInvalidIDToken
		}
		var claims struct {
			Nonce string `json:"nonce"`
		}
		if err = json.Unmarshal(payload, &claims); err != nil {
			logger.Warn("nonce verification failed: cannot unmarshal id token claims", ezlog.Err(err))
			return ErrInvalidIDToken
		}
		if claims.Nonce == "" {
			logger.Warn("id token missing nonce claim")
			return fmt.Errorf("nonce claim missing from id token")
		}
		if !session.CheckNonce(claims.Nonce) {
			logger.Warn("nonce mismatch in id token: possible replay attack")
			return fmt.Errorf("nonce mismatch: possible replay attack")
		}
	}

	if !p.Authorize(req.Context(), session) {
		return fmt.Errorf("resources are not authorized")
	}
	session.IDType = ezapi.OIDCUserIDType
	session.Provider = p.ProviderName()
	if err := p.SessionStore.Save(rw, req, session); err != nil {
		return fmt.Errorf("unable to save session: %w", err)
	}
	return nil
}

// ValidateSession checks whether the session's access token is still valid via the UserInfo endpoint.
func (p *OauthProvider) ValidateSession(ctx context.Context, s *ezapi.Session, headers ...map[string]string) bool {
	logger := ezlog.FromContext(ctx)
	if s.AccessToken == "" {
		logger.Error("Empty access token in session")
		return false
	}

	validateURL := p.opts.ValidateURL
	if validateURL == nil {
		logger.Error("Empty validation url")
		return false
	}
	if validateURL.Scheme == "" || validateURL.Host == "" {
		logger.Error("Invalid validate url", ezlog.Str("url", validateURL.String()))
		return false
	}

	params := url.Values{"access_token": {s.AccessToken}}
	endpoint := validateURL.String()
	if hasQueryParams(endpoint) {
		endpoint = endpoint + "&" + params.Encode()
	} else {
		endpoint = endpoint + "?" + params.Encode()
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		logger.Error("Token validation request creation failed", ezlog.Err(err))
		return false
	}
	httpReq.Header.Set("User-Agent", "ezauth-agent")
	if len(headers) > 0 {
		for k, v := range headers[0] {
			httpReq.Header.Set(k, v)
		}
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		logger.Error("Token validation request failed", ezlog.Err(err))
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		return true
	}
	respBody, _ := io.ReadAll(resp.Body)
	logger.Error("Token validation request failed", ezlog.Int("status", resp.StatusCode), ezlog.Str("body", string(respBody)))
	return false
}

// RefreshSession uses the refresh token to obtain new access and ID tokens.
func (p *OauthProvider) RefreshSession(ctx context.Context, s *ezapi.Session) error {
	if s == nil {
		return ErrEmptySession
	}
	return p.refreshSession(ctx, s)
}

// Revoke invalidates the session's tokens at the identity provider per RFC 7009.
func (p *OauthProvider) Revoke(ctx context.Context, s *ezapi.Session) error {
	if s == nil {
		return ErrEmptySession
	}
	revokeURL := p.opts.RevocationURL
	if revokeURL == nil || revokeURL.String() == "" {
		return nil
	}
	token := s.RefreshToken
	tokenType := "refresh_token"
	if token == "" {
		token = s.AccessToken
		tokenType = "access_token"
	}
	if token == "" {
		return nil
	}
	params := url.Values{}
	params.Set("token", token)
	params.Set("token_type_hint", tokenType)
	params.Set("client_id", p.opts.ClientID)
	if p.opts.ClientSecret != "" {
		params.Set("client_secret", p.opts.ClientSecret)
	}
	body := bytes.NewBufferString(params.Encode())
	httpReq, err := http.NewRequestWithContext(ctx, "POST", revokeURL.String(), body)
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("User-Agent", "ezauth-agent")
	if p.opts.ClientSecret != "" {
		escapedAuth := url.QueryEscape(p.opts.ClientID) + ":" + url.QueryEscape(p.opts.ClientSecret)
		httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(escapedAuth)))
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("revoke request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if code := resp.StatusCode; code != http.StatusOK && code != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token revocation failed with status %d: %s", code, string(respBody))
	}
	return nil
}

func (p *OauthProvider) refreshSession(ctx context.Context, s *ezapi.Session) error {
	logger := ezlog.FromContext(ctx)
	if s.RefreshToken == "" {
		return ErrEmptyRefreshToken
	}

	c := p.oauth2Config
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		logger.Error("Error in refreshing token from token issuer", ezlog.Err(err))
		return ErrRefreshSession
	}
	s.AccessToken = token.AccessToken
	idToken := token.Extra("id_token")

	if idToken != nil && idToken != "" {
		verifier := p.Verifier()
		if _, err := verifier.Verify(ctx, idToken.(string)); err != nil {
			logger.Error("Error in validating id token", ezlog.Err(err))
			return ErrInvalidIDToken
		}
		s.IDToken = idToken.(string)
		err = p.refreshSessionFromToken(s)
		if err != nil || p.opts.ClaimsFromProfile {
			err = p.refreshSessionFromProfile(ctx, s)
		}
	} else {
		return ErrInvalidIDToken
	}

	if err == nil {
		s.RefreshToken = token.RefreshToken
		s.CreatedAt = time.Now().Unix()
		if token.ExpiresIn == 0 {
			s.ExpiresOn = token.Expiry.Unix()
		} else {
			s.ExpiresIn(time.Duration(token.ExpiresIn) * time.Second)
		}
		return nil
	}

	return ErrRefreshSession
}

func (p *OauthProvider) refreshSessionFromToken(session *ezapi.Session) error {
	payload, err := ezutils.ParseJWT(session.IDToken)
	if err != nil {
		return ErrInvalidIDToken
	}
	profile := &ezapi.Profile{}
	err = json.Unmarshal(payload, profile)
	if err != nil {
		return ErrInvalidIDToken
	}
	session.Profile = *profile
	return nil
}

func (p *OauthProvider) refreshSessionFromProfile(ctx context.Context, session *ezapi.Session, headers ...map[string]string) error {
	logger := ezlog.FromContext(ctx)
	profileURL := p.opts.UserInfoURL
	if profileURL == nil || profileURL.String() == "" {
		logger.Error("empty profile url, not able to refresh session from profile")
		return ErrRefreshSession
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", profileURL.String(), nil)
	if err != nil {
		logger.Error("Failed to create profile request", ezlog.Err(err))
		return ErrRetrieveProfile
	}
	httpReq.Header.Set("User-Agent", "ezauth-agent")
	if len(headers) > 0 {
		for k, v := range headers[0] {
			httpReq.Header.Set(k, v)
		}
	} else {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session.AccessToken))
		httpReq.Header.Set("Accept", "application/json")
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		logger.Error("Failed to retrieve user profile", ezlog.Err(err))
		return ErrRetrieveProfile
	}
	defer func() { _ = resp.Body.Close() }()

	// Check if the response is a JWT token
	// https://openid.net/specs/openid-connect-core-1_0-final.html#UserInfoResponse
	mediaType, _, parseErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	profile := &ezapi.Profile{}
	if parseErr == nil && mediaType == "application/jwt" {
		var b []byte
		b, err = io.ReadAll(resp.Body)
		if err == nil {
			var payload []byte
			payload, err = ezutils.ParseJWT(string(b))
			if err == nil {
				err = json.Unmarshal(payload, profile)
			}
		}
	} else {
		err = json.NewDecoder(resp.Body).Decode(profile)
	}
	if err != nil {
		logger.Error("Failed to retrieve user profile", ezlog.Err(err))
		return ErrRetrieveProfile
	}
	session.Profile = *profile
	return nil
}
