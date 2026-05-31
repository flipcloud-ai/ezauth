package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"

	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	ezerror "github.com/flipcloud-ai/ezauth/pkg/error"
	ezmetrics "github.com/flipcloud-ai/ezauth/pkg/metrics"
	"github.com/flipcloud-ai/ezauth/pkg/middleware"
	ezproviders "github.com/flipcloud-ai/ezauth/pkg/providers"
	ezauth "github.com/flipcloud-ai/ezauth/pkg/server/auth"
	dto "github.com/flipcloud-ai/ezauth/pkg/server/dto"
	"github.com/flipcloud-ai/ezauth/pkg/server/rbac"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
)

// revokeTimeout caps the time spent calling the IdP's revocation endpoint so
// /logout stays responsive when the IdP is slow or unreachable.
const revokeTimeout = 5 * time.Second

// respondUnauthorized redirects browsers to the login page (delegating to
// redirectToLogin so the redirect format stays in one place) and returns 401
// to API/XHR clients and non-GET requests. Use this from any "no session"
// path that may be hit by both a browser and a programmatic client.
func (s *Server) respondUnauthorized(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet && wantsHTML(req) {
		s.redirectToLogin(rw, req)
		return
	}
	http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func wantsHTML(req *http.Request) bool {
	if req.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return false
	}
	accept := req.Header.Get("Accept")
	if accept == "" {
		return false
	}
	// Position-based, not q-value-based: if a client sends a quality-weighted
	// Accept that contradicts the ordering (e.g. text/html;q=0.1 before
	// application/json;q=1.0) this picks HTML. Real browsers list text/html
	// first with no conflicting q-values, and real API clients send plain
	// application/json — both cases work. Full RFC 7231 parsing isn't worth
	// the added complexity for a best-effort redirect heuristic.
	htmlIdx := strings.Index(accept, "text/html")
	jsonIdx := strings.Index(accept, "application/json")
	if htmlIdx < 0 {
		return false
	}
	if jsonIdx < 0 {
		return true
	}
	return htmlIdx < jsonIdx
}

// isSkipAuthPath reports whether the request matches a configured skip-auth
// path entry. Delegates to revProxy.matchSkipAuth; returns false when there
// is no proxy (auth-only mode).
func (s *Server) isSkipAuthPath(req *http.Request) bool {
	if s.revProxy == nil {
		return false
	}
	return s.revProxy.matchSkipAuth(req)
}

// Authorization is the RBAC enforcement middleware applied in the admin
// middleware chain. All requests reaching this handler are admin routes that
// require RBAC enforcement. Failures fail closed.
func (s *Server) Authorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		allowed, err := s.rbacController.EnforceRequest(req)
		// Fail closed: any unexpected error denies the request. Expected
		// outcomes (ErrExplicitDeny, ErrNoSession) are not logged as errors.
		switch {
		case errors.Is(err, rbac.ErrNoSession):
			ezmetrics.AuthzDenyTotal.WithLabelValues("rbac", "no_session").Inc()
			s.respondUnauthorized(rw, req)
			return
		case errors.Is(err, rbac.ErrExplicitDeny):
			ezmetrics.AuthzDenyTotal.WithLabelValues("rbac", "explicit_deny").Inc()
			s.respondError(rw, req, http.StatusForbidden, http.StatusText(http.StatusForbidden))
			return
		case err != nil:
			ezmetrics.AuthzDenyTotal.WithLabelValues("rbac", "error").Inc()
			s.requestLogger(req).Warn("rbac enforcement error",
				ezlog.Str("path", req.URL.Path),
				ezlog.Err(err))
			s.respondError(rw, req, http.StatusForbidden, http.StatusText(http.StatusForbidden))
			return
		case !allowed:
			ezmetrics.AuthzDenyTotal.WithLabelValues("rbac", "denied").Inc()
			s.respondError(rw, req, http.StatusForbidden, http.StatusText(http.StatusForbidden))
			return
		}
		ezmetrics.AuthzAllowTotal.WithLabelValues("rbac").Inc()
		next.ServeHTTP(rw, req)
	})
}

func setProxyDirector(proxy *httputil.ReverseProxy) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
		req.URL.ForceQuery = false
		req.Header.Del("Authorization")
	}
}

func stripIdentityHeaders(req *http.Request, cfg ezcfg.IdentityHeadersConfig) {
	for _, h := range []string{cfg.User, cfg.Email, cfg.Groups, cfg.Subject} {
		if h != "" {
			req.Header.Del(h)
		}
	}
}

func injectIdentityHeaders(req *http.Request, session *ezapi.Session, cfg ezcfg.IdentityHeadersConfig) {
	stripIdentityHeaders(req, cfg)
	if cfg.User != "" {
		req.Header.Set(cfg.User, session.User)
	}
	if cfg.Email != "" {
		req.Header.Set(cfg.Email, session.Email)
	}
	if cfg.Groups != "" {
		req.Header.Set(cfg.Groups, strings.Join(session.Groups, ","))
	}
	if cfg.Subject != "" {
		req.Header.Set(cfg.Subject, session.Subject)
	}
}

func (s *Server) buildProxy() *httputil.ReverseProxy {
	errorLog, err := zap.NewStdLogAt(s.Logger.Zap(), zap.ErrorLevel)
	if err != nil {
		s.Logger.Warn("failed to create error-level stdlog, falling back to default level", ezlog.Err(err))
		errorLog = zap.NewStdLog(s.Logger.Zap())
	}
	target := s.ServeCfg.Upstream
	proxy := httputil.NewSingleHostReverseProxy(target)
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var transport http.RoundTripper = &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    100,
		IdleConnTimeout:        time.Second * time.Duration(s.ServeCfg.IdleTimeout),
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: 1 << 20, // 1 MiB
	}

	proxy.Transport = transport
	proxy.ErrorLog = errorLog
	proxy.ErrorHandler = middleware.ProxyErrorHandler

	setProxyDirector(proxy)

	return proxy
}

// OAuthCallback is the OAuth2 authentication flow callback that finishes the
// OAuth2 authentication flow
// @Summary      OAuth2/OIDC callback handler
// @Description  Completes the OAuth2 authorization flow. The IdP redirects the browser here with authorization code and state. On success the user gets a session cookie and is redirected to the app. In auth-only mode returns 200 JSON.
// @Tags         Authentication
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        state query string true "State parameter for CSRF protection"
// @Param        code query string false "Authorization code (authorization code flow)"
// @Success      302 "Redirect to app (proxy mode)"
// @Success      200 {object} map[string]interface{} "Auth-only mode success JSON"
// @Failure      400 {object} dto.ErrorResponse "Callback processing error"
// @Router       /ezauth/callback [get]
func (s *Server) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	logger := s.requestLogger(req)

	err := req.ParseForm()
	if err != nil {
		logger.Error("Error in processing OAuth2 callback, error while parsing request form", ezlog.Err(err))
		s.respondError(rw, req, http.StatusBadRequest, "Error in processing OAuth2 callback, invalid request")
		return
	} else {
		errorString := req.FormValue("error")
		if errorString != "" {
			logger.Error("Error in processing OAuth2 callback, the upstream identity provider returned an error", ezlog.Str("idp_error", errorString))
			message := fmt.Sprintf("Error in processing OAuth2 callback, the upstream identity provider returned an error: %s", errorString)
			s.respondError(rw, req, http.StatusBadRequest, message)
			return
		}
	}

	encodedState := req.Form.Get("state")
	statecode, decodedState, err := ezutils.DecodeState(encodedState)
	if err != nil {
		logger.Error("Error in processing OAuth2 callback, unable to decode state", ezlog.Err(err))
		s.respondError(rw, req, http.StatusBadRequest, "Error in processing OAuth2 callback, unable to obtain CSRF cookie")
		return
	}
	req.Form.Set("statecode", statecode)
	appRedirect := decodedState.Get("app_redirect")
	providerName := decodedState.Get("provider")
	provider := s.registry.resolve(req.Context(), providerName)
	if provider == nil {
		logger.Error("Error in processing OAuth2 callback, unable to find provider", ezlog.Str("provider", providerName))
		ezmetrics.AuthLoginFailureTotal.WithLabelValues(providerName, "oidc", "unknown_provider").Inc()
		s.respondError(rw, req, http.StatusBadRequest, "Error in processing OAuth2 callback, unknown provider")
		return
	}
	ezmetrics.AuthLoginAttemptsTotal.WithLabelValues(providerName, "oidc").Inc()
	err = provider.Callback(rw, req)
	if err != nil {
		logger.Error("Error in processing OAuth2 callback", ezlog.Err(err))
		ezmetrics.AuthOIDCCallbackTotal.WithLabelValues(providerName, "failure").Inc()
		ezmetrics.AuthLoginFailureTotal.WithLabelValues(providerName, "oidc", "callback_error").Inc()
		s.respondError(rw, req, http.StatusBadRequest, "Error in processing OAuth2 callback")
		return
	} else {
		ezmetrics.AuthOIDCCallbackTotal.WithLabelValues(providerName, "success").Inc()
		ezmetrics.AuthLoginSuccessTotal.WithLabelValues(providerName, "oidc").Inc()
		ezmetrics.AuthSessionActiveTotal.Inc()
		if !s.isValidRedirect(appRedirect) {
			appRedirect = "/"
		}
		// Auth-only mode: return success, no redirect needed.
		// The external gateway handles routing using the session cookie.
		if !s.AuthCfg.Proxy.IsEnabled() {
			session := ezapi.GetRequest(req).Session
			user := ""
			if session != nil {
				user = session.User
			}
			logger.Info("Oauth2 callback finished in auth-only mode")
			s.authOnlySuccess(rw, req, user)
			return
		}
		logger.Info("Oauth2 callback is finished", ezlog.Str("redirect", appRedirect))
		http.Redirect(rw, req, appRedirect, http.StatusFound) //nolint:gosec // appRedirect is validated by isValidRedirect before use
	}
}

// Login handles the GET and POST login endpoints.
//
// @Summary      Authenticate user
// @Description  GET returns the HTML login page with provider buttons and username/password form. POST authenticates with username/password and creates a session cookie. In proxy mode the client is redirected to the upstream; in auth-only mode a 200 JSON/HTML success is returned.
// @Tags         Authentication
// @Accept       x-www-form-urlencoded
// @Produce      html,json
// @Param        username formData string false "Username (required for POST auth)"
// @Param        password formData string false "Password (required for POST auth)"
// @Param        redirect query string false "Redirect target after successful login"
// @Success      200 {string} string "Login page HTML (GET) or success (auth-only POST)"
// @Success      302 {string} string "Redirect to upstream (proxy mode POST)"
// @Failure      400 {object} dto.ErrorResponse "Bad request"
// @Failure      401 {object} dto.ErrorResponse "Invalid credentials"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/login [get]
// @Router       /ezauth/login [post]
func (s *Server) Login(rw http.ResponseWriter, req *http.Request) {
	logger := s.requestLogger(req)
	if req.Method == "POST" {
		// Auth-only mode: authenticate, set session cookie, return 200.
		// There is no upstream to redirect to — the external gateway
		// handles all routing decisions using the session cookie.
		if !s.AuthCfg.Proxy.IsEnabled() {
			logger.Info("handling login request in auth-only mode")
			s.userPassLoginAuthOnly(rw, req)
			return
		}

		redirectURL, err := s.GetRedirect(req)
		if err != nil {
			logger.Error("error in getting redirect url", ezlog.Err(err))
			s.respondError(rw, req, http.StatusBadRequest, "Failed in login")
			return
		}
		if redirectURL == fmt.Sprintf("%s%s", s.ServeCfg.AuthPrefix, signInPath) {
			redirectURL = "/"
		}
		logger.Info("handling login request", ezlog.Str("redirect_url", redirectURL))
		s.UserPassLogin(rw, req, redirectURL)
		return
	}
	// GET: render the login page with username/password form and provider buttons.
	if ezerr := s.LoginPage(rw, req, http.StatusOK); ezerr != nil {
		s.respondError(rw, req, ezerr.Code, "Failed to load login page")
	}
}

// OAuthStart redirects the browser to the identity provider's authorization URL.
//
// @Summary      Start OAuth2/OIDC login flow
// @Description  Redirects the browser to the identity provider's authorization URL for the specified provider. If no provider query param is given, renders the login page with an error.
// @Tags         Authentication
// @Produce      json
// @Param        provider query string true "Provider name to use for authentication"
// @Success      302 "Redirect to IdP authorization URL"
// @Failure      400 {object} dto.ErrorResponse "No provider found"
// @Failure      500 {object} dto.ErrorResponse "Failed to get login URL"
// @Router       /ezauth/start [get]
func (s *Server) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	logger := s.requestLogger(req)
	noCacheHeader(rw)
	p := req.URL.Query().Get("provider")
	provider := s.registry.resolve(req.Context(), p)
	if provider != nil {
		logger.Debug("starting oauth2 login flow with provider", ezlog.Str("provider", provider.ProviderName()))
		loginURL, err := provider.GetLoginURL(rw, req)
		if err != nil {
			logger.Error("Error in getting login url", ezlog.Err(err))
			s.respondError(rw, req, http.StatusInternalServerError, "Failed to start OAuth flow")
			return
		}
		if loginURL != nil && loginURL.Host != "" {
			logger.Info("Oauth2 start, redirect to login url", ezlog.Str("url", loginURL.String()))
			http.Redirect(rw, req, loginURL.String(), http.StatusFound) //nolint:gosec // loginURL is constructed by the provider from its own configuration, not from user input
			return
		}
	}
	// No provider resolved or no login URL — show login page with error.
	if ezerr := s.LoginPage(rw, req, http.StatusBadRequest, "No identity provider found"); ezerr != nil {
		s.respondError(rw, req, ezerr.Code, "Failed to load login page")
	}
}

// authOnlySuccess renders a 200 success response for auth-only mode
// login/callback. Format follows the same rules as respondError:
// JSONResponse=true → always JSON; JSONResponse=false → HTML for browsers, JSON
// for API clients.
func (s *Server) authOnlySuccess(rw http.ResponseWriter, req *http.Request, user string) {
	if s.AuthCfg.Proxy.JSONResponse || !wantsHTML(req) {
		s.writeJSONAuthSuccess(rw, user)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(rw, `<html><body>`+
		`<h1>Logged in</h1>`+
		`<p>Authentication successful. You may close this window.</p>`+
		`</body></html>`)
}

// writeJSONAuthSuccess writes a JSON success response for auth endpoints.
func (s *Server) writeJSONAuthSuccess(rw http.ResponseWriter, user string) {
	resp := dto.AuthSuccessResponse{
		Code:   http.StatusOK,
		Status: "authenticated",
		User:   user,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		body = []byte("{}")
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if _, err := rw.Write(body); err != nil {
		s.Logger.Error("error writing JSON success response", ezlog.Int("code", http.StatusOK), ezlog.Err(err))
	}
}

// Verify responds to GET /ezauth/verify. It is designed for external gateway
// auth_request integration (nginx, Kong, Envoy). It always returns JSON —
// never HTML, never a redirect — so an external proxy always gets a
// machine-readable auth decision. When the session is valid it returns 200
// with user profile fields; otherwise it returns 401.
// @Summary      Verify session (gateway auth_request integration)
// @Description  Returns the session status as JSON for external gateway auth_request integration (nginx, Kong, Envoy). 200 with user profile when authenticated; 401 when not. Never returns HTML or redirect.
// @Tags         Authentication
// @Produce      json
// @Success      200 {object} dto.VerifyResponse "Authenticated: returns user, subject, email, groups, id_type"
// @Failure      401 {object} dto.ErrorResponse "Unauthenticated: returns {authenticated: false, error: ...}"
// @Router       /ezauth/verify [get]
func (s *Server) Verify(rw http.ResponseWriter, req *http.Request) {
	noCacheHeader(rw)

	session := ezapi.GetRequest(req).Session
	if session == nil || session.IsExpired() {
		s.writeJSONError(rw, http.StatusUnauthorized, "unauthorized", false)
		return
	}

	groups := session.Groups
	if groups == nil {
		groups = []string{}
	}

	resp := dto.VerifyResponse{
		Authenticated: true,
		User:          session.User,
		Subject:       session.Subject,
		Email:         session.Email,
		Groups:        groups,
		IDType:        session.IDType,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		s.writeJSONError(rw, http.StatusInternalServerError, "internal error", false)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if _, err := rw.Write(body); err != nil {
		s.Logger.Error("error writing verify response", ezlog.Err(err))
	}
}

func (s *Server) saveSession(rw http.ResponseWriter, req *http.Request, profile ezapi.Profile) error {
	var err error
	ss := &ezapi.Session{}
	ss.Profile = profile
	ss.AccessToken, err = ezauth.GenerateToken(s.AuthCfg.JWT, ss.Profile)
	if err != nil {
		return err
	}
	ss.CreatedAtNow()
	if s.AuthCfg.Session.Cookie.Expire > 0 {
		ss.ExpiresIn(s.AuthCfg.Session.Cookie.Expire)
	}
	if err := s.sessionStore.Save(rw, req, ss); err != nil {
		return err
	}
	ezmetrics.AuthSessionCreationsTotal.WithLabelValues(profile.Provider).Inc()
	return nil
}

// authenticateUser parses the login form, validates credentials against the
// database or static user list, and returns the authenticated profile on
// success. On failure it calls respondError and returns nil.
func (s *Server) authenticateUser(rw http.ResponseWriter, req *http.Request) *ezapi.Profile {
	logger := s.requestLogger(req)
	ezmetrics.AuthLoginAttemptsTotal.WithLabelValues("local", "password").Inc()
	if err := req.ParseForm(); err != nil {
		logger.Error("Error while parsing request form", ezlog.Err(err))
		ezmetrics.AuthLoginFailureTotal.WithLabelValues("local", "password", "bad_request").Inc()
		s.respondError(rw, req, http.StatusBadRequest, "Failed to parse login form")
		return nil
	}
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	var profile *ezapi.Profile
	var err error
	if s.DB != nil {
		profile, err = s.DB.UserLogin(req.Context(), user, passwd)
		if err != nil {
			switch err {
			case ezdb.ErrNoRecord:
				logger.Warn("Login failed: user does not exist", ezlog.Str("user", user))
				ezmetrics.AuthLoginFailureTotal.WithLabelValues("local", "password", "user_not_found").Inc()
				s.respondError(rw, req, http.StatusUnauthorized, "Login failed: invalid credentials")
			case ezdb.ErrInvalidCreds:
				logger.Warn("Login failed: invalid password", ezlog.Str("user", user))
				ezmetrics.AuthLoginFailureTotal.WithLabelValues("local", "password", "invalid_credentials").Inc()
				s.respondError(rw, req, http.StatusUnauthorized, "Login failed: invalid credentials")
			default:
				logger.Error("Login failed: internal error", ezlog.Str("user", user), ezlog.Err(err))
				ezmetrics.AuthLoginFailureTotal.WithLabelValues("local", "password", "internal_error").Inc()
				s.respondError(rw, req, http.StatusInternalServerError, "Login failed due to an internal error, please try again later.")
			}
			return nil
		}
	} else {
		for _, u := range s.AuthCfg.Static {
			if user == u.User && ezutils.CompareBytes([]byte(passwd), []byte(u.Password)) {
				profile = &ezapi.Profile{
					Subject: user,
					User:    user,
				}
				break
			}
		}
	}
	if profile == nil {
		logger.Warn("Login failed: static user not found or invalid password", ezlog.Str("user", user))
		ezmetrics.AuthLoginFailureTotal.WithLabelValues("local", "password", "invalid_credentials").Inc()
		s.respondError(rw, req, http.StatusUnauthorized, "Login failed: invalid credentials")
		return nil
	}
	profile.IDType = ezapi.UserIDType
	return profile
}

// UserPassLogin handles username/password form authentication and creates a session.
func (s *Server) UserPassLogin(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	start := time.Now()
	profile := s.authenticateUser(rw, req)
	if profile == nil {
		return
	}
	ezmetrics.AuthLoginSuccessTotal.WithLabelValues("local", "password").Inc()
	ezmetrics.AuthLoginDuration.WithLabelValues("local", "password", "true").Observe(time.Since(start).Seconds())
	ezmetrics.AuthSessionActiveTotal.Inc()
	logger := s.requestLogger(req)
	if err := s.saveSession(rw, req, *profile); err != nil {
		logger.Error("error in saving session for user", ezlog.Str("user", profile.User), ezlog.Err(err))
		s.respondError(rw, req, http.StatusInternalServerError, "Failed to save login session, please contact admin.")
		return
	}
	logger.Info("successfully logged in user", ezlog.Str("user", profile.User))
	http.Redirect(rw, req, redirectURL, http.StatusFound) //nolint:gosec // redirectURL is validated by isValidRedirect before reaching this point
}

// userPassLoginAuthOnly authenticates the user and returns a 200 success
// response instead of redirecting. Used in auth-only mode when there is no
// upstream proxy to handle the redirect target.
func (s *Server) userPassLoginAuthOnly(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	profile := s.authenticateUser(rw, req)
	if profile == nil {
		return
	}
	ezmetrics.AuthLoginSuccessTotal.WithLabelValues("local", "password").Inc()
	ezmetrics.AuthLoginDuration.WithLabelValues("local", "password", "true").Observe(time.Since(start).Seconds())
	ezmetrics.AuthSessionActiveTotal.Inc()
	logger := s.requestLogger(req)
	if err := s.saveSession(rw, req, *profile); err != nil {
		logger.Error("error in saving session for user", ezlog.Str("user", profile.User), ezlog.Err(err))
		s.respondError(rw, req, http.StatusInternalServerError, "Failed to save login session, please contact admin.")
		return
	}
	logger.Info("successfully authenticated user in auth-only mode", ezlog.Str("user", profile.User))
	s.authOnlySuccess(rw, req, profile.User)
}

// renderFallbackHTML writes a minimal hardcoded HTML error page. It is the
// last-resort fallback when the error template is unavailable or fails to
// execute, so the response stays HTML no matter what.
func (s *Server) renderFallbackHTML(rw http.ResponseWriter, statusCode int, message string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(rw, `<!DOCTYPE html><html><head><title>%d %s</title></head><body><h1>%d %s</h1><p>%s</p></body></html>`,
		statusCode, template.HTMLEscapeString(http.StatusText(statusCode)),
		statusCode, template.HTMLEscapeString(http.StatusText(statusCode)),
		template.HTMLEscapeString(message))
}

// ErrorPage renders the HTML error page with the given HTTP status code and messages.
func (s *Server) ErrorPage(rw http.ResponseWriter, req *http.Request, statusCode int, messages ...string) {
	logger := s.requestLogger(req)
	noCacheHeader(rw)

	reqInfo := ezapi.GetRequest(req)

	if reqInfo == nil {
		logger.Error("Error in retrieving request id.")
		reqInfo = &ezapi.AuthRequest{}
	}

	redirectURL, err := s.GetRedirect(req)
	if err != nil {
		logger.Error("Error in getting redirect url", ezlog.Err(err))
		redirectURL = ""
	}

	var message string
	if len(messages) > 0 {
		message = messages[0]
	}
	r := s.renderer
	if r == nil {
		logger.Error("Error in rendering error page.")
		s.renderFallbackHTML(rw, statusCode, message)
		return
	}

	// Only auth-related failures (401 Unauthorized, 400 Bad Request from the
	// login/callback flow) clear the session. 403 means the user is
	// authenticated but not permitted, and 5xx / 404 are server or routing
	// problems — none of those should log the user out.
	if statusCode == http.StatusUnauthorized {
		if err := s.sessionStore.Clear(rw, req); err != nil {
			logger.Error("Error in clearing session", ezlog.Err(err))
		}
	}

	d := struct {
		Message      string
		RequestID    string
		LogoData     template.HTML
		LogoURL      string
		StaticPrefix string
		AuthPrefix   string
		StatusCode   int
		RedirectURL  string
		Title        string
		Footer       string
		AppName      string
		HideAppName  bool
	}{
		Title:        http.StatusText(statusCode),
		RedirectURL:  redirectURL,
		StatusCode:   statusCode,
		RequestID:    reqInfo.RequestID,
		StaticPrefix: s.ServeCfg.StaticPrefix,
		AuthPrefix:   s.ServeCfg.AuthPrefix,
		LogoData:     r.Logo(),
		LogoURL:      s.ServeCfg.StaticPrefix + "/logo",
		Message:      message,
		AppName:      s.ServeCfg.AppName,
		HideAppName:  s.ServeCfg.HideAppName,
	}
	logger.Debug("Rendering error page.")
	out, err := r.Execute("error.html", d)
	if err != nil {
		logger.Error("error rendering error page", ezlog.Err(err))
		s.renderFallbackHTML(rw, statusCode, message)
		return
	}
	rw.WriteHeader(statusCode)
	_, _ = rw.Write(out)
}

// LoginPage renders the HTML login page with the given status code and optional error messages.
func (s *Server) LoginPage(rw http.ResponseWriter, req *http.Request, statusCode int, errorMsg ...string) *ezerror.GeneralError {
	logger := s.requestLogger(req)
	noCacheHeader(rw)

	redirectURL, err := s.GetRedirect(req)
	if err != nil {
		logger.Error("Error in getting redirect url", ezlog.Err(err))
		return ezerror.NewError(http.StatusBadRequest)
	}

	r := s.renderer
	if r == nil {
		logger.Error("Error in rendering login page.")
		return ezerror.NewError(http.StatusInternalServerError)
	}

	if statusCode >= http.StatusBadRequest {
		if err := s.sessionStore.Clear(rw, req); err != nil {
			logger.Error("Error clearing session", ezlog.Err(err))
		}
	}

	var providers []*ezcfg.ProviderConfig
	s.registry.rangeAll(req.Context(), func(_ string, p ezproviders.Provider) bool {
		opts := p.Opts()
		providers = append(providers, &opts)
		return true
	})

	var errmsg string
	if len(errorMsg) > 0 {
		errmsg = errorMsg[0]
	}
	if statusCode > 400 && errmsg == "" {
		errmsg = fmt.Sprintf("Login Failed: %s", http.StatusText(statusCode))
	}

	d := struct {
		Providers    []*ezcfg.ProviderConfig
		CustomLogin  bool
		AuthPrefix   string
		StaticPrefix string
		LogoData     template.HTML
		LogoURL      string
		StatusCode   int
		RedirectURL  string
		ErrorMessage string
		Footer       string
		CSRFToken    string
		AppName      string
		HideAppName  bool
	}{
		RedirectURL:  redirectURL,
		StatusCode:   statusCode,
		Providers:    providers,
		CustomLogin:  s.DB != nil || len(s.AuthCfg.Static) > 0,
		AuthPrefix:   s.ServeCfg.AuthPrefix,
		StaticPrefix: s.ServeCfg.StaticPrefix,
		LogoData:     r.Logo(),
		LogoURL:      s.ServeCfg.StaticPrefix + "/logo",
		ErrorMessage: errmsg,
		CSRFToken:    middleware.Token(req),
		AppName:      s.ServeCfg.AppName,
		HideAppName:  s.ServeCfg.HideAppName,
	}
	logger.Debug("Rendering login page.")
	out, err := r.Execute("login.html", d)
	if err != nil {
		logger.Error("error rendering login page", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusInternalServerError, "Internal Server Error, please contact admin.")
		return nil
	}
	rw.WriteHeader(statusCode)
	_, _ = rw.Write(out)
	return nil
}

// Logout invalidates the caller's local session and, for OIDC-backed
// sessions, attempts to revoke the upstream tokens via RFC 7009. Upstream
// revocation is best-effort: failures are logged but do not prevent the
// local session from being cleared, so a compromised refresh_token cannot
// keep the user logged in from the proxy's perspective even if the IdP is
// unreachable. Responds 204 to API clients and redirects browsers to the
// login page.
// @Summary      Log out and clear session
// @Description  Invalidates the session and clears the session cookie. For OIDC sessions, attempts RFC 7009 upstream token revocation (best-effort). Returns 204 to API clients and redirects browsers to the login page.
// @Tags         Authentication
// @Produce      json
// @Success      204 "Session cleared successfully (API clients)"
// @Success      302 "Redirect to login page (browsers)"
// @Failure      500 {object} dto.ErrorResponse "Failed to clear session"
// @Router       /ezauth/logout [get]
// @Router       /ezauth/logout [post]
func (s *Server) Logout(rw http.ResponseWriter, req *http.Request) {
	logger := s.requestLogger(req)
	noCacheHeader(rw)

	// Only accept GET (browser link) and POST (API/form). CSRF middleware
	// guards POST; GET is idempotent from the caller's perspective because
	// clearing an already-absent session is a no-op.
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		rw.Header().Set("Allow", "GET, POST")
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session := ezapi.GetRequest(req).Session

	if session != nil && session.IDType == ezapi.OIDCUserIDType {
		// Use the exact provider that minted the session for revocation.
		// If it no longer resolves (renamed / removed from config), skip
		// upstream cleanup — the local session is still cleared below.
		p := s.registry.resolve(req.Context(), session.Provider)
		if p != nil {
			// Bound the upstream call so a hung IdP can't stall /logout —
			// local session clear is the load-bearing step.
			revokeCtx, cancel := context.WithTimeout(req.Context(), revokeTimeout)
			err := p.Revoke(revokeCtx, session)
			cancel()
			if err != nil {
				logger.Warn("Upstream token revocation failed, clearing local session anyway", ezlog.Err(err))
			} else {
				logger.Info("Upstream tokens revoked.")
			}
		} else {
			logger.Warn("No provider available for revocation, clearing local session only.")
		}
	}

	if err := s.sessionStore.Clear(rw, req); err != nil {
		logger.Error("Error clearing session on logout", ezlog.Err(err))
		s.respondError(rw, req, http.StatusInternalServerError, "Failed to clear session.")
		return
	}

	if session != nil {
		ezmetrics.AuthSessionActiveTotal.Dec()
		logger.Info("Logged out user", ezlog.Str("user", session.User))
	}

	if req.Method == http.MethodGet && wantsHTML(req) {
		http.Redirect(rw, req, s.ServeCfg.AuthPrefix+signInPath, http.StatusFound)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// Proxy forwards authenticated requests to the upstream server.
// Gate guarantees that session is non-nil and unexpired before this handler runs.
func (s *Server) Proxy(rw http.ResponseWriter, req *http.Request) {
	logger := s.requestLogger(req)
	session := ezapi.GetRequest(req).Session
	logger.Info("proxying request to upstream",
		ezlog.Str("path", req.URL.Path),
		ezlog.Str("upstream", s.ServeCfg.Upstream.String()),
		ezlog.Str("user", session.User),
	)
	if s.revProxy == nil {
		logger.Error("reverse proxy is not initialized")
		s.respondError(rw, req, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}
	injectIdentityHeaders(req, session, s.AuthCfg.Proxy.IdentityHeaders)
	s.revProxy.rp.ServeHTTP(rw, req)
}

var redirectPathRe = regexp.MustCompile(`[/\\](?:[\s\v]*|\.{1,2})[/\\]`)

func (s *Server) isValidRedirect(redirect string) bool {
	var err error
	redirect, err = url.PathUnescape(redirect)
	if err != nil {
		s.Logger.Error("error in parsing redirect path", ezlog.Err(err))
		return false
	}
	switch {
	case redirect == "":
		// The user didn't specify a redirect, we will proxy to `/`
		return false
	// Matches //, /\ and both of these with whitespace in between (eg / / or / \).
	case !strings.HasPrefix(redirect, "//") && strings.HasPrefix(redirect, "/") && !redirectPathRe.MatchString(redirect):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.ParseRequestURI(redirect)
		if err != nil {
			s.Logger.Error("rejecting invalid redirect", ezlog.Str("redirect", redirect), ezlog.Err(err))
			return false
		}
		port := redirectURL.Port()
		if port == "" {
			switch redirectURL.Scheme {
			case "http":
				port = "80"
			case "https":
				port = "443"
			}
		}
		for _, allowDomain := range s.AuthCfg.Proxy.AllowDomains {
			allowHostname, allowPort, err := net.SplitHostPort(allowDomain)
			if err != nil {
				s.Logger.Error("rejecting invalid domain in config", ezlog.Str("domain", allowDomain), ezlog.Err(err))
				continue
			}
			if allowHostname == redirectURL.Hostname() && (allowPort == port || allowPort == "*" || (allowPort == "" && redirectURL.Port() == "")) {
				return true
			}
		}
		s.Logger.Error("rejecting invalid redirect, domain or port not in whitelist", ezlog.Str("redirect", redirect))
		return false
	default:
		s.Logger.Error("rejecting invalid redirect, not an absolute or relative URL", ezlog.Str("redirect", redirect))
		return false
	}
}

// GetRedirect returns the validated redirect URL from the request, or the default upstream URL.
func (s *Server) GetRedirect(req *http.Request) (string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", fmt.Errorf("parse form: %w", err)
	}

	var redirect string

	redirect = req.Form.Get("redirect")

	if redirect == "" {
		redirect = req.Header.Get("X-Auth-Request-Redirect")
	}

	if redirect == "" {
		host := req.Header.Get("X-Forwarded-Host")
		proto := req.Header.Get("X-Forwarded-Proto")
		prefix := "/"
		if s.AuthCfg.Proxy.ProxyPrefix != "" {
			prefix = s.AuthCfg.Proxy.ProxyPrefix
		}
		redirect = fmt.Sprintf(
			"%s://%s%s",
			proto,
			host,
			prefix,
		)
	}

	if !s.isValidRedirect(redirect) {
		redirect = "/"
	}

	req.Form.Set("redirect", redirect)
	return redirect, nil
}
