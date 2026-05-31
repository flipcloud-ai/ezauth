package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	ezutil "github.com/flipcloud-ai/ezauth/pkg/utils"
)

// csrfContextKey is an unexported type for CSRF context keys, preventing
// collisions with keys from other packages.
type csrfContextKey string

const (
	tokenKey    csrfContextKey = "csrf_token"
	errorKey    csrfContextKey = "csrf_error"
	cookieName                 = "_xw_csrf"
	headerName                 = "X-CSRF-Token"
	tokenLength                = 32
	// tokenFormField is a plain string constant used as an html form field name
	// and multipart map key — not a context key, so it must not use csrfContextKey.
	tokenFormField = "csrf_token"
)

var defaultCSRFOpts = config.CSRFConfig{
	Name:       cookieName,
	HeaderName: headerName,
	MaxAge:     12 * time.Hour,
}

var (
	// ErrNoReferer is returned when a HTTPS request provides an empty Referer
	// header.
	ErrNoReferer = errors.New("referer not supplied")
	// ErrBadOrigin is returned when the Origin header is present and is not a
	// trusted origin.
	ErrBadOrigin = errors.New("origin invalid")
	// ErrBadReferer is returned when the scheme & host in the URL do not match
	// the supplied Referer header.
	ErrBadReferer = errors.New("referer invalid")
	// ErrNoToken is returned if no CSRF token is supplied in the request.
	ErrNoToken = errors.New("CSRF token not found in request")
	// ErrBadToken is returned if the CSRF token in the request does not match
	// the token in the session, or is otherwise malformed.
	ErrBadToken = errors.New("CSRF token invalid")
	safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)

type csrf struct {
	h            http.Handler
	opts         config.CSRFConfig
	store        sessions.SessionStore
	ErrorHandler http.Handler
}

func contextGet(r *http.Request, key csrfContextKey) (any, error) {
	val := r.Context().Value(key)
	if val == nil {
		return nil, fmt.Errorf("no value exists in the context for key %q", key)
	}
	return val, nil
}

// Token returns the masked CSRF token for the current request from the context,
// or an empty string if the CSRF middleware has not run, no token was set, or
// the path matched an ExcludePrefixes entry (excluded paths skip token issuance).
// Use this in template data or API responses to embed the token in forms/headers.
func Token(r *http.Request) string {
	if val, err := contextGet(r, tokenKey); err == nil {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// FailureReason returns the CSRF failure error stored in the request context, if any.
func FailureReason(r *http.Request) error {
	if val, err := contextGet(r, errorKey); err == nil {
		if err, ok := val.(error); ok {
			return err
		}
	}

	return nil
}

// ErrorHandler sets a status and writes the
// failure reason to the response.
func ErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, fmt.Sprintf("%s - %s",
		http.StatusText(http.StatusForbidden), FailureReason(r)),
		http.StatusForbidden)
}

// CSRF returns middleware that validates CSRF tokens on mutating requests.
func CSRF(opts *config.CSRFConfig, store sessions.SessionStore, errorHandler http.Handler) func(http.Handler) http.Handler {
	if opts == nil {
		opts = &defaultCSRFOpts
	}

	if opts.MaxAge <= 0 {
		opts.MaxAge = defaultCSRFOpts.MaxAge
	}

	if opts.Name == "" {
		opts.Name = defaultCSRFOpts.Name
	}

	if opts.HeaderName == "" {
		opts.HeaderName = defaultCSRFOpts.HeaderName
	}

	if errorHandler == nil {
		errorHandler = http.HandlerFunc(ErrorHandler)
	}

	return func(next http.Handler) http.Handler {
		return &csrf{
			h:            next,
			opts:         *opts,
			store:        store,
			ErrorHandler: errorHandler,
		}
	}
}

func contextSave(r *http.Request, key csrfContextKey, val any) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, key, val)
	return r.WithContext(ctx)
}

func wrapCSRFError(r *http.Request, err error) *http.Request {
	if err == nil {
		err = fmt.Errorf("request may be expired or invalid, please refresh your page")
	}
	return contextSave(r, errorKey, err)
}

func xorToken(a, b []byte) []byte {
	n := min(len(b), len(a))

	res := make([]byte, n)

	for i := range n {
		res[i] = a[i] ^ b[i]
	}

	return res
}

func mask(realToken []byte) (string, error) {
	otp, err := ezutil.RandomBytes(tokenLength)
	if err != nil {
		return "", fmt.Errorf("csrf: generate mask: %w", err)
	}

	// XOR the OTP with the real token to generate a masked token. Append the
	// OTP to the front of the masked token to allow unmasking in the subsequent
	// request.
	return base64.StdEncoding.EncodeToString(append(otp, xorToken(otp, realToken)...)), nil
}

// unmask splits the issued token (one-time-pad + masked token) and returns the
// unmasked request token for comparison.
func unmask(issued []byte) []byte {
	// Issued tokens are always masked and combined with the pad.
	if len(issued) != tokenLength*2 {
		return nil
	}

	// We now know the length of the byte slice.
	otp := issued[tokenLength:]
	masked := issued[:tokenLength]

	// Unmask the token by XOR'ing it against the OTP used to mask it.
	return xorToken(otp, masked)
}

// requestToken returns the issued token (pad + masked token) from the HTTP POST
// body or HTTP header. It will return nil if the token fails to decode.
func (cs *csrf) requestToken(r *http.Request) ([]byte, error) {
	// 1. Check the HTTP header first.
	issued := r.Header.Get(cs.opts.HeaderName)

	// 2. Fall back to the POST (form) value.
	if issued == "" {
		issued = r.PostFormValue(tokenFormField)
	}

	// 3. Finally, fall back to the multipart form (if set).
	if issued == "" && r.MultipartForm != nil {
		vals := r.MultipartForm.Value[tokenFormField]

		if len(vals) > 0 {
			issued = vals[0]
		}
	}

	// Return nil (equivalent to empty byte slice) if no token was found
	if issued == "" {
		return nil, nil
	}

	// Decode the "issued" (pad + masked) token sent in the request. Return a
	// nil byte slice on a decoding error (this will fail upstream).
	decoded, err := base64.StdEncoding.DecodeString(issued)
	if err != nil {
		return nil, fmt.Errorf("decode csrf token: %w", err)
	}

	return decoded, nil
}

// valueOpts builds the per-call overrides passed to the session store.
// Cookie scope (Path/Domains) and transport attributes (Secure/HTTPOnly/
// SameSite) are deliberately not set here — the store applies the session
// cookie's own values so the CSRF cookie stays consistent with the session.
// Secret is passed through only when non-empty; an empty Secret lets the
// store fall back to its configured signing key rather than HMAC with an
// empty key.
func (cs *csrf) valueOpts() *sessions.ValueOptions {
	return &sessions.ValueOptions{
		Name:   cs.opts.Name,
		Secret: cs.opts.Secret.Bytes(),
		MaxAge: cs.opts.MaxAge,
		Expire: cs.opts.Expire,
	}
}

// loadToken reads the real CSRF token from the session store. Returns nil if
// the stored value is missing, malformed, or has the wrong length.
func (cs *csrf) loadToken(r *http.Request) []byte {
	if cs.store == nil {
		return nil
	}
	val, err := cs.store.LoadValue(r, cs.valueOpts())
	if err != nil || len(val) != tokenLength {
		return nil
	}
	return val
}

// saveToken persists the real CSRF token in the session store so it can be
// retrieved on the subsequent unsafe request.
func (cs *csrf) saveToken(w http.ResponseWriter, r *http.Request, token []byte) error {
	if cs.store == nil {
		return errors.New("CSRF session store is not configured")
	}
	return cs.store.SaveValue(w, r, token, cs.valueOpts())
}

func (cs *csrf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := ezlog.FromContext(r.Context())

	// Programmatic API clients using Bearer token auth are exempt from CSRF.
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		cs.h.ServeHTTP(w, r)
		return
	}

	// Skip all CSRF processing for excluded path prefixes (e.g. static assets).
	// These paths are safe to skip because they serve read-only resources and
	// never mutate server state, so CSRF protection adds no value.
	for _, prefix := range cs.opts.ExcludePrefixes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			logger.Debug("csrf: skipping excluded prefix", ezlog.Str("path", r.URL.Path))
			cs.h.ServeHTTP(w, r)
			return
		}
	}

	reqInfo := apis.LookupRequest(r)
	if reqInfo == nil {
		logger.Error("csrf: no AuthRequest in context — InitSession middleware may be missing from the chain")
		r = wrapCSRFError(r, nil)
		cs.ErrorHandler.ServeHTTP(w, r)
		return
	}

	realToken := cs.loadToken(r)
	if len(realToken) != tokenLength {
		logger.Warn("csrf: no valid session token found, generating new token")
		generated, err := ezutil.RandomBytes(tokenLength)
		if err != nil {
			r = wrapCSRFError(r, err)
			cs.ErrorHandler.ServeHTTP(w, r)
			return
		}
		realToken = generated
		if err := cs.saveToken(w, r, realToken); err != nil {
			r = wrapCSRFError(r, err)
			cs.ErrorHandler.ServeHTTP(w, r)
			return
		}
		logger.Debug("csrf: new session token saved")
	} else {
		logger.Debug("csrf: loaded existing session token")
	}

	// Cache the real token on the AuthRequest so downstream handlers in the
	// same request can access it without hitting the session store again.
	reqInfo.CSRFToken = realToken
	// Store the masked token in the request context for use by template rendering.
	maskedToken, err := mask(realToken)
	if err != nil {
		logger.Error("csrf: failed to generate token mask", ezlog.Err(err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	r = contextSave(r, tokenKey, maskedToken)
	if !slices.Contains(safeMethods, r.Method) {
		logger.Debug("csrf: validating token for unsafe method",
			ezlog.Str("method", r.Method),
			ezlog.Str("path", r.URL.Path))
		// Infer the effective request scheme. Behind a reverse proxy we
		// trust X-Forwarded-Proto; otherwise we look at the URL's own
		// scheme and fall back to r.TLS for direct connections. When none
		// of these signals is present (common for httptest-constructed
		// requests), we default to treating the request as "strict",
		// which runs the TLS-grade Origin/Referer enforcement — safer
		// than silently skipping checks.
		effectiveScheme := ezutil.GetRequestProto(r)
		if effectiveScheme == "" {
			if r.TLS != nil {
				effectiveScheme = "https"
			} else if r.URL.Scheme != "" {
				effectiveScheme = r.URL.Scheme
			}
		}
		strict := effectiveScheme != "http"

		host := r.Host
		if host == "" {
			host = r.URL.Host
		}

		// Origin check: if present, must match the request's scheme+host,
		// or be in the trusted-origins allowlist. The browser sets Origin
		// itself and cannot be overridden from JS, so the scheme in
		// Origin reflects the real context — comparing it catches
		// MITM-over-HTTP attempts to submit to an HTTPS endpoint. When
		// the request's own scheme is unknown we only require host
		// equality, otherwise the check would reject legitimate
		// httptest-style requests where r.URL.Scheme is empty.
		if origin := r.Header.Get("Origin"); origin != "" {
			parsedOrigin, err := url.Parse(origin)
			if err != nil || parsedOrigin.Host == "" {
				logger.Error("csrf: bad origin header", ezlog.Str("origin", origin))
				r = wrapCSRFError(r, ErrBadOrigin)
				cs.ErrorHandler.ServeHTTP(w, r)
				return
			}
			sameOrigin := parsedOrigin.Host == host &&
				(effectiveScheme == "" || parsedOrigin.Scheme == effectiveScheme)
			if !sameOrigin && !slices.Contains(cs.opts.TrustedOrigins, parsedOrigin.Host) {
				logger.Error("csrf: origin mismatch",
					ezlog.Str("origin", parsedOrigin.Host),
					ezlog.Str("host", host))
				r = wrapCSRFError(r, ErrBadOrigin)
				cs.ErrorHandler.ServeHTTP(w, r)
				return
			}
		} else if strict {
			// No Origin header. Under strict (TLS-grade) enforcement,
			// require a Referer whose host matches ours (or is trusted)
			// and whose scheme is not cleartext. This prevents
			// MITM-over-HTTP attacks that inject forms targeting our
			// origin.
			referer, err := url.Parse(r.Referer())
			if err != nil || referer.String() == "" {
				logger.Error("csrf: no referer on strict request")
				r = wrapCSRFError(r, ErrNoReferer)
				cs.ErrorHandler.ServeHTTP(w, r)
				return
			}

			if referer.Scheme == "http" {
				logger.Error("csrf: referer uses cleartext scheme", ezlog.Str("referer", referer.String()))
				r = wrapCSRFError(r, ErrBadReferer)
				cs.ErrorHandler.ServeHTTP(w, r)
				return
			}

			if referer.Host != "" && referer.Host != host && !slices.Contains(cs.opts.TrustedOrigins, referer.Host) {
				logger.Error("csrf: referer host mismatch",
					ezlog.Str("referer", referer.Host),
					ezlog.Str("host", host))
				r = wrapCSRFError(r, ErrBadReferer)
				cs.ErrorHandler.ServeHTTP(w, r)
				return
			}
		}
		// Retrieve the combined token (pad + masked) token...
		maskedToken, err := cs.requestToken(r)
		if err != nil {
			logger.Error("csrf: token decode error", ezlog.Err(err))
			r = wrapCSRFError(r, ErrBadToken)
			cs.ErrorHandler.ServeHTTP(w, r)
			return
		}

		if maskedToken == nil {
			logger.Error("csrf: no token in request",
				ezlog.Str("method", r.Method),
				ezlog.Str("path", r.URL.Path))
			r = wrapCSRFError(r, ErrNoToken)
			cs.ErrorHandler.ServeHTTP(w, r)
			return
		}

		// ... and unmask it.
		requestToken := unmask(maskedToken)

		// Compare the request token against the real token
		if !ezutil.CompareBytes(requestToken, realToken) {
			logger.Error("csrf: token mismatch")
			r = wrapCSRFError(r, ErrBadToken)
			cs.ErrorHandler.ServeHTTP(w, r)
			return
		}
		logger.Debug("csrf: token validated successfully")
	}
	// Set the Vary: Cookie header to protect clients from caching the response.
	w.Header().Add("Vary", "Cookie")

	// Call the wrapped handler/router on success.
	cs.h.ServeHTTP(w, r)
}
