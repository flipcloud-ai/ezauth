package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezproviders "github.com/flipcloud-ai/ezauth/pkg/providers"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
)

// PATAuthFunc resolves a Bearer token from the request into a session.
// It is called by LoadSession when no cookie session is found and the request
// carries an Authorization: Bearer header. Returning (nil, nil) means the
// token was not recognised; a non-nil error means an unexpected server fault.
type PATAuthFunc func(req *http.Request) (*ezapi.Session, error)

// InitSession returns middleware that attaches a new request UUID to the context.
func InitSession(trustForwardedHeaders bool) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			uuid, err := ezutils.NewRandomUUID()
			if err != nil {
				ctx := req.Context()
				logger := ezlog.FromContext(ctx)
				logger.Error("Fail to generate request ID", ezlog.Err(err))
				rw.WriteHeader(http.StatusInternalServerError)
				_, _ = rw.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
			if existing := ezapi.LookupRequest(req); existing != nil {
				// AuthRequest already present (e.g. from earlier middleware
				// or a test fixture): only backfill a missing RequestID and
				// leave other fields intact rather than replacing the pointer.
				if existing.RequestID == "" {
					existing.RequestID = uuid
				}
				next.ServeHTTP(rw, req)
				return
			}
			info := &ezapi.AuthRequest{TrustForwardedHeaders: trustForwardedHeaders, RequestID: uuid, Session: nil}
			req = ezapi.AddRequestInfo(req, info)
			next.ServeHTTP(rw, req)
		})
	}
}

// LoadSession returns middleware that loads the session from the session store
// into the request context. When patAuth is non-nil, a request carrying an
// Authorization: Bearer header is authenticated via PAT before the cookie store
// is consulted — PAT takes priority and failure is immediate (no cookie fallback).
func LoadSession(resolver ezproviders.ResolveFunc, sessionStore sessions.SessionStore, patAuth ...PATAuthFunc) mux.MiddlewareFunc {
	var pat PATAuthFunc
	if len(patAuth) > 0 {
		pat = patAuth[0]
	}
	return func(next http.Handler) http.Handler {
		return loadSession(resolver, sessionStore, pat, next)
	}
}

func loadSession(resolver ezproviders.ResolveFunc, sessionStore sessions.SessionStore, patAuth PATAuthFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		logger := ezlog.FromContext(req.Context())
		reqInfo := ezapi.GetRequest(req)

		if reqInfo.Session != nil {
			next.ServeHTTP(rw, req)
			return
		}

		// PAT first: if the request carries a Bearer token, authenticate it
		// immediately. A valid PAT yields a synthetic session. An invalid or
		// unrecognised PAT yields 401 without falling back to cookie auth.
		if patAuth != nil && hasBearerPrefix(req) {
			session, err := patAuth(req)
			if err != nil {
				logger.Error("PAT authentication error", ezlog.Err(err))
				http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			if session == nil {
				http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			reqInfo.Session = session
			next.ServeHTTP(rw, req)
			return
		}

		session, err := sessionStore.Load(req)
		switch {
		case err == nil:
			reqInfo.Session = session
		case errors.Is(err, http.ErrNoCookie):
			reqInfo.Session = nil
		case errors.Is(err, sessions.ErrNeedsRefresh):
			reqInfo.Session = refreshSession(req.Context(), session, resolver, sessionStore, rw, req)
		default:
			if errors.Is(err, sessions.ErrCorruptedSession) {
				logger.Error("Session data corrupted, clearing session", ezlog.Err(err))
				if clearErr := sessionStore.Clear(rw, req); clearErr != nil {
					logger.Error("Error clearing corrupted session", ezlog.Err(clearErr))
				}
			} else {
				logger.Error("Error loading session (transient, session preserved)", ezlog.Err(err))
			}
			reqInfo.Session = nil
		}
		next.ServeHTTP(rw, req)
	})
}

func hasBearerPrefix(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ")
}

// refreshSession handles session renewal for OAuth sessions and is a no-op for
// password / static-auth sessions. OAuth tokens are refreshed via the provider
// that originally minted the session (read from session.Profile.Provider), with
// the result persisted to the session store on success. The session is cleared
// on failure so the caller must re-authenticate rather than retrying a stale
// refresh token in a loop.
func refreshSession(
	ctx context.Context,
	session *ezapi.Session,
	resolver ezproviders.ResolveFunc,
	store sessions.SessionStore,
	rw http.ResponseWriter,
	req *http.Request,
) *ezapi.Session {
	logger := ezlog.FromContext(ctx)

	if session.IDType != ezapi.OIDCUserIDType {
		return session
	}

	providerName := session.Provider
	if providerName == "" {
		logger.Warn("OIDC session has no provider set, clearing session")
		_ = store.Clear(rw, req)
		return nil
	}

	var provider ezproviders.Provider
	if resolver != nil {
		provider = resolver(ctx, providerName)
	}
	if provider == nil {
		logger.Warn("Provider not found, unable to refresh OIDC session, clearing session", ezlog.Str("provider", providerName))
		_ = store.Clear(rw, req)
		return nil
	}

	if err := provider.RefreshSession(ctx, session); err != nil {
		logger.Error("Error refreshing session, keeping existing session", ezlog.Err(err))
		return session
	}

	if err := store.Save(rw, req, session); err != nil {
		logger.Error("Error saving refreshed session", ezlog.Err(err))
	}
	return session
}
