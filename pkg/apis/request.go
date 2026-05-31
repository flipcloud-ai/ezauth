package apis

import (
	"context"
	"net/http"
)

// requestContextKey is a private type for context keys to avoid collisions.
type requestContextKey string

const requestKey requestContextKey = "ezauth-request"

// AuthRequest contains information regarding the request that is being made.
// The AuthRequest is used to pass information between different middlewares
// within the chain.
type AuthRequest struct {
	// TrustForwardedHeaders indicates whether the request's
	// `X-Forwarded-*` headers should be trusted (set when behind a reverse proxy).
	TrustForwardedHeaders bool

	// CSRFToken is the unmasked CSRF token for this request, if it exists.
	CSRFToken []byte

	// RequestID is set to the request's `X-Request-Id` header if set.
	// Otherwise a random UUID is set.
	RequestID string

	// Session details the authenticated users information (if it exists).
	Session *Session

	// Upstream tracks which upstream was used for this request
	Upstream string
}

// GetRequest returns the current request scope from the given request.
func GetRequest(req *http.Request) *AuthRequest {
	if req != nil {
		v := req.Context().Value(requestKey)
		if v != nil {
			return v.(*AuthRequest)
		}
	}
	return &AuthRequest{}
}

// LookupRequest returns the AuthRequest stored in the request's context,
// or nil if no value is present. Unlike GetRequest, it lets callers
// distinguish between an absent value and a zero AuthRequest.
func LookupRequest(req *http.Request) *AuthRequest {
	if req == nil {
		return nil
	}
	v := req.Context().Value(requestKey)
	if v == nil {
		return nil
	}
	return v.(*AuthRequest)
}

// AddRequestInfo adds a RequestScope to a request
func AddRequestInfo(req *http.Request, requestInfo *AuthRequest) *http.Request {
	ctx := context.WithValue(req.Context(), requestKey, requestInfo)
	return req.WithContext(ctx)
}
