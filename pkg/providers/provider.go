package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// Package-level variables.
var (
	ErrNotImplemented    = errors.New("not implemented")
	ErrEmptyConfig       = errors.New("no provider configuration")
	ErrInvalidConfig     = errors.New("invalid provider configuration")
	ErrInitProvider      = errors.New("fail to init provider")
	ErrEmptySession      = errors.New("session is empty")
	ErrEmptyRefreshToken = errors.New("refresh token is empty")
	ErrEmptyCode         = errors.New("failed to retrieve redeem code from request")
	ErrParseToken        = errors.New("fail to parse token")
	ErrNoAccessToken     = errors.New("no access token")
	ErrInvalidIDToken    = errors.New("invalid ID token")
	ErrRefreshSession    = errors.New("unable to refresh session")
	ErrRetrieveProfile   = errors.New("unable to get user information")
)

// ResolveFunc resolves a provider by name. It abstracts over both the cached
// path (size>0) and the no-cache path (size=0, per-request DB load).
type ResolveFunc func(ctx context.Context, name string) Provider

// Provider is the interface that all OAuth/OIDC provider implementations must satisfy.
type Provider interface {
	GetLoginURL(http.ResponseWriter, *http.Request) (*url.URL, error)
	Callback(http.ResponseWriter, *http.Request) error
	Redeem(context.Context, string, string, string) (*ezapi.Session, error)
	ValidateSession(context.Context, *ezapi.Session, ...map[string]string) bool
	Authorize(context.Context, *ezapi.Session) bool
	RefreshSession(context.Context, *ezapi.Session) error
	Revoke(context.Context, *ezapi.Session) error
	ProviderName() string
	Opts() ezcfg.ProviderConfig
	GetSessionStore() sessions.SessionStore
}

// DefaultProvider provides no-op implementations of optional Provider methods.
type DefaultProvider struct {
	name          string
	opts          ezcfg.ProviderConfig
	AllowedGroups map[string]struct{}
	SessionStore  sessions.SessionStore
}

// ProviderName returns the URL-encoded name of the provider.
func (p *DefaultProvider) ProviderName() string {
	return url.QueryEscape(p.name)
}

// Opts returns the provider configuration.
func (p *DefaultProvider) Opts() ezcfg.ProviderConfig {
	return p.opts
}

// GetLoginURL returns ErrNotImplemented; override in concrete providers.
func (p *DefaultProvider) GetLoginURL(rw http.ResponseWriter, req *http.Request) (*url.URL, error) {
	return nil, ErrNotImplemented
}

// NewProvider constructs a map of provider name → Provider for each config entry.
func NewProvider(opts []*ezcfg.ProviderConfig, sessionStore sessions.SessionStore, ctxArgs ...context.Context) (map[string]Provider, error) {
	ctx := context.Background()
	if len(ctxArgs) > 0 && ctxArgs[0] != nil {
		ctx = ctxArgs[0]
	}
	providers := make(map[string]Provider)
	if len(opts) == 0 {
		return nil, ErrInitProvider
	}
	var initErrs []error
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		p, err := NewOauthProvider(ctx, opt)
		if err != nil {
			// A single provider failing (e.g. unreachable OIDC discovery endpoint)
			// must not prevent the others from loading. Collect the error so the
			// caller can log it; the periodic refresh will retry later.
			initErrs = append(initErrs, fmt.Errorf("init provider %q: %w", opt.ProviderName, err))
			continue
		}

		p.SessionStore = sessionStore

		providers[p.ProviderName()] = p
	}

	// Only support OIDC Provider now.
	return providers, errors.Join(initErrs...)
}

func (p *DefaultProvider) setAllowedGroups() {
	p.AllowedGroups = make(map[string]struct{}, len(p.opts.AllowedGroups))
	for _, group := range p.opts.AllowedGroups {
		p.AllowedGroups[group] = struct{}{}
	}
}

// ValidateSession returns false; override in concrete providers.
func (p *DefaultProvider) ValidateSession(ctx context.Context, s *ezapi.Session, headers ...map[string]string) bool {
	return false
}

// Authorize returns true if the session belongs to one of the allowed groups, or if no groups are configured.
func (p *DefaultProvider) Authorize(ctx context.Context, s *ezapi.Session) bool {
	if len(p.AllowedGroups) == 0 {
		return true
	}

	for _, group := range s.Groups {
		if _, ok := p.AllowedGroups[group]; ok {
			return true
		}
	}

	return false
}

func hasQueryParams(endpoint string) bool {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	return len(endpointURL.RawQuery) != 0
}

// RefreshSession refreshes the session token. DefaultProvider always returns ErrNotImplemented.
func (p *DefaultProvider) RefreshSession(ctx context.Context, s *ezapi.Session) error {
	return ErrNotImplemented
}

// Revoke revokes the session token. DefaultProvider always returns ErrNotImplemented.
func (p *DefaultProvider) Revoke(ctx context.Context, s *ezapi.Session) error {
	return ErrNotImplemented
}

// GetSessionStore returns the session store associated with this provider.
func (p *DefaultProvider) GetSessionStore() sessions.SessionStore {
	return p.SessionStore
}
