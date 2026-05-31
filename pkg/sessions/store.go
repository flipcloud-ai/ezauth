package sessions

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"
)

var (
	// ErrNeedsRefresh is returned when a session has passed its refresh threshold.
	ErrNeedsRefresh = errors.New("session is expired, need to refresh")
	// ErrEmptyConfig is returned when session configuration is nil.
	ErrEmptyConfig = errors.New("session config is empty")
	// ErrNotImplemented is returned for unknown session store types.
	ErrNotImplemented = errors.New("session store type is not implemented")
	// ErrCorruptedSession is returned when session data cannot be decoded.
	ErrCorruptedSession = errors.New("session data is permanently invalid")
)

type store struct {
	RefreshPeriod time.Duration
	Cookie        *config.CookieStoreOptions
}

// ValueOptions carries the per-value overrides that are meaningful to any
// session store. Cookie-scope fields (Path, Domains, Secure, HTTPOnly,
// SameSite) are intentionally absent — a cookie-backed store reuses the
// session cookie's scope/transport attributes, and non-cookie stores ignore
// them entirely. This keeps the interface storage-agnostic.
type ValueOptions struct {
	// Name is the cookie name (cookie-backed store) or the key (Redis-style
	// store). Required.
	Name string
	// Secret overrides the store's signing secret for this value. Nil or
	// empty means fall back to the store's configured secret.
	Secret []byte
	// MaxAge controls the cookie's Max-Age (cookie-backed store) or the
	// value's TTL (Redis-style store). Zero means "store default".
	MaxAge time.Duration
	// Expire sets the cookie's absolute Expires timestamp relative to now.
	// Cookie-backed stores only; non-cookie stores ignore it.
	Expire time.Duration
}

// SessionStore is the interface for loading, saving, and clearing session data.
type SessionStore interface {
	Save(rw http.ResponseWriter, req *http.Request, s *ezapi.Session) error
	Load(req *http.Request) (*ezapi.Session, error)
	Clear(rw http.ResponseWriter, req *http.Request) error
	VerifyConnection(ctx context.Context) error
	// SaveValue persists an arbitrary byte value. Cookie-backed stores sign
	// and write a cookie using their session cookie's scope/transport
	// attributes, with Name/Secret/MaxAge/Expire coming from opts. Non-cookie
	// stores treat opts.Name as the key and opts.MaxAge as the TTL.
	SaveValue(rw http.ResponseWriter, req *http.Request, value []byte, opts *ValueOptions) error
	// LoadValue retrieves the value written by SaveValue. Returns (nil, nil)
	// when no value exists so callers can treat "missing" as a non-error
	// case.
	LoadValue(req *http.Request, opts *ValueOptions) ([]byte, error)
	// DeleteValue removes the value written by SaveValue. Cookie-backed
	// stores emit a clearing cookie (MaxAge=-1) unconditionally; non-cookie
	// stores (Redis-style) must treat a missing key as a successful delete
	// — return nil rather than a "not found" error so callers can invoke
	// DeleteValue as a single-use idempotent step without pre-checking.
	DeleteValue(rw http.ResponseWriter, req *http.Request, opts *ValueOptions) error
	// Close releases any resources held by the store (connections, pools, etc.).
	Close() error
}

// NewSessionStore constructs the appropriate SessionStore based on opts.StoreType.
func NewSessionStore(opts *config.Session) (SessionStore, error) {
	if opts == nil {
		return nil, ErrEmptyConfig
	}
	switch opts.StoreType {
	case config.RedisSession:
		return NewRedisStore(&opts.Cookie, &opts.Redis, opts.RefreshPeriod)
	default:
		return NewCookieStore(&opts.Cookie, opts.RefreshPeriod)
	}
}

func (s *store) needsRefresh(session *ezapi.Session) bool {
	return s.RefreshPeriod > time.Duration(0) && session.Age() > s.RefreshPeriod
}

func (s *store) Save(rw http.ResponseWriter, req *http.Request, session *ezapi.Session) error {
	return ErrNotImplemented
}

func (s *store) Load(req *http.Request) (*ezapi.Session, error) {
	return nil, ErrNotImplemented
}

func (s *store) Clear(rw http.ResponseWriter, req *http.Request) error {
	return ErrNotImplemented
}

func (s *store) VerifyConnection(ctx context.Context) error {
	return ErrNotImplemented
}

func (s *store) Close() error {
	return nil
}

// cookieOptsFor clones the session's cookie options and applies the per-value
// overrides from ValueOptions. Path/Domains/Secure/HTTPOnly/SameSite are
// inherited from the session cookie unconditionally.
func (s *store) cookieOptsFor(opts *ValueOptions) *config.CookieStoreOptions {
	c := *s.Cookie
	c.Name = opts.Name
	if len(opts.Secret) > 0 {
		c.Secret = config.NewResolvedSecretRef(opts.Secret)
	}
	if opts.MaxAge != 0 {
		c.MaxAge = opts.MaxAge
	}
	if opts.Expire != 0 {
		c.Expire = opts.Expire
	}
	return &c
}

// SaveValue writes a signed cookie for an arbitrary byte value. The cookie
// reuses the session cookie's scope (Path, Domains) and transport attributes
// (Secure, HTTPOnly, SameSite); only Name, Secret, MaxAge, and Expire are
// overridable per call via opts. Secret defaults to the session cookie's
// secret when the caller leaves it unset.
func (s *store) SaveValue(rw http.ResponseWriter, req *http.Request, value []byte, opts *ValueOptions) error {
	if opts == nil || opts.Name == "" {
		return errors.New("SaveValue requires opts.Name")
	}
	cookieOpts := s.cookieOptsFor(opts)
	signed, err := encryption.SignedValue(cookieOpts.Secret.Bytes(), cookieOpts.Name, value)
	if err != nil {
		return err
	}
	c := MakeCookieFromOptions(req, signed, cookieOpts)
	http.SetCookie(rw, c)
	return nil
}

// LoadValue reads and validates a signed cookie previously written by
// SaveValue. Missing cookies return (nil, nil).
func (s *store) LoadValue(req *http.Request, opts *ValueOptions) ([]byte, error) {
	if opts == nil || opts.Name == "" {
		return nil, errors.New("LoadValue requires opts.Name")
	}
	cookieOpts := s.cookieOptsFor(opts)
	c, err := req.Cookie(cookieOpts.Name)
	if err != nil {
		return nil, nil
	}
	return encryption.Validate(c, cookieOpts.Secret.Bytes())
}

// DeleteValue emits a clearing cookie for a value previously written by
// SaveValue. The cleared cookie inherits the session cookie's scope so
// browsers treat it as the same cookie and evict it.
func (s *store) DeleteValue(rw http.ResponseWriter, req *http.Request, opts *ValueOptions) error {
	if opts == nil || opts.Name == "" {
		return errors.New("DeleteValue requires opts.Name")
	}
	cookieOpts := s.cookieOptsFor(opts)
	c := MakeCookieFromOptions(req, "", cookieOpts) //nolint:gosec // Secure/HttpOnly/SameSite attributes are set by MakeCookieFromOptions from cookieOpts
	c.MaxAge = -1
	if !c.Expires.IsZero() {
		c.Expires = time.Now()
	}
	http.SetCookie(rw, c)
	return nil
}
