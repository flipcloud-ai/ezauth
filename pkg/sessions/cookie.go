package sessions

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezutil "github.com/flipcloud-ai/ezauth/pkg/utils"
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"
)

const (
	// Cookies are limited to 4kb for all parts
	// including the cookie name, value, attributes; IE (http.cookie).String()
	// Most browsers' max is 4096 -- but we give ourselves some leeway
	maxCookieLength = 4000
)

// CookieStore implements SessionStore by persisting session data in signed HTTP cookies.
type CookieStore struct {
	store
	Cookie       *config.CookieStoreOptions
	CookieCipher encryption.Cipher
}

// Save takes a ezapi.Session and stores the information from it
// within Cookies set on the HTTP response writer
func (s *CookieStore) Save(rw http.ResponseWriter, req *http.Request, ss *ezapi.Session) error {
	if ss.CreatedAt == 0 {
		ss.CreatedAtNow()
	}
	value, err := ss.EncodeSessionState(s.CookieCipher, true)
	if err != nil {
		return err
	}
	return s.setSessionCookie(rw, req, value)
}

// Load reads ezapi.Session information from Cookies within the
// HTTP request object
func (s *CookieStore) Load(req *http.Request) (*ezapi.Session, error) {
	c, err := loadCookie(req, s.Cookie.Name)
	if err != nil {
		// always http.ErrNoCookie
		return nil, err
	}
	val, err := encryption.Validate(c, s.Cookie.Secret.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: Cookie failed in validation: %s", ErrCorruptedSession, err.Error())
	}

	session, err := ezapi.DecodeSessionState(val, s.CookieCipher, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCorruptedSession, err.Error())
	}
	if s.needsRefresh(session) || session.IsExpired() {
		return session, ErrNeedsRefresh
	}
	return session, nil
}

// Clear clears any saved session information by writing a cookie to
// clear the session
func (s *CookieStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	for _, c := range req.Cookies() {
		if matchCookieName(c.Name, s.Cookie.Name) {
			clearCookie := s.makeCookie(req, "") //nolint:gosec // Secure/HttpOnly/SameSite attributes are set by makeCookie from s.Cookie config
			clearCookie.Name = c.Name
			clearCookie.MaxAge = -1
			if !clearCookie.Expires.IsZero() {
				clearCookie.Expires = time.Now()
			}
			http.SetCookie(rw, clearCookie)
		}
	}

	return nil
}

// VerifyConnection always return no-error, as there's no connection
// in this store
func (s *CookieStore) VerifyConnection(_ context.Context) error {
	return nil
}

// setSessionCookie adds the user's session cookie to the response
func (s *CookieStore) setSessionCookie(rw http.ResponseWriter, req *http.Request, val []byte) error {
	cookies, err := s.makeSessionCookie(req, val)
	if err != nil {
		return err
	}
	for _, c := range cookies {
		http.SetCookie(rw, c)
	}
	return nil
}

// makeSessionCookie creates an http.Cookie containing the authenticated user's
// authentication details
func (s *CookieStore) makeSessionCookie(req *http.Request, value []byte) ([]*http.Cookie, error) {
	strValue := string(value)
	if strValue != "" {
		var err error
		strValue, err = encryption.SignedValue(s.Cookie.Secret.Bytes(), s.Cookie.Name, value)
		if err != nil {
			return nil, err
		}
	}
	c := s.makeCookie(req, strValue)
	if len(c.String()) > maxCookieLength {
		ctx := req.Context()
		logger := ezlog.FromContext(ctx)
		logger.Warn("Session cookie exceeds the 4kb cookie limit, will attempt to split into multiple cookies. Suggested to use server side session storage (eg. Redis) instead.")
		return splitCookie(c), nil
	}
	return []*http.Cookie{c}, nil
}

// GetCookieDomain returns the best-matching cookie domain for req from cookieDomains.
func GetCookieDomain(req *http.Request, cookieDomains []string) string {
	host := ezutil.GetRequestHost(req)
	// match request host with the domains
	for _, domain := range cookieDomains {
		if strings.HasSuffix(host, domain) {
			return domain
		}
	}
	if len(cookieDomains) > 0 {
		logger := ezlog.FromContext(req.Context())
		logger.Warn("request host did not match any configured cookie domain, cookie will be host-only",
			ezlog.Str("host", ezutil.GetRequestHost(req)),
			ezlog.Str("domains", strings.Join(cookieDomains, ",")),
		)
	}
	return ""
}

// ParseSameSite converts the SameSite string from config to an http.SameSite constant.
func ParseSameSite(v string) http.SameSite {
	switch strings.ToLower(v) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

// MakeCookieFromOptions constructs an http.Cookie from the given value and CookieStoreOptions.
func MakeCookieFromOptions(req *http.Request, value string, opts *config.CookieStoreOptions) *http.Cookie {
	domain := GetCookieDomain(req, opts.Domains)

	c := &http.Cookie{ //nolint:gosec // Secure/HttpOnly/SameSite attributes are explicitly set from opts below
		Name:     opts.Name,
		Value:    value,
		Path:     opts.Path,
		Domain:   domain,
		HttpOnly: *opts.HTTPOnly,
		Secure:   opts.Secure,
		SameSite: ParseSameSite(opts.SameSite),
	}

	if opts.MaxAge > time.Duration(0) {
		c.MaxAge = int(opts.MaxAge.Seconds())
	} else if opts.MaxAge < time.Duration(0) {
		c.MaxAge = -1
	}

	if opts.Expire != 0 {
		c.Expires = time.Now().Add(opts.Expire)
	}

	warnInvalidDomain(c, req)

	return c
}

func warnInvalidDomain(c *http.Cookie, req *http.Request) {
	ctx := req.Context()
	logger := ezlog.FromContext(ctx)
	if c.Domain == "" {
		logger.Warn("request host is empty, cookie domain will not be set")
		return
	}

	host := ezutil.GetRequestHost(req)
	if u, err := url.ParseRequestURI(host); err == nil {
		host = u.Host
	}
	if !strings.HasSuffix(host, c.Domain) {
		logger.Warn("request host does not match configured cookie domain", ezlog.Str("host", host), ezlog.Str("domain", c.Domain))
	}
}

func (s *CookieStore) makeCookie(req *http.Request, value string) *http.Cookie {
	return MakeCookieFromOptions(
		req,
		value,
		s.Cookie,
	)
}

// NewCookieStore initialises a new instance of the CookieStore from
// the configuration given
func NewCookieStore(cookieOpts *config.CookieStoreOptions, refreshPeriod time.Duration) (SessionStore, error) {
	cipher, err := encryption.NewGCMCipher(cookieOpts.Secret.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error initialising cipher: %v", err)
	}

	if ParseSameSite(cookieOpts.SameSite) == http.SameSiteNoneMode && !cookieOpts.Secure {
		return nil, fmt.Errorf("cookie with SameSite=None must be Secure, or use a different SameSite value")
	}

	return &CookieStore{
		store: store{
			RefreshPeriod: refreshPeriod,
			Cookie:        cookieOpts,
		},
		CookieCipher: cipher,
		Cookie:       cookieOpts,
	}, nil
}

// splitCookie reads the full cookie generated to store the session and splits
// it into a slice of cookies which fit within the 4kb cookie limit indexing
// the cookies from 0
func splitCookie(c *http.Cookie) []*http.Cookie {
	if len(c.String()) < maxCookieLength {
		return []*http.Cookie{c}
	}

	cookies := []*http.Cookie{}
	valueBytes := []byte(c.Value)
	count := 0
	for len(valueBytes) > 0 {
		newCookie := copyCookie(c) //nolint:gosec // Secure/HttpOnly/SameSite attributes are preserved from the source cookie by copyCookie
		newCookie.Name = splitCookieName(c.Name, count)
		count++

		newCookie.Value = string(valueBytes)
		cookieLength := len(newCookie.String())

		if cookieLength > maxCookieLength {
			overflow := cookieLength - maxCookieLength
			valueSize := len(valueBytes) - overflow

			newCookie.Value = string(valueBytes[:valueSize])
			valueBytes = valueBytes[valueSize:]
		} else {
			valueBytes = []byte{}
		}
		cookies = append(cookies, newCookie)
	}
	return cookies
}

// matchCookieName reports whether name equals base or base_<digits> (one or more digits).
// This mirrors the split-cookie naming produced by splitCookieName.
func matchCookieName(name, base string) bool {
	if name == base {
		return true
	}
	prefix := base + "_"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := name[len(prefix):]
	if len(suffix) == 0 {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return false
		}
	}
	return true
}

func splitCookieName(name string, count int) string {
	splitName := fmt.Sprintf("%s_%d", name, count)
	overflow := len(splitName) - 256
	if overflow > 0 {
		splitName = fmt.Sprintf("%s_%d", name[:len(name)-overflow], count)
	}
	return splitName
}

// loadCookie retreieves the sessions state cookie from the http request.
// If a single cookie is present this will be returned, otherwise it attempts
// to reconstruct a cookie split up by splitCookie
func loadCookie(req *http.Request, cookieName string) (*http.Cookie, error) {
	c, err := req.Cookie(cookieName)
	if err == nil {
		return c, nil
	}
	cookies := []*http.Cookie{}
	err = nil
	count := 0
	for err == nil {
		var c *http.Cookie
		c, err = req.Cookie(splitCookieName(cookieName, count))
		if err == nil {
			cookies = append(cookies, c)
			count++
		}
	}
	if len(cookies) == 0 {
		return nil, http.ErrNoCookie
	}
	return joinCookies(cookies, cookieName)
}

// joinCookies takes a slice of cookies from the request and reconstructs the
// full session cookie
func joinCookies(cookies []*http.Cookie, cookieName string) (*http.Cookie, error) {
	if len(cookies) == 0 {
		return nil, fmt.Errorf("list of cookies must be > 0")
	}
	if len(cookies) == 1 {
		return cookies[0], nil
	}
	c := copyCookie(cookies[0]) //nolint:gosec // cookie attributes are copied from the original cookie which is already validated
	for i := 1; i < len(cookies); i++ {
		c.Value += cookies[i].Value
	}
	c.Name = cookieName
	return c, nil
}

func copyCookie(c *http.Cookie) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure/HttpOnly/SameSite are preserved from the source cookie
		Name:       c.Name,
		Value:      c.Value,
		Path:       c.Path,
		Domain:     c.Domain,
		Expires:    c.Expires,
		RawExpires: c.RawExpires,
		MaxAge:     c.MaxAge,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		Raw:        c.Raw,
		Unparsed:   c.Unparsed,
		SameSite:   c.SameSite,
	}
}
