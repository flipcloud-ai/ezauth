package utils

import (
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"

	regexp2 "github.com/dlclark/regexp2"

	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
)

// HTTP forwarding header constants.
const (
	// XForwardedProto is the header name for the original protocol.
	XForwardedProto = "X-Forwarded-Proto"
	XForwardedHost  = "X-Forwarded-Host"
	b61             = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	maxNameLength   = 128
)

var (
	muxTemplateRegex = regexp.MustCompile(`\{[^{}]+\}`)

	// Pre-compiled name regexps for the three digit values used in practice (16, 32, 64).
	// Pattern does not contain lookahead, so standard regexp suffices.
	validNameRe16 = regexp.MustCompile(`^[\p{L}\p{M}0-9._:-]{1,16}$`)
	validNameRe32 = regexp.MustCompile(`^[\p{L}\p{M}0-9._:-]{1,32}$`)
	validNameRe64 = regexp.MustCompile(`^[\p{L}\p{M}0-9._:-]{1,64}$`)

	// validPermNameRe32 is the only digit variant used for permission names.
	validPermNameRe32 = regexp.MustCompile(`^[\p{L}\p{M}0-9._*:-]{1,32}$`)

	phoneRe = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

	// usernameRe and passwordRe use lookahead; regexp2 is required.
	usernameRe = regexp2.MustCompile(`^(?=[a-zA-Z0-9._-]{4,20}$)(?!.*[_.-]{2})[^_.-].*[^_.-]$`, 0)
	passwordRe = regexp2.MustCompile(`^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])[a-zA-Z0-9!@#$&*]{8,}$`, 0)
)

// IsValidName reports whether name contains only allowed characters and is within length limits.
func IsValidName(name string, digit ...int) bool {
	d := 16
	if len(digit) > 0 {
		d = digit[0]
	}
	switch d {
	case 16:
		return validNameRe16.MatchString(name)
	case 32:
		return validNameRe32.MatchString(name)
	case 64:
		return validNameRe64.MatchString(name)
	default:
		if d < 1 || d > maxNameLength {
			return false
		}
		// No production caller reaches this branch (all use 16/32/64).
		// Dynamic compile is intentional: adding a new variant here is the signal
		// to promote it to a package-level pre-compiled variable instead.
		return regexp.MustCompile(fmt.Sprintf(`^[\p{L}\p{M}0-9._:-]{1,%d}$`, d)).MatchString(name)
	}
}

// IsValidPermissionName validates RBAC permission names, which may contain
// wildcard characters (*) in addition to the characters allowed by IsValidName.
func IsValidPermissionName(name string, digit ...int) bool {
	d := 16
	if len(digit) > 0 {
		d = digit[0]
	}
	if d == 32 {
		return validPermNameRe32.MatchString(name)
	}
	if d < 1 || d > maxNameLength {
		return false
	}
	// No production caller reaches this branch; see IsValidName for the same rationale.
	return regexp.MustCompile(fmt.Sprintf(`^[\p{L}\p{M}0-9._*:-]{1,%d}$`, d)).MatchString(name)
}

// IsValidUsername reports whether username is a valid username.
func IsValidUsername(username string) bool {
	if strings.Contains(username, " ") {
		return false
	}
	r, err := usernameRe.FindStringMatch(username)
	return (r != nil && err == nil) || IsValidPhoneNumber(username) || IsValidEmail(username)
}

// IsValidPassword reports whether password meets complexity requirements.
func IsValidPassword(password string) bool {
	// Minimum eight characters, at least one uppercase letter, one lowercase letter and one number
	r, err := passwordRe.FindStringMatch(password)
	return r != nil && err == nil
}

// IsValidPhoneNumber reports whether phone_number matches the E.164 international format.
func IsValidPhoneNumber(phone_number string) bool {
	return phoneRe.MatchString(phone_number)
}

// IsValidEmail reports whether email is a valid RFC 5322 address.
func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// IsValidPath reports whether path is a valid URL path.
func IsValidPath(path string) bool {
	routePath := muxTemplateRegex.ReplaceAllString(path, "x")
	u, err := url.ParseRequestURI(routePath)
	return err == nil && u.Path == routePath
}

// Getenv returns the value of env, or defaultEnv if it is unset or empty.
func Getenv(env string, defaultEnv string) string {
	e := os.Getenv(env)
	if e == "" {
		e = defaultEnv
	}
	return e
}

// GetRequestProto returns the request protocol, preferring X-Forwarded-Proto when trusted.
func GetRequestProto(req *http.Request) string {
	proto := req.Header.Get(XForwardedProto)
	if !IsProxied(req) || proto == "" {
		proto = req.URL.Scheme
	}
	return proto
}

// GetRequestHost returns the request host, preferring X-Forwarded-Host when trusted.
func GetRequestHost(req *http.Request) string {
	host := req.Header.Get(XForwardedHost)
	if !IsProxied(req) || host == "" {
		host = req.Host
	}
	return host
}

// IsProxied reports whether the request context trusts forwarded headers.
func IsProxied(req *http.Request) bool {
	reqInfo := ezapi.GetRequest(req)
	return reqInfo.TrustForwardedHeaders
}

// EncodeState encodes a statecode and state map as "statecode:url-query-string".
// url.Values percent-encodes values, so arbitrary strings (including URLs) are safe.
func EncodeState(statecode string, state url.Values) string {
	return statecode + ":" + state.Encode()
}

// DecodeState decodes a state string produced by EncodeState back into its
// statecode and key-value map.
func DecodeState(state string) (string, url.Values, error) {
	statecode, query, ok := strings.Cut(state, ":")
	if !ok {
		return "", nil, fmt.Errorf("invalid state format")
	}
	params, err := url.ParseQuery(query)
	if err != nil {
		return "", nil, fmt.Errorf("invalid state format: %w", err)
	}
	return statecode, params, nil
}
