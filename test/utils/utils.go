package utils

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/spf13/cobra"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
)

var b61 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

//nolint:gosec // test constants contain mock endpoint URLs, not real credentials
const (
	authorizationEndpoint = "https://www.randomcloud123.com/authorize"
	tokenEndpoint         = "https://www.randomcloud123.com/token"
	introspectionEndpoint = "https://www.randomcloud123.com/introspect"
	revocationEndpoint    = "https://www.randomcloud123.com/revoke"
	userInfoEndpoint      = "https://www.randomcloud123.com/userinfo"
	jwksUri               = "https://www.randomcloud123.com/keys"
)

type oidcInfo struct {
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	IntrospectionEndpoint       string   `json:"introspection_endpoint"`
	RevocationEndpoint          string   `json:"revocation_endpoint"`
	UserinfoEndpoint            string   `json:"userinfo_endpoint"`
	GrantTypesSupported         []string `json:"grant_types_supported"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
	TokenAuthMethods            []string `json:"token_endpoint_auth_methods_supported"`
	JwksUri                     string   `json:"jwks_uri"`
	ResponseModesSupported      []string `json:"response_modes_supported"`
	SubjectTypesSupported       []string `json:"subject_types_supported"`
	IDTokenSigningAlgSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypeSupported       []string `json:"response_types_supported"`
	ScopesSupported             []string `json:"scopes_supported"`
	Issuer                      string   `json:"issuer"`
	RequestURIParameter         bool     `json:"request_uri_parameter_supported"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	LogoutEndpoint              string   `json:"end_session_endpoint"`
	ClaimsSupported             []string `json:"claims_supported"`
}

// NewOIDCServer starts a test OIDC discovery server with optional request middlewares.
func NewOIDCServer(middlewares ...func(rw http.ResponseWriter, r *http.Request)) (*url.URL, *httptest.Server) {
	body, _ := json.Marshal(oidcInfo{
		AuthorizationEndpoint: authorizationEndpoint,
		TokenEndpoint:         tokenEndpoint,
		IntrospectionEndpoint: introspectionEndpoint,
		RevocationEndpoint:    revocationEndpoint,
		UserinfoEndpoint:      userInfoEndpoint,
		CodeChallengeMethods:  []string{"S256", "plain"},
		JwksUri:               jwksUri,
	})
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		for _, m := range middlewares {
			m(rw, r)
		}
		rw.Header().Add("content-type", "application/json")
		_, _ = rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

// SetupLogsCapture returns a logger and observer that captures log entries for assertions.
func SetupLogsCapture() (ezlog.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.InfoLevel)
	return ezlog.New(zap.New(core)), logs
}

// SetupTestLogger creates a development-mode zap logger for use in tests.
func SetupTestLogger() (ezlog.Logger, error) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("create test logger: %w", err)
	}
	return ezlog.New(zl), nil
}

// FuncsEqual reports whether f1 and f2 point to the same function.
func FuncsEqual(f1, f2 interface{}) bool {
	val1 := reflect.ValueOf(f1)
	val2 := reflect.ValueOf(f2)
	return val1.Pointer() == val2.Pointer()
}

// TestPath returns the absolute path to the test fixtures directory.
func TestPath() string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	return filepath.Join(dir, "../")
}

// Config verifies the test config file at path exists and returns its full path.
func Config(path string) (string, error) {
	dir := TestPath()
	fullPath := filepath.Join(dir, path)
	_, err := os.ReadFile(fullPath) //nolint:gosec // path is constructed from test fixtures directory
	if err != nil {
		return "", fmt.Errorf("read config file: %w", err)
	}
	return fullPath, nil
}

// LoadFromConfig loads an Options struct from the named test config file.
// After loading, any zero-value SecretRef fields are populated with test
// secrets so callers can immediately use session stores, JWT, etc. without
// needing to call ResolveSecrets (which writes files to disk).
func LoadFromConfig(path string) config.Options {
	rootCmd := &cobra.Command{}
	rootCmd.Flags().StringP("config", "f", "/opt/ezauth/config.yaml", "Config file (default is /opt/ezauth/config.yaml)")
	config.AddServerFlags(rootCmd)
	currentCfgPath, _ := Config(fmt.Sprintf("config/%s", path))

	rootCmd.SetArgs(
		[]string{
			fmt.Sprintf("--config=%s", currentCfgPath),
		},
	)
	_ = rootCmd.Execute()
	cfg, _ := config.LoadConfiguration(rootCmd)
	// Populate zero SecretRef fields with test secrets so callers can use
	// them directly without file-based ResolveSecrets. Each value is exactly
	// 32 bytes of "test-secret-padding-for-32-bytes!" so it passes the HMAC
	// minimum-length check.
	if cfg.Auth.Session.Cookie.Secret.IsZero() {
		cfg.Auth.Session.Cookie.Secret = config.NewResolvedSecretRef([]byte("test-secret-for-tests-32-bytes!!"))
	}
	if cfg.Auth.Session.CSRF.Secret.IsZero() {
		cfg.Auth.Session.CSRF.Secret = config.NewResolvedSecretRef([]byte("test-csrf-tests-32-bytes-secure!"))
	}
	if cfg.Cache.Redis.EncryptSecret.IsZero() {
		cfg.Cache.Redis.EncryptSecret = config.NewResolvedSecretRef([]byte("test-redis-encrypt-32-bytes-key!"))
	}
	if cfg.Auth.JWT.SecretKey.IsZero() {
		cfg.Auth.JWT.SecretKey = config.NewResolvedSecretRef([]byte("test-jwt-secret-key-for-32bytes!!"))
	}
	return *cfg
}

// ConfigPrinter is a no-op config printer used in test setup.
func ConfigPrinter(opts config.Options) error {
	return nil
}

// WaitForServer polls requestURL until it returns HTTP 200, then returns true.
func WaitForServer(requestURL string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		req, err := http.NewRequestWithContext(context.Background(), "GET", requestURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			return true
		}
	}
	return false
}

// NewRandomString generates a cryptographically random alphanumeric string of the given length.
func NewRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	for i := range b {
		b[i] = b61[b[i]%61]
	}
	return string(b), nil
}

// MustNewRandomString wraps NewRandomString and panics on error. Use for package-level var initialisation in tests.
func MustNewRandomString(length int) string {
	s, err := NewRandomString(length)
	if err != nil {
		panic(err)
	}
	return s
}

// BoolPtr returns a pointer to b, for use in struct literals with *bool fields.
func BoolPtr(b bool) *bool { return &b }
