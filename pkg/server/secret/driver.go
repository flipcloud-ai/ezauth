package secret

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
)

// DefaultSecretsDir is the default directory for auto-generated secret files.
//
//nolint:gosec // path string, not a credential
const DefaultSecretsDir = "/opt/ezauth/secrets"

const alphanumChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Driver resolves secret fields in a config.Options, loading bytes from files
// or auto-generating them as needed.
type Driver struct {
	logger     ezlog.Logger
	secretsDir string
}

// New returns a Driver using the given logger and secrets directory.
func New(logger ezlog.Logger, secretsDir string) *Driver {
	return &Driver{logger: logger, secretsDir: secretsDir}
}

type secretField struct {
	ptr        *config.SecretRef
	fieldName  string
	configPath string
	skipIfZero bool
}

// Resolve resolves all secret fields in opts.
func (d *Driver) Resolve(opts *config.Options) error {
	fields := []secretField{
		{
			ptr:        &opts.Auth.Session.Cookie.Secret,
			fieldName:  "cookie secret",
			configPath: "auth.session.cookie.cookie_secret",
		},
		{
			ptr:        &opts.Auth.Session.CSRF.Secret,
			fieldName:  "csrf secret",
			configPath: "auth.session.csrf.cookie_secret",
		},
		{
			ptr:        &opts.Cache.Redis.EncryptSecret,
			fieldName:  "redis encrypt secret",
			skipIfZero: true,
		},
		{
			ptr:        &opts.Auth.JWT.SecretKey,
			fieldName:  "jwt secret key",
			configPath: "auth.jwt.secret_key",
		},
		{
			ptr:        &opts.Database.Password,
			fieldName:  "database password",
			skipIfZero: true,
		},
	}

	for _, f := range fields {
		if err := d.resolveField(f); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) resolveField(f secretField) error {
	sr := f.ptr

	// Already resolved (e.g. inline base64 decoded by the mapstructure hook).
	if sr.Bytes() != nil {
		return nil
	}

	switch sr.Type {
	case "":
		if sr.Path != "" {
			return fmt.Errorf("secret source with path %q has no type; did you mean type: file?", sr.Path)
		}
		if f.skipIfZero {
			return nil
		}
		return d.autoGen(sr, f.fieldName, f.configPath)

	case "file":
		if sr.Path == "" {
			return fmt.Errorf("secret source type %q requires a path", sr.Type)
		}
		raw, err := readFileSecret(sr.Path, sr.Key)
		if err != nil {
			return fmt.Errorf("load secret from file %q: %w", sr.Path, err)
		}
		sr.SetRaw(raw)
		d.logger.Info("secret loaded from file", ezlog.Str("path", sr.Path))
		return nil

	case "hashicorp":
		return fmt.Errorf("secret source %q is not yet implemented", sr.Type)

	default:
		return fmt.Errorf("unknown secret source type %q", sr.Type)
	}
}

func (d *Driver) autoGen(sr *config.SecretRef, fieldName, configPath string) error {
	defaultPath := filepath.Join(d.secretsDir, strings.ReplaceAll(fieldName, " ", "_"))

	// Reuse existing file.
	if _, err := os.Stat(defaultPath); err == nil {
		raw, err := readFileSecret(defaultPath, "")
		if err != nil {
			return fmt.Errorf("read existing secret file %q: %w", defaultPath, err)
		}
		if len(raw) < 32 {
			return fmt.Errorf("secret file %q is too short (%d bytes); expected at least 32", defaultPath, len(raw))
		}
		sr.SetRaw(raw)
		return nil
	}

	// Generate new 32-byte alphanumeric secret for AES-256.
	b, err := randAlphaNum(32)
	if err != nil {
		return fmt.Errorf("generate secret for %s: %w", fieldName, err)
	}

	// Persist to file.
	if err := os.MkdirAll(filepath.Dir(defaultPath), 0o700); err != nil {
		return fmt.Errorf(
			"could not persist auto-generated secret for %s: %w\n\trun 'openssl rand -hex 32' and set %s in your config",
			fieldName, err, configPath,
		)
	}
	if err := os.WriteFile(defaultPath, b, 0o600); err != nil {
		return fmt.Errorf(
			"could not persist auto-generated secret for %s: %w\n\trun 'openssl rand -hex 32' and set %s in your config",
			fieldName, err, configPath,
		)
	}

	sr.SetRaw(b)
	d.logger.Warn("no secret configured, generated new secret; for distributed deployments, distribute this file to all instances",
		ezlog.Str("field", fieldName),
		ezlog.Str("path", defaultPath),
	)
	return nil
}

// readFileSecret reads a secret from a file as plain text.
// If key is non-empty, the file is parsed as YAML/JSON and the string value at key is used.
func readFileSecret(path, key string) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("file source: path must be absolute")
	}

	//nolint:gosec // path is validated to be absolute and comes from config, not user input
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file source: read file: %w", err)
	}
	content := strings.TrimSpace(string(data))

	if key == "" {
		if len(content) == 0 {
			return nil, fmt.Errorf("file source: secret is empty")
		}
		return []byte(content), nil
	}

	// Key-based extraction: parse as YAML (superset of JSON).
	var m map[string]any
	if err := yaml.Unmarshal([]byte(content), &m); err != nil {
		return nil, fmt.Errorf("file source: parse yaml/json: %w", err)
	}

	val, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	strVal, ok := val.(string)
	if !ok {
		return nil, fmt.Errorf("value at key %q is not a string", key)
	}
	if len(strVal) == 0 {
		return nil, fmt.Errorf("file source: secret at key %q is empty", key)
	}
	return []byte(strVal), nil
}

func randAlphaNum(n int) ([]byte, error) {
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumChars))))
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}
		b[i] = alphanumChars[idx.Int64()]
	}
	return b, nil
}
