package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidPassword is returned when a password fails validation.
var ErrInvalidPassword = fmt.Errorf("invalid password")

// GeneratePwd generates a bcrypt hash and random salt for the given password.
func GeneratePwd(pwd string) ([]byte, string, error) {
	if !IsValidPassword(pwd) {
		return nil, "", ErrInvalidPassword
	}
	// Generate a random salt
	saltBytes := make([]byte, 16)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return nil, "", fmt.Errorf("generate salt: %w", err)
	}
	salt := base64.StdEncoding.EncodeToString(saltBytes)

	// Combine salt and password, then hash
	combined := salt + pwd
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(combined), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("hash password: %w", err)
	}
	return hashedPassword, salt, nil
}

// CompareBytes performs a constant-time comparison of two byte slices.
func CompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// LoadRSAPrivateKeyFromFile reads and parses a PEM-encoded RSA private key from path.
func LoadRSAPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.ReadFile(path) //nolint:gosec // path is provided by caller from config
	if err != nil {
		return nil, fmt.Errorf("read rsa private key %q: %w", path, err)
	}
	privateKeyBlock, _ := pem.Decode(privateKeyFile)
	if privateKeyBlock == nil {
		return nil, fmt.Errorf("no PEM data found in %s", path)
	}
	key, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rsa private key: %w", err)
	}
	return key, nil
}

// LoadRSAPublicKeyFromFile reads and parses a PEM-encoded RSA public key from path.
func LoadRSAPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	publicKeyFile, err := os.ReadFile(path) //nolint:gosec // path is provided by caller from config
	if err != nil {
		return nil, fmt.Errorf("read rsa public key %q: %w", path, err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyFile)
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("no PEM data found in %s", path)
	}
	publicKey, pkcs1Err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if pkcs1Err == nil {
		return publicKey, nil
	}
	pub, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA type")
	}
	return rsaKey, nil
}

// LoadECDSAPrivateKeyFromFile reads and parses a PEM-encoded ECDSA private key from path.
func LoadECDSAPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	privateKeyFile, err := os.ReadFile(path) //nolint:gosec // path is provided by caller from config
	if err != nil {
		return nil, fmt.Errorf("read ecdsa private key %q: %w", path, err)
	}
	privateKeyBlock, _ := pem.Decode(privateKeyFile)
	if privateKeyBlock == nil {
		return nil, fmt.Errorf("no PEM data found in %s", path)
	}
	key, err := x509.ParseECPrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ecdsa private key: %w", err)
	}
	return key, nil
}

// LoadECDSAPublicKeyFromFile reads and parses a PEM-encoded ECDSA public key from path.
func LoadECDSAPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	publicKeyFile, err := os.ReadFile(path) //nolint:gosec // path is provided by caller from config
	if err != nil {
		return nil, fmt.Errorf("read ecdsa public key %q: %w", path, err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyFile)
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("no PEM data found in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ecdsa public key: %w", err)
	}
	ecdsaKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA type")
	}
	return ecdsaKey, nil
}

// ParseJWT extracts and base64-decodes the payload segment of a JWT string.
// It does not verify the signature; use ParseToken from pkg/server/auth for validated parsing.
func ParseJWT(idToken string) ([]byte, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// err == nil only if len(b) == n
	if err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}

	return b, nil
}

const passwordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$&*"

const (
	passwordUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	passwordLower   = "abcdefghijklmnopqrstuvwxyz"
	passwordDigits  = "0123456789"
	passwordSpecial = "!@#$&*"
)

// GeneratePassword produces a 16-character random password containing at least
// one lowercase letter, one uppercase letter, one digit, and one special
// character. Each character is drawn uniformly from passwordAlphabet using
// rejection sampling to avoid modulo bias. The complexity check uses the same
// rejection-sampling loop so no character positions are forced to a fixed class.
func GeneratePassword() (string, error) {
	const n = 16
	alphabetLen := big.NewInt(int64(len(passwordAlphabet)))
	for {
		buf := make([]byte, n)
		for i := range buf {
			idx, err := rand.Int(rand.Reader, alphabetLen)
			if err != nil {
				return "", fmt.Errorf("generate password: %w", err)
			}
			buf[i] = passwordAlphabet[idx.Int64()]
		}
		p := string(buf)
		if strings.ContainsAny(p, passwordUpper) &&
			strings.ContainsAny(p, passwordLower) &&
			strings.ContainsAny(p, passwordDigits) &&
			strings.ContainsAny(p, passwordSpecial) {
			return p, nil
		}
	}
}
