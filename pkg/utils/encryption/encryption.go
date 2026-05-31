package encryption

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Nonce generates a random n-byte slice
func Nonce(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return b, nil
}

// HashNonce returns the BLAKE2b 256-bit hash of a nonce
// NOTE: Error checking (G104) is purposefully skipped:
// - `blake2b.New256` has no error path with a nil signing key
// - `hash.Hash` interface's `Write` has an error signature, but
//   `blake2b.digest.Write` does not use it.
/* #nosec G104 */
func HashNonce(nonce []byte) string {
	hasher, _ := blake2b.New256(nil)
	hasher.Write(nonce)
	sum := hasher.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

// CheckNonce tests if a nonce matches the hashed version of it
func CheckNonce(nonce []byte, hashed string) bool {
	return hmac.Equal([]byte(HashNonce(nonce)), []byte(hashed))
}

// GenerateCodeVerifier generates a random PKCE code verifier of length n.
func GenerateCodeVerifier(n int) (string, error) {
	data := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data), nil
}

// GenerateCodeChallenge derives a PKCE code challenge from the given verifier using the specified method.
func GenerateCodeChallenge(method, codeVerifier string) (string, error) {
	switch method {
	case "plain":
		return codeVerifier, nil
	case "S256":
		shaSum := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(shaSum[:]), nil
	default:
		err := UnknownChallengeMethod
		err.msg = method
		return "", err
	}
}

// Validate verifies a signed cookie's signature and expiry, returning the decoded value.
func Validate(cookie *http.Cookie, seed []byte) (value []byte, err error) {
	if !cookie.Expires.IsZero() && time.Now().After(cookie.Expires) {
		return nil, CookieExpired
	}
	// value, timestamp, sig
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 2 {
		return nil, InvalidCookieValue
	}
	if checkSignature(parts[1], string(seed), cookie.Name, parts[0]) {
		rawValue, err := base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("decode cookie value: %w", err)
		}
		return rawValue, nil
	}
	return nil, SignatureNotMatch
}

// SignedValue encodes value and appends an HMAC signature, returning a cookie-safe string.
func SignedValue(seed []byte, key string, value []byte) (string, error) {
	encodedValue := base64.URLEncoding.EncodeToString(value)
	sig, err := signature(sha256.New, string(seed), key, encodedValue)
	if err != nil {
		return "", err
	}
	cookieVal := fmt.Sprintf("%s|%s", encodedValue, sig)
	return cookieVal, nil
}

func signature(signer func() hash.Hash, args ...string) (string, error) {
	h := hmac.New(signer, []byte(args[0]))
	for _, arg := range args[1:] {
		_, err := h.Write([]byte(arg))
		if err != nil {
			return "", fmt.Errorf("write hmac: %w", err)
		}
	}
	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}

// SecretBytes returns the secret as a byte slice.
func SecretBytes(secret string) []byte {
	return []byte(secret)
}

func checkSignature(sig string, args ...string) bool {
	vsig, err := signature(sha256.New, args...)
	if err != nil {
		return false
	}
	return checkHmac(sig, vsig)
}

func checkHmac(input, expected string) bool {
	var err error
	inputMAC, err := base64.URLEncoding.DecodeString(input)
	if err == nil {
		expectedMAC, err := base64.URLEncoding.DecodeString(expected)
		if err == nil {
			return hmac.Equal(inputMAC, expectedMAC)
		}
	}
	return false
}
