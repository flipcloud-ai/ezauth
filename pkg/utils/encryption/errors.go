package encryption

import "fmt"

// EncryptionError is returned by encryption/decryption operations on failure.
//
//nolint:revive // established API name; renaming would be a breaking change
type EncryptionError struct {
	err string
	msg string
}

func (ee *EncryptionError) Error() string {
	if ee.msg != "" {
		return fmt.Sprintf("%s: %s", ee.err, ee.msg)
	}
	return ee.err
}

var (
	// UnknownChallengeMethod indicates that the challenge method is not supported.
	UnknownChallengeMethod = &EncryptionError{err: "unknown challenge method"}

	// CookieExpired indicates that cookie is already expired
	CookieExpired = &EncryptionError{err: "cookie is expired"}

	// InvalidCookieValue indicates that cookie value is not a valid value
	InvalidCookieValue = &EncryptionError{err: "invalid cookie value"}

	// SignatureNotMatch indicates that cookie signature is not match to the one issued
	SignatureNotMatch = &EncryptionError{err: "signatures do not match"}
)
