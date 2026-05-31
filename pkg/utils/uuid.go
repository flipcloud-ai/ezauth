package utils

import (
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/xid"
)

// NewRandomUUID generates and returns a random UUID v4 string.
func NewRandomUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	return id.String(), nil
}

// NewRandomXID generates and returns a random XID string.
func NewRandomXID() string {
	return xid.New().String()
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
