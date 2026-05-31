package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Cipher provides methods to encrypt and decrypt
type Cipher interface {
	Encrypt(value []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type gcmCipher struct {
	cipher.Block
}

// NewGCMCipher returns a new AES GCM Cipher
func NewGCMCipher(secret []byte) (Cipher, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	return &gcmCipher{Block: c}, nil
}

// Encrypt with AES GCM on raw bytes
func (c *gcmCipher) Encrypt(value []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(c.Block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// Using nonce as Seal's dst argument results in it being the first
	// chunk of bytes in the ciphertext. Decrypt retrieves the nonce/IV from this.
	ciphertext := gcm.Seal(nonce, nonce, value, nil)
	return ciphertext, nil
}

// Decrypt an AES GCM ciphertext
func (c *gcmCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(c.Block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm decrypt: %w", err)
	}
	return plaintext, nil
}
