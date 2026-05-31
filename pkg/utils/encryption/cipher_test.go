package encryption_test

import (
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GCM Cipher", func() {
	var (
		plaintext = []byte("hello world, this is a test message")
		key       = []byte("0123456789abcdef")
	)

	It("should encrypt and decrypt successfully", func() {
		c, err := encryption.NewGCMCipher(key)
		Expect(err).ToNot(HaveOccurred())

		ciphertext, err := c.Encrypt(plaintext)
		Expect(err).ToNot(HaveOccurred())
		Expect(ciphertext).ToNot(BeEmpty())
		Expect(ciphertext).ToNot(Equal(plaintext))

		decrypted, err := c.Decrypt(ciphertext)
		Expect(err).ToNot(HaveOccurred())
		Expect(decrypted).To(Equal(plaintext))
	})

	It("should detect tampered ciphertext", func() {
		c, err := encryption.NewGCMCipher(key)
		Expect(err).ToNot(HaveOccurred())

		ciphertext, err := c.Encrypt(plaintext)
		Expect(err).ToNot(HaveOccurred())

		// Tamper with the ciphertext
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		if len(tampered) > 0 {
			tampered[len(tampered)-1] ^= 0xff
		}

		_, err = c.Decrypt(tampered)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("authentication"))
	})

	It("should return an error when creating cipher with an invalid key length", func() {
		_, err := encryption.NewGCMCipher([]byte("short"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid key size"))
	})

	It("should encrypt and decrypt empty plaintext", func() {
		c, err := encryption.NewGCMCipher(key)
		Expect(err).ToNot(HaveOccurred())

		ciphertext, err := c.Encrypt([]byte{})
		Expect(err).ToNot(HaveOccurred())

		decrypted, err := c.Decrypt(ciphertext)
		Expect(err).ToNot(HaveOccurred())
		Expect(decrypted).To(BeEmpty())
	})
})

var _ = Describe("GCM Cipher short ciphertext", func() {
	It("should return error when GCM ciphertext is too short to contain nonce", func() {
		c, err := encryption.NewGCMCipher([]byte("0123456789abcdef"))
		Expect(err).ToNot(HaveOccurred())
		// A ciphertext exactly at nonce size (12 bytes) has no payload after the nonce,
		// so GCM Open fails with an authentication error.
		_, err = c.Decrypt(make([]byte, 12))
		Expect(err).To(HaveOccurred())
	})
})
