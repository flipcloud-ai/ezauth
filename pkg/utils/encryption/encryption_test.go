package encryption_test

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Nonce", func() {
	It("should generate random bytes of the requested length", func() {
		nonce, err := encryption.Nonce(16)
		Expect(err).ToNot(HaveOccurred())
		Expect(nonce).To(HaveLen(16))
	})

	It("should generate different values on subsequent calls", func() {
		n1, err := encryption.Nonce(32)
		Expect(err).ToNot(HaveOccurred())

		n2, err := encryption.Nonce(32)
		Expect(err).ToNot(HaveOccurred())

		Expect(n1).ToNot(Equal(n2))
	})

	It("should handle zero length", func() {
		nonce, err := encryption.Nonce(0)
		Expect(err).ToNot(HaveOccurred())
		Expect(nonce).To(BeEmpty())
	})
})

var _ = Describe("HashNonce / CheckNonce", func() {
	var nonce []byte

	BeforeEach(func() {
		var err error
		nonce, err = encryption.Nonce(16)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should hash a nonce and verify it matches", func() {
		hashed := encryption.HashNonce(nonce)
		Expect(hashed).ToNot(BeEmpty())

		match := encryption.CheckNonce(nonce, hashed)
		Expect(match).To(BeTrue())
	})

	It("should reject a wrong nonce", func() {
		hashed := encryption.HashNonce(nonce)

		otherNonce, err := encryption.Nonce(16)
		Expect(err).ToNot(HaveOccurred())

		match := encryption.CheckNonce(otherNonce, hashed)
		Expect(match).To(BeFalse())
	})

	It("should produce consistent hashes for the same nonce", func() {
		hashed1 := encryption.HashNonce(nonce)
		hashed2 := encryption.HashNonce(nonce)
		Expect(hashed1).To(Equal(hashed2))
	})
})

var _ = Describe("GenerateCodeVerifier / GenerateCodeChallenge", func() {
	It("should generate a code verifier of the requested length", func() {
		verifier, err := encryption.GenerateCodeVerifier(32)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(verifier)).To(BeNumerically(">", 0))
	})

	It("should round-trip with 'plain' challenge method", func() {
		verifier, err := encryption.GenerateCodeVerifier(32)
		Expect(err).ToNot(HaveOccurred())

		challenge, err := encryption.GenerateCodeChallenge("plain", verifier)
		Expect(err).ToNot(HaveOccurred())
		Expect(challenge).To(Equal(verifier))
	})

	It("should round-trip with 'S256' challenge method", func() {
		verifier, err := encryption.GenerateCodeVerifier(32)
		Expect(err).ToNot(HaveOccurred())

		challenge, err := encryption.GenerateCodeChallenge("S256", verifier)
		Expect(err).ToNot(HaveOccurred())
		Expect(challenge).ToNot(BeEmpty())
		Expect(challenge).ToNot(Equal(verifier))
	})

	It("should return an error for an unknown challenge method", func() {
		_, err := encryption.GenerateCodeChallenge("unknown", "verifier")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unknown challenge method"))
	})
})

var _ = Describe("SignedValue / Validate", func() {
	var (
		seed = []byte("test-seed")
		key  = "test-key"
		val  = []byte("test-value")
	)

	It("should create a signed cookie value and validate it", func() {
		signed, err := encryption.SignedValue(seed, key, val)
		Expect(err).ToNot(HaveOccurred())
		Expect(signed).To(ContainSubstring("|"))

		cookie := &http.Cookie{
			Name:  key,
			Value: signed,
		}

		result, err := encryption.Validate(cookie, seed)
		Expect(err).ToNot(HaveOccurred())
		Expect(result).To(Equal(val))
	})

	It("should return an error for an expired cookie", func() {
		signed, err := encryption.SignedValue(seed, key, val)
		Expect(err).ToNot(HaveOccurred())

		cookie := &http.Cookie{
			Name:    key,
			Value:   signed,
			Expires: time.Now().Add(-1 * time.Hour),
		}

		_, err = encryption.Validate(cookie, seed)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cookie is expired"))
	})

	It("should return an error for a truncated cookie value (no pipe separator)", func() {
		cookie := &http.Cookie{
			Name:  key,
			Value: "no-pipe-separator",
		}

		_, err := encryption.Validate(cookie, seed)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid cookie value"))
	})

	It("should return an error for a wrong signature", func() {
		signed, err := encryption.SignedValue(seed, key, val)
		Expect(err).ToNot(HaveOccurred())

		cookie := &http.Cookie{
			Name:  key,
			Value: signed,
		}

		_, err = encryption.Validate(cookie, []byte("different-seed"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("signatures do not match"))
	})
})

var _ = Describe("SecretBytes", func() {
	It("should return the raw string bytes when given a regular string", func() {
		result := encryption.SecretBytes("myplainsecret")
		Expect(result).To(Equal([]byte("myplainsecret")))
	})

	It("should handle empty string", func() {
		result := encryption.SecretBytes("")
		Expect(result).To(BeEmpty())
	})
})

var _ = Describe("Validate checkHmac invalid base64 in stored sig", func() {
	It("should return signature mismatch when stored sig is not valid base64", func() {
		seed := []byte("test-seed")
		key := "test-key"
		val := []byte("test-value")

		signed, err := encryption.SignedValue(seed, key, val)
		Expect(err).ToNot(HaveOccurred())

		// Replace the sig part with an invalid base64 string so checkHmac returns false
		parts := strings.SplitN(signed, "|", 2)
		Expect(parts).To(HaveLen(2))
		tampered := fmt.Sprintf("%s|!!!invalid-base64!!!", parts[0])

		cookie := &http.Cookie{Name: key, Value: tampered}
		_, err = encryption.Validate(cookie, seed)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("GenerateCodeVerifier zero length", func() {
	It("should return empty string for length 0", func() {
		v, err := encryption.GenerateCodeVerifier(0)
		Expect(err).ToNot(HaveOccurred())
		Expect(v).To(BeEmpty())
	})
})
