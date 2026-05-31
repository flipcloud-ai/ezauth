package apis

import (
	"crypto/rand"
	"io"
	"strings"
	"time"

	"github.com/agiledragon/gomonkey/v2"

	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("API Module Test Suite", func() {
	When("session test", func() {
		It("CreatedAtNow test", func(ctx SpecContext) {
			ss := &Session{}
			Expect(ss.Age()).To(Equal(time.Duration(0)))
			now := time.Now()
			var p = gomonkey.ApplyFunc(time.Now, func() time.Time {
				return now
			})
			defer p.Reset()
			ss.CreatedAtNow()
			Expect(ss.CreatedAt).To(Equal(now.Unix()))
			Expect(ss.Age()).To(Equal(time.Now().Truncate(time.Second).Sub(time.Unix(ss.CreatedAt, 0))))
		})
		It("Expires test", func(ctx SpecContext) {
			ss := &Session{}
			ttl := time.Duration(888) * time.Second
			ss.CreatedAtNow()
			ss.ExpiresIn(ttl)
			Expect(ss.IsExpired()).To(BeFalse())
			Expect(ss.ExpiresOn).To(Equal(ss.CreatedAt + int64(ttl.Seconds())))

			var p = gomonkey.ApplyFunc(time.Now, func() time.Time {
				return time.Unix(ss.CreatedAt, 0).Add(time.Duration(889) * time.Second)
			})
			defer p.Reset()
			Expect(ss.IsExpired()).To(BeTrue())
		})
		It("ExpiresIn sets CreatedAt when zero", func() {
			ss := &Session{}
			ss.ExpiresIn(1 * time.Hour)
			Expect(ss.CreatedAt).To(BeNumerically(">", 0))
			Expect(ss.ExpiresOn).To(Equal(ss.CreatedAt + 3600))
		})
		It("CheckNonce returns true for valid nonce", func() {
			nonce := []byte("test-nonce")
			hash := encryption.HashNonce(nonce)
			ss := &Session{Nonce: nonce}
			Expect(ss.CheckNonce(hash)).To(BeTrue())
		})
		It("CheckNonce returns false for invalid nonce", func() {
			ss := &Session{Nonce: []byte("test-nonce")}
			Expect(ss.CheckNonce("wrong-hash")).To(BeFalse())
		})
		DescribeTable("encode/decode round-trip", func(ss *Session) {
			for _, secretSize := range []int{16, 24, 32} {
				secret := make([]byte, secretSize)
				_, err := io.ReadFull(rand.Reader, secret)
				Expect(err).To(BeNil())
				gcm, err := encryption.NewGCMCipher([]byte(secret))
				Expect(err).To(BeNil())
				encoded, err := ss.EncodeSessionState(gcm, false)
				Expect(err).To(BeNil())
				encodedCompressed, err := ss.EncodeSessionState(gcm, true)
				Expect(err).To(BeNil())
				Expect(len(encodedCompressed)).To(BeNumerically("<=", len(encoded)))

				decoded, err := DecodeSessionState(encoded, gcm, false)
				Expect(err).To(BeNil())
				decodedCompressed, err := DecodeSessionState(encodedCompressed, gcm, true)
				Expect(err).To(BeNil())

				Expect(decoded.AccessToken).To(Equal(ss.AccessToken))
				Expect(decoded.IDToken).To(Equal(ss.IDToken))
				Expect(decoded.RefreshToken).To(Equal(ss.RefreshToken))
				Expect(decoded.CreatedAt).To(Equal(ss.CreatedAt))
				Expect(decoded.ExpiresOn).To(Equal(ss.ExpiresOn))
				Expect(decoded.Email).To(Equal(ss.Email))
				Expect(decoded.User).To(Equal(ss.User))
				Expect(decoded.PreferredUsername).To(Equal(ss.PreferredUsername))
				Expect(decoded.Groups).To(Equal(ss.Groups))

				Expect(decodedCompressed.AccessToken).To(Equal(ss.AccessToken))
				Expect(decodedCompressed.IDToken).To(Equal(ss.IDToken))
				Expect(decodedCompressed.RefreshToken).To(Equal(ss.RefreshToken))
				Expect(decodedCompressed.CreatedAt).To(Equal(ss.CreatedAt))
				Expect(decodedCompressed.ExpiresOn).To(Equal(ss.ExpiresOn))
				Expect(decodedCompressed.Email).To(Equal(ss.Email))
				Expect(decodedCompressed.User).To(Equal(ss.User))
				Expect(decodedCompressed.PreferredUsername).To(Equal(ss.PreferredUsername))
				Expect(decodedCompressed.Groups).To(Equal(ss.Groups))
			}
		},
			Entry("full session", &Session{
				CreatedAt: time.Now().Truncate(time.Second).Unix(),
				ExpiresOn: time.Now().Truncate(time.Second).Add(888 * time.Second).Unix(),
				Profile: Profile{
					Email:             "email@test.com",
					User:              "testuser",
					PreferredUsername: "preferred_name",
					Groups:            []string{"group1", "group2", "group3"},
				},
				AccessToken:  "AccessToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
				IDToken:      "IDToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
				RefreshToken: "RefreshToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
				Nonce:        []byte("nonce"),
			}),
			Entry("minimal session", &Session{
				CreatedAt:    time.Now().Truncate(time.Second).Unix(),
				AccessToken:  "AccessToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
				IDToken:      "IDToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
				RefreshToken: "RefreshToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
			}),
		)
	})

	When("codec version byte test", func() {
		newCipher := func() encryption.Cipher {
			secret := make([]byte, 32)
			_, err := io.ReadFull(rand.Reader, secret)
			Expect(err).To(BeNil())
			gcm, err := encryption.NewGCMCipher(secret)
			Expect(err).To(BeNil())
			return gcm
		}

		It("small payload encodes with codecVersionRaw (0x01)", func() {
			ss := &Session{
				AccessToken: "short",
			}
			gcm := newCipher()
			encoded, err := ss.EncodeSessionState(gcm, true)
			Expect(err).To(BeNil())
			raw, err := gcm.Decrypt(encoded)
			Expect(err).To(BeNil())
			Expect(raw[0]).To(Equal(codecVersionRaw))
		})

		It("large payload encodes with codecVersionLZ4Block (0x03)", func() {
			ss := &Session{
				AccessToken:  strings.Repeat("a", 300),
				RefreshToken: strings.Repeat("b", 300),
				IDToken:      strings.Repeat("c", 300),
			}
			gcm := newCipher()
			encoded, err := ss.EncodeSessionState(gcm, true)
			Expect(err).To(BeNil())
			raw, err := gcm.Decrypt(encoded)
			Expect(err).To(BeNil())
			Expect(raw[0]).To(Equal(codecVersionLZ4Block))
		})

		It("lz4DecompressBlock round-trip", func() {
			payload := []byte(strings.Repeat("hello world ", 50))
			compressed, err := lz4CompressBlock(payload)
			Expect(err).To(BeNil())
			Expect(compressed[0]).To(Equal(codecVersionLZ4Block))
			decompressed, err := lz4DecompressBlock(compressed)
			Expect(err).To(BeNil())
			Expect(decompressed).To(Equal(payload))
		})

		It("lz4DecompressBlock accepts 5-byte header with empty body (origSize=0)", func() {
			data := []byte{codecVersionLZ4Block, 0, 0, 0, 0}
			out, err := lz4DecompressBlock(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(BeEmpty())
		})

		It("unknown version byte returns error", func() {
			gcm := newCipher()
			encrypted, err := gcm.Encrypt([]byte{0x02, 0x00, 0x00})
			Expect(err).To(BeNil())
			_, err = DecodeSessionState(encrypted, gcm, true)
			Expect(err).To(MatchError(ContainSubstring("unknown codec version 0x02")))
		})
		It("returns error for corrupted lz4 data", func() {
			gcm := newCipher()
			badData := []byte{codecVersionLZ4Block, 0, 0, 0, 100, 0xFF, 0xFF, 0xFF}
			encrypted, _ := gcm.Encrypt(badData)
			_, err := DecodeSessionState(encrypted, gcm, true)
			Expect(err).To(HaveOccurred())
		})
		It("returns error for corrupt msgpack after raw version byte", func() {
			gcm := newCipher()
			badData := []byte{codecVersionRaw, 0xFF, 0xFE, 0xFD}
			encrypted, _ := gcm.Encrypt(badData)
			_, err := DecodeSessionState(encrypted, gcm, true)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unmarshalling"))
		})
		It("returns error for empty payload", func() {
			gcm := newCipher()
			encrypted, err := gcm.Encrypt([]byte{})
			Expect(err).To(BeNil())
			_, err = DecodeSessionState(encrypted, gcm, true)
			Expect(err).To(MatchError(ContainSubstring("empty payload")))
		})
		It("lz4DecompressBlock returns error for short data", func() {
			_, err := lz4DecompressBlock([]byte{0x03})
			Expect(err).To(MatchError(ContainSubstring("data too short")))
		})
		It("lz4DecompressBlock returns error for size mismatch", func() {
			data := []byte{codecVersionLZ4Block, 0, 0, 0, 10, 0x00}
			_, err := lz4DecompressBlock(data)
			Expect(err).To(HaveOccurred())
		})
		It("returns error for decryption failure", func() {
			gcm, err := encryption.NewGCMCipher(make([]byte, 32))
			Expect(err).To(BeNil())
			_, err = DecodeSessionState([]byte("not-encrypted"), gcm, true)
			Expect(err).To(HaveOccurred())
		})
	})
})
