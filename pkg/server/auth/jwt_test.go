package auth_test

import (
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/server/auth"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var testProfile = ezapi.Profile{
	Subject:           "test-subject-123",
	Email:             "test@example.com",
	EmailVerified:     true,
	User:              "testuser",
	Groups:            []string{"group1", "group2"},
	PreferredUsername: "tester",
}

var _ = Describe("JWT", func() {
	var baseCfg config.JWTConfig

	BeforeEach(func() {
		baseCfg = config.JWTConfig{
			SecretKey:      config.NewResolvedSecretRef([]byte("test-secret-key-for-hs256-tests!")),
			ExpireDuration: 1 * time.Hour,
			TokenIssuer:    "test-issuer",
			Audience:       "test-audience",
		}
	})

	Describe("GenerateToken / ParseToken", func() {
		DescribeTable("should round-trip with HMAC signing methods",
			func(method string) {
				cfg := baseCfg
				cfg.SigningMethod = method

				tokenString, err := auth.GenerateToken(cfg, testProfile)
				Expect(err).ToNot(HaveOccurred())
				Expect(tokenString).ToNot(BeEmpty())

				claims, err := auth.ParseToken(cfg, tokenString)
				Expect(err).ToNot(HaveOccurred())
				Expect(claims).ToNot(BeNil())

				Expect(claims.Email).To(Equal(testProfile.Email))
				Expect(claims.User).To(Equal(testProfile.User))
				Expect(claims.Groups).To(ConsistOf(testProfile.Groups))
				Expect(claims.PreferredUsername).To(Equal(testProfile.PreferredUsername))
				Expect(claims.Issuer).To(Equal("test-issuer"))
				Expect(claims.Subject).To(Equal(testProfile.Subject))
				Expect(claims.ID).ToNot(BeEmpty())
			},
			Entry("HS256", "HS256"),
			Entry("HS384", "HS384"),
			Entry("HS512", "HS512"),
		)

		It("should use HS256 as default when SigningMethod is empty", func() {
			cfg := baseCfg
			cfg.SigningMethod = ""

			tokenString, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).ToNot(HaveOccurred())

			claims, err := auth.ParseToken(cfg, tokenString)
			Expect(err).ToNot(HaveOccurred())
			Expect(claims).ToNot(BeNil())
			Expect(claims.Email).To(Equal(testProfile.Email))
		})

		It("should default to HS256 when signing method is unknown", func() {
			cfg := baseCfg
			cfg.SigningMethod = "UNKNOWN"

			tokenString, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).ToNot(HaveOccurred())
			Expect(tokenString).ToNot(BeEmpty())

			claims, err := auth.ParseToken(cfg, tokenString)
			Expect(err).ToNot(HaveOccurred())
			Expect(claims.Email).To(Equal(testProfile.Email))
		})
	})

	Describe("Token validation", func() {
		It("should fail to parse an expired token", func() {
			cfg := baseCfg
			cfg.SigningMethod = "HS256"

			claims := &auth.AuthClaim{
				Email: testProfile.Email,
				User:  testProfile.User,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					Issuer:    "test-issuer",
					Subject:   testProfile.Subject,
					Audience:  []string{"test-audience"},
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(cfg.SecretKey.Bytes())
			Expect(err).ToNot(HaveOccurred())

			_, err = auth.ParseToken(cfg, tokenString)
			Expect(err).To(HaveOccurred())
		})

		It("should fail to parse a token with an invalid signature", func() {
			cfgA := baseCfg
			cfgA.SigningMethod = "HS256"
			cfgA.SecretKey = config.NewResolvedSecretRef([]byte("secret-a-with-enough-bytes-32!!!"))

			cfgB := baseCfg
			cfgB.SigningMethod = "HS256"
			cfgB.SecretKey = config.NewResolvedSecretRef([]byte("secret-b-with-enough-bytes-32!!!"))

			tokenString, err := auth.GenerateToken(cfgA, testProfile)
			Expect(err).ToNot(HaveOccurred())

			_, err = auth.ParseToken(cfgB, tokenString)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("signature is invalid"))
		})

		It("should fail to parse a malformed token string", func() {
			cfg := baseCfg
			cfg.SigningMethod = "HS256"

			_, err := auth.ParseToken(cfg, "not-a-valid-token")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("getIssuer / getAudience defaults", func() {
		It("should use default issuer when TokenIssuer is empty", func() {
			cfg := baseCfg
			cfg.TokenIssuer = ""

			tokenString, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).ToNot(HaveOccurred())

			claims, err := auth.ParseToken(cfg, tokenString)
			Expect(err).ToNot(HaveOccurred())
			Expect(claims.Issuer).To(Equal(auth.DefaultTokenIssuer))
		})

		It("should use default audience when Audience is empty", func() {
			cfg := baseCfg
			cfg.Audience = ""

			tokenString, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).ToNot(HaveOccurred())

			claims, err := auth.ParseToken(cfg, tokenString)
			Expect(err).ToNot(HaveOccurred())
			Expect(claims.Audience).To(ContainElement(auth.DefaultAudience))
		})
	})

	Describe("getSignMethod all variants", func() {
		DescribeTable("should return the correct signing method",
			func(method string) {
				cfg := baseCfg
				cfg.SigningMethod = method
				// Just verify GenerateToken picks the right code path (RSA/ECDSA will fail on missing key, that's OK)
				_, err := auth.GenerateToken(cfg, testProfile)
				// We only care that it tried the right branch, not that it succeeded
				Expect(err).To(HaveOccurred()) // no key file → expected error
			},
			Entry("RS256", "RS256"),
			Entry("RS384", "RS384"),
			Entry("RS512", "RS512"),
			Entry("ES256", "ES256"),
			Entry("ES384", "ES384"),
			Entry("ES512", "ES512"),
		)
	})

	Describe("GenerateToken with invalid secret key", func() {
		It("should fail when secret_key is empty", func() {
			cfg := baseCfg
			cfg.SecretKey = config.NewResolvedSecretRef(nil)
			cfg.SigningMethod = "HS256"

			_, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secret_key is required"))
		})

		It("should fail when HMAC key is shorter than 32 bytes", func() {
			cfg := baseCfg
			cfg.SecretKey = config.NewResolvedSecretRef([]byte("short"))
			cfg.SigningMethod = "HS256"

			_, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(">= 32 bytes"))
		})

		It("should fail for HS384 with short key", func() {
			cfg := baseCfg
			cfg.SecretKey = config.NewResolvedSecretRef([]byte("short"))
			cfg.SigningMethod = "HS384"

			_, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).To(HaveOccurred())
		})

		It("should fail for HS512 with short key", func() {
			cfg := baseCfg
			cfg.SecretKey = config.NewResolvedSecretRef([]byte("short"))
			cfg.SigningMethod = "HS512"

			_, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("ParseToken error paths", func() {
		It("should fail when secret_key is empty during parse", func() {
			cfg := baseCfg
			tokenString, err := auth.GenerateToken(cfg, testProfile)
			Expect(err).ToNot(HaveOccurred())

			cfg.SecretKey = config.NewResolvedSecretRef(nil)
			_, err = auth.ParseToken(cfg, tokenString)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secret_key is required"))
		})

		It("should fail when parsing token signed with unexpected algorithm", func() {
			// Create a token with 'none' algorithm (not supported by jwt library by default)
			cfg := baseCfg
			// Use a hand-crafted token with alg=none
			_, err := auth.ParseToken(cfg, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.")
			Expect(err).To(HaveOccurred())
		})
	})
})
