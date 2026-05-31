package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// writePEM writes a PEM block to a temp file and returns the path.
func writePEM(t GinkgoTInterface, pemType string, der []byte) string {
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: pemType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

var _ = Describe("GeneratePwd", func() {
	It("should hash a valid password and return a salt", func() {
		hash, salt, err := GeneratePwd("ValidPass1")
		Expect(err).ToNot(HaveOccurred())
		Expect(hash).NotTo(BeEmpty())
		Expect(salt).NotTo(BeEmpty())
	})

	It("should return ErrInvalidPassword for a weak password", func() {
		_, _, err := GeneratePwd("weak")
		Expect(err).To(MatchError(ErrInvalidPassword))
	})

	It("should produce different salts on subsequent calls", func() {
		_, salt1, err1 := GeneratePwd("ValidPass1")
		_, salt2, err2 := GeneratePwd("ValidPass1")
		Expect(err1).ToNot(HaveOccurred())
		Expect(err2).ToNot(HaveOccurred())
		Expect(salt1).NotTo(Equal(salt2))
	})
})

var _ = Describe("CompareBytes", func() {
	It("should return true for equal slices", func() {
		Expect(CompareBytes([]byte("abc"), []byte("abc"))).To(BeTrue())
	})

	It("should return false for unequal slices", func() {
		Expect(CompareBytes([]byte("abc"), []byte("xyz"))).To(BeFalse())
	})

	It("should return false for different-length slices", func() {
		Expect(CompareBytes([]byte("ab"), []byte("abc"))).To(BeFalse())
	})
})

var _ = Describe("LoadRSAPrivateKeyFromFile", func() {
	var rsaKey *rsa.PrivateKey

	BeforeEach(func() {
		var err error
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should load a valid PKCS1 RSA private key", func() {
		der := x509.MarshalPKCS1PrivateKey(rsaKey)
		path := writePEM(GinkgoT(), "RSA PRIVATE KEY", der)
		loaded, err := LoadRSAPrivateKeyFromFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(loaded.N).To(Equal(rsaKey.N))
	})

	It("should return error for non-existent file", func() {
		_, err := LoadRSAPrivateKeyFromFile("/nonexistent/key.pem")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("read rsa private key"))
	})

	It("should return error for file with no PEM data", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "empty.pem")
		Expect(os.WriteFile(path, []byte("not pem"), 0600)).To(Succeed())
		_, err := LoadRSAPrivateKeyFromFile(path)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no PEM data"))
	})

	It("should return error for invalid PKCS1 key bytes", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "bad.pem")
		f, _ := os.Create(path)
		_ = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("garbage")})
		_ = f.Close()
		_, err := LoadRSAPrivateKeyFromFile(path)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("parse rsa private key"))
	})
})

var _ = Describe("LoadRSAPublicKeyFromFile", func() {
	var rsaKey *rsa.PrivateKey

	BeforeEach(func() {
		var err error
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should load a valid PKCS1 RSA public key", func() {
		der := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		path := writePEM(GinkgoT(), "RSA PUBLIC KEY", der)
		loaded, err := LoadRSAPublicKeyFromFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(loaded.N).To(Equal(rsaKey.N))
	})

	It("should load a valid PKIX RSA public key", func() {
		der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		path := writePEM(GinkgoT(), "PUBLIC KEY", der)
		loaded, err := LoadRSAPublicKeyFromFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(loaded.N).To(Equal(rsaKey.N))
	})

	It("should return error for non-existent file", func() {
		_, err := LoadRSAPublicKeyFromFile("/nonexistent/key.pem")
		Expect(err).To(HaveOccurred())
	})

	It("should return error for file with no PEM data", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "empty.pem")
		Expect(os.WriteFile(path, []byte("not pem"), 0600)).To(Succeed())
		_, err := LoadRSAPublicKeyFromFile(path)
		Expect(err).To(HaveOccurred())
	})

	It("should return error for PKIX public key with wrong type (ECDSA in RSA loader)", func() {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		path := writePEM(GinkgoT(), "PUBLIC KEY", der)
		_, err := LoadRSAPublicKeyFromFile(path)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not RSA type"))
	})
})

var _ = Describe("LoadECDSAPrivateKeyFromFile", func() {
	It("should load a valid ECDSA private key", func() {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(key)
		path := writePEM(GinkgoT(), "EC PRIVATE KEY", der)
		loaded, err := LoadECDSAPrivateKeyFromFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(loaded.X).To(Equal(key.X))
	})

	It("should return error for non-existent file", func() {
		_, err := LoadECDSAPrivateKeyFromFile("/nonexistent/key.pem")
		Expect(err).To(HaveOccurred())
	})

	It("should return error for no PEM data", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "empty.pem")
		Expect(os.WriteFile(path, []byte("not pem"), 0600)).To(Succeed())
		_, err := LoadECDSAPrivateKeyFromFile(path)
		Expect(err).To(HaveOccurred())
	})

	It("should return error for invalid EC key bytes", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "bad.pem")
		f, _ := os.Create(path)
		_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})
		_ = f.Close()
		_, err := LoadECDSAPrivateKeyFromFile(path)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("LoadECDSAPublicKeyFromFile", func() {
	It("should load a valid ECDSA public key", func() {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		path := writePEM(GinkgoT(), "PUBLIC KEY", der)
		loaded, err := LoadECDSAPublicKeyFromFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(loaded.X).To(Equal(key.X))
	})

	It("should return error for non-existent file", func() {
		_, err := LoadECDSAPublicKeyFromFile("/nonexistent/key.pem")
		Expect(err).To(HaveOccurred())
	})

	It("should return error for no PEM data", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "empty.pem")
		Expect(os.WriteFile(path, []byte("not pem"), 0600)).To(Succeed())
		_, err := LoadECDSAPublicKeyFromFile(path)
		Expect(err).To(HaveOccurred())
	})

	It("should return error for non-ECDSA PKIX key (RSA in ECDSA loader)", func() {
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		path := writePEM(GinkgoT(), "PUBLIC KEY", der)
		_, err := LoadECDSAPublicKeyFromFile(path)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not ECDSA type"))
	})
})

var _ = Describe("ParseJWT", func() {
	It("should extract payload from a valid JWT", func() {
		// header.payload.sig — base64url encoded
		jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"
		payload, err := ParseJWT(jwt)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(payload)).To(ContainSubstring("sub"))
	})

	It("should return error for malformed JWT with fewer than 2 parts", func() {
		_, err := ParseJWT("onlyone")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("malformed jwt"))
	})

	It("should return error for invalid base64 in payload", func() {
		_, err := ParseJWT("header.!!!invalid!!!.sig")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("malformed jwt payload"))
	})
})

var _ = Describe("RandomBytes", func() {
	It("should return n random bytes", func() {
		b, err := RandomBytes(32)
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(HaveLen(32))
	})

	It("should return different values on subsequent calls", func() {
		b1, _ := RandomBytes(16)
		b2, _ := RandomBytes(16)
		Expect(b1).NotTo(Equal(b2))
	})

	It("should return empty slice for n=0", func() {
		b, err := RandomBytes(0)
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(BeEmpty())
	})
})

var _ = Describe("GeneratePassword", func() {
	It("should produce a 16-character password", func() {
		pwd, err := GeneratePassword()
		Expect(err).ToNot(HaveOccurred())
		Expect(pwd).To(HaveLen(16))
	})

	It("should produce passwords that pass IsValidPassword", func() {
		for range 5 {
			pwd, err := GeneratePassword()
			Expect(err).ToNot(HaveOccurred())
			Expect(IsValidPassword(pwd)).To(BeTrue(), "password %q did not pass validation", pwd)
		}
	})
})
