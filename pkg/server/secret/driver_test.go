package secret_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/server/secret"
)

func newDriver(secretsDir string) *secret.Driver {
	logger := ezlog.NewLogger(context.Background(), config.LogConfig{})
	return secret.New(logger, secretsDir)
}

var _ = Describe("Driver.Resolve", func() {
	var (
		tmpDir string
		driver *secret.Driver
	)

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
		driver = newDriver(tmpDir)
	})

	It("skips fields that already have resolved bytes", func() {
		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.NewResolvedSecretRef([]byte("pre-resolved-jwt-secret-32-bytes!"))
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Auth.JWT.SecretKey.Bytes()).To(Equal([]byte("pre-resolved-jwt-secret-32-bytes!")))
	})

	It("auto-generates secrets for zero fields and persists them", func() {
		opts := &config.Options{}
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Auth.JWT.SecretKey.Bytes()).To(HaveLen(32))
		Expect(opts.Auth.Session.Cookie.Secret.Bytes()).To(HaveLen(32))
		Expect(opts.Auth.Session.CSRF.Secret.Bytes()).To(HaveLen(32))
		// Verify files were written.
		Expect(filepath.Join(tmpDir, "jwt_secret_key")).To(BeAnExistingFile())
		Expect(filepath.Join(tmpDir, "cookie_secret")).To(BeAnExistingFile())
		Expect(filepath.Join(tmpDir, "csrf_secret")).To(BeAnExistingFile())
	})

	It("reuses existing secret file on second resolve", func() {
		opts := &config.Options{}
		Expect(driver.Resolve(opts)).To(Succeed())
		first := opts.Auth.JWT.SecretKey.Bytes()

		opts2 := &config.Options{}
		Expect(driver.Resolve(opts2)).To(Succeed())
		Expect(opts2.Auth.JWT.SecretKey.Bytes()).To(Equal(first))
	})

	It("skips redis encrypt secret when zero (skipIfZero)", func() {
		opts := &config.Options{}
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Cache.Redis.EncryptSecret.IsZero()).To(BeTrue())
	})

	It("skips database password when zero (skipIfZero)", func() {
		opts := &config.Options{}
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Database.Password.IsZero()).To(BeTrue())
	})

	It("reads file-type secrets as plain text", func() {
		filePath := filepath.Join(tmpDir, "my_secret")
		Expect(os.WriteFile(filePath, []byte("file-secret-data"), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath}
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Auth.JWT.SecretKey.Bytes()).To(Equal([]byte("file-secret-data")))
	})

	It("reads file-type secrets with YAML key extraction as plain text", func() {
		yamlContent := fmt.Sprintf("jwt: %s\n", "key-secret-data")
		filePath := filepath.Join(tmpDir, "secrets.yaml")
		Expect(os.WriteFile(filePath, []byte(yamlContent), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath, Key: "jwt"}
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Auth.JWT.SecretKey.Bytes()).To(Equal([]byte("key-secret-data")))
	})

	It("reads database password from file as plain text", func() {
		filePath := filepath.Join(tmpDir, "database-password")
		Expect(os.WriteFile(filePath, []byte("myS3cretP@ss"), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Database.Password = config.SecretRef{Type: "file", Path: filePath}
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Database.Password.String()).To(Equal("myS3cretP@ss"))
	})

	It("trims trailing newline from file-type secrets", func() {
		filePath := filepath.Join(tmpDir, "my_secret")
		Expect(os.WriteFile(filePath, []byte("file-secret-data\n"), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath}
		Expect(driver.Resolve(opts)).To(Succeed())
		Expect(opts.Auth.JWT.SecretKey.Bytes()).To(Equal([]byte("file-secret-data")))
	})

	It("fails for file-type secret with non-absolute path", func() {
		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: "relative/path"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("path must be absolute")))
	})

	It("fails for YAML key extraction when key is not found", func() {
		yamlContent := "other: somevalue\n"
		filePath := filepath.Join(tmpDir, "secrets.yaml")
		Expect(os.WriteFile(filePath, []byte(yamlContent), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath, Key: "missing"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("not found")))
	})

	It("fails for YAML key extraction when value is not a string", func() {
		filePath := filepath.Join(tmpDir, "secrets.yaml")
		Expect(os.WriteFile(filePath, []byte("jwt: 12345\n"), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath, Key: "jwt"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("not a string")))
	})

	It("fails for YAML key extraction when value is empty string", func() {
		filePath := filepath.Join(tmpDir, "secrets.yaml")
		Expect(os.WriteFile(filePath, []byte(`jwt: ""`), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath, Key: "jwt"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("is empty")))
	})

	It("fails for file-type secret with YAML key when file contains invalid YAML", func() {
		filePath := filepath.Join(tmpDir, "bad.yaml")
		Expect(os.WriteFile(filePath, []byte(":\tinvalid:\tyaml:::"), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath, Key: "jwt"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("parse yaml/json")))
	})

	It("fails when existing secret file is too short", func() {
		secretPath := filepath.Join(tmpDir, "jwt_secret_key")
		Expect(os.WriteFile(secretPath, []byte("tooshort"), 0o600)).To(Succeed())

		opts := &config.Options{}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("too short")))
	})

	It("fails for file type with empty path", func() {
		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("requires a path")))
	})

	It("fails for path without type", func() {
		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Path: "/some/path"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("has no type")))
	})

	It("fails for hashicorp source type (not yet implemented)", func() {
		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "hashicorp"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("not yet implemented")))
	})

	It("fails for unknown source type", func() {
		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "vault"}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("unknown secret source type")))
	})

	It("fails when secrets directory cannot be created", func() {
		opts := &config.Options{}
		badDriver := secret.New(ezlog.NewLogger(context.Background(), config.LogConfig{}), "/proc/readonly")
		Expect(badDriver.Resolve(opts)).To(MatchError(ContainSubstring("could not persist")))
	})

	It("fails when file-type secret file is empty", func() {
		filePath := filepath.Join(tmpDir, "empty_secret")
		Expect(os.WriteFile(filePath, []byte(""), 0o600)).To(Succeed())

		opts := &config.Options{}
		opts.Auth.JWT.SecretKey = config.SecretRef{Type: "file", Path: filePath}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("secret is empty")))
	})

	It("fails when auto-gen cannot write file (read-only dir)", func() {
		roDir := GinkgoT().TempDir()
		Expect(os.Chmod(roDir, 0o500)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(roDir, 0o700) })

		roDriver := secret.New(ezlog.NewLogger(context.Background(), config.LogConfig{}), filepath.Join(roDir, "secrets"))
		opts := &config.Options{}
		Expect(roDriver.Resolve(opts)).To(MatchError(ContainSubstring("could not persist")))
	})

	It("fails when existing secret file cannot be read (no read permission)", func() {
		secretPath := filepath.Join(tmpDir, "jwt_secret_key")
		Expect(os.WriteFile(secretPath, []byte("validsecretcontentthatis32bytes!!"), 0o000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(secretPath, 0o600) })

		opts := &config.Options{}
		Expect(driver.Resolve(opts)).To(MatchError(ContainSubstring("read existing secret file")))
	})
})
