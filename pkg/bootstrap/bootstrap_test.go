package bootstrap

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

var _ = Describe("Bootstrap", func() {
	Describe("resolveDefaults", func() {
		It("fills zero-value fields", func() {
			cfg := Config{}.resolveDefaults()
			Expect(cfg.SecretFile).To(Equal("/opt/ezauth/secrets/root_secret"))
			Expect(cfg.SystemAdminGroup).To(Equal("system-admins"))
		})
		It("preserves explicitly set fields", func() {
			cfg := Config{
				SecretFile:       "/custom/secret",
				SystemAdminGroup: "my-admins",
			}.resolveDefaults()
			Expect(cfg.SecretFile).To(Equal("/custom/secret"))
			Expect(cfg.SystemAdminGroup).To(Equal("my-admins"))
		})
	})

	Describe("Bootstrap nil db", func() {
		It("returns immediately when db is nil", func() {
			logger, _ := testutils.SetupTestLogger()
			Bootstrap(context.Background(), nil, logger, Config{})
		})
	})

	Describe("loadOrCreateBootstrapSecret", func() {
		It("generates credentials when file is missing", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "root.secret")
			logger, _ := testutils.SetupTestLogger()

			user, pass, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).ToNot(HaveOccurred())
			Expect(user).To(Equal(defaultRootUsername))
			Expect(pass).ToNot(BeEmpty())
			_, statErr := os.Stat(path)
			Expect(statErr).ToNot(HaveOccurred())

			user2, pass2, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).ToNot(HaveOccurred())
			Expect(user2).To(Equal(user))
			Expect(pass2).To(Equal(pass))
		})

		It("returns error for invalid base64 content", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "root.secret")
			Expect(os.WriteFile(path, []byte("not-valid-base64!!!\n"), 0o600)).To(Succeed())

			logger, _ := testutils.SetupTestLogger()
			_, _, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).To(HaveOccurred())
		})

		It("generates credentials for empty file", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "root.secret")
			Expect(os.WriteFile(path, []byte("\n"), 0o600)).To(Succeed())

			logger, _ := testutils.SetupTestLogger()
			user, pass, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).ToNot(HaveOccurred())
			Expect(user).ToNot(BeEmpty())
			Expect(pass).ToNot(BeEmpty())
		})

		It("returns error for secret without colon separator", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "root.secret")
			encoded := base64.StdEncoding.EncodeToString([]byte("nocolon"))
			Expect(os.WriteFile(path, []byte(encoded+"\n"), 0o600)).To(Succeed())

			logger, _ := testutils.SetupTestLogger()
			_, _, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).To(HaveOccurred())
		})

		It("returns error for empty username in secret", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "root.secret")
			encoded := base64.StdEncoding.EncodeToString([]byte(":password"))
			Expect(os.WriteFile(path, []byte(encoded+"\n"), 0o600)).To(Succeed())

			logger, _ := testutils.SetupTestLogger()
			_, _, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).To(HaveOccurred())
		})

		It("returns error for empty password in secret", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "root.secret")
			encoded := base64.StdEncoding.EncodeToString([]byte("user:"))
			Expect(os.WriteFile(path, []byte(encoded+"\n"), 0o600)).To(Succeed())

			logger, _ := testutils.SetupTestLogger()
			_, _, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).To(HaveOccurred())
		})

		It("returns error when parent path is a file", func() {
			dir := GinkgoT().TempDir()
			parent := filepath.Join(dir, "parent")
			Expect(os.WriteFile(parent, []byte("not-a-dir"), 0o600)).To(Succeed())
			path := filepath.Join(parent, "sub", "root.secret")

			logger, _ := testutils.SetupTestLogger()
			_, _, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).To(HaveOccurred())
		})

		It("returns error when secret path is a directory", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "root.secret")
			Expect(os.Mkdir(path, 0o700)).To(Succeed())

			logger, _ := testutils.SetupTestLogger()
			_, _, err := loadOrCreateBootstrapSecret(logger, path)
			Expect(err).To(HaveOccurred())
		})
	})
})
