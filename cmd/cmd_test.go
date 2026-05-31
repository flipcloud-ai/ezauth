package cmd

import (
	"fmt"
	"time"

	"github.com/flipcloud-ai/ezauth/config"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	"github.com/spf13/cobra"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cmd Test Suite", func() {
	var rootCmd *cobra.Command
	currentCfgPath, err := testutils.Config("config/empty.yaml")
	Expect(err).To(BeNil())

	BeforeEach(func() {
		rootCmd = Command(testutils.ConfigPrinter)
		rootCmd.SetArgs([]string{fmt.Sprintf("--config=%s", currentCfgPath)})
	})

	Describe("Default configuration", func() {
		BeforeEach(func() {
			rootCmd.SetArgs([]string{fmt.Sprintf("--config=%s", currentCfgPath)})
			Expect(rootCmd.Execute()).To(Succeed())
		})

		It("loads default configuration values", func() {
			cfg, err := config.LoadConfiguration(rootCmd)
			Expect(err).To(BeNil())
			Expect(cfg).NotTo(BeNil())

			// Server defaults
			Expect(cfg.Server.ForceHTTPS).To(Equal(false))
			Expect(cfg.Server.Http2).To(Equal(false))
			Expect(cfg.Server.Hostname).To(Equal("0.0.0.0"))
			Expect(cfg.Server.Port).To(Equal(0))
			Expect(cfg.Server.IdleTimeout).To(Equal(60))
			Expect(cfg.Server.WriteTimeout).To(Equal(300))
			Expect(cfg.Server.ReadTimeout).To(Equal(300))
			Expect(cfg.Server.TLS.Enabled).To(Equal(false))
			Expect(cfg.Server.TLS.CertPath).To(Equal("/opt/ezauth/tls/cert.crt"))
			Expect(cfg.Server.TLS.KeyPath).To(Equal("/opt/ezauth/tls/key.pem"))
			Expect(cfg.Server.TLS.Version).To(Equal("TLS1.2"))

			// Auth defaults
			Expect(cfg.Auth.JWT.KeyPath).To(Equal("/opt/ezauth"))
			Expect(cfg.Auth.JWT.SigningMethod).To(Equal("hs256"))

			// Log defaults
			Expect(cfg.Log.Level).To(Equal("info"))
		})
	})

	Describe("Log flag variations", func() {
		DescribeTable("log level flag combinations",
			func(args []string, expectedLevel string) {
				rootCmd.SetArgs(append([]string{fmt.Sprintf("--config=%s", currentCfgPath)}, args...))
				Expect(rootCmd.Execute()).To(Succeed())
				cfg, err := config.LoadConfiguration(rootCmd)
				Expect(err).To(BeNil())
				Expect(cfg.Log.Level).To(Equal(expectedLevel))
			},
			Entry("debug flag", []string{"--debug"}, "debug"),
			Entry("log-level info", []string{"--log-level=info"}, "info"),
			Entry("log-level warn", []string{"--log-level=warn"}, "warn"),
			Entry("log-level debug", []string{"--log-level=debug"}, "debug"),
			Entry("log-path flag", []string{"--log-path=/var/log/ezauth"}, "info"),
			Entry("combined debug and log-path", []string{"--debug", "--log-path=/test"}, "debug"),
		)
	})

	Describe("Provider flag variations", func() {
		DescribeTable("provider flag combinations",
			func(args []string, expectedProviderName, expectedClientID, expectedClientSecret string) {
				rootCmd.SetArgs(append([]string{fmt.Sprintf("--config=%s", currentCfgPath)}, args...))
				Expect(rootCmd.Execute()).To(Succeed())
				cfg, err := config.LoadConfiguration(rootCmd)
				Expect(err).To(BeNil())
				Expect(cfg.Auth.Provider).To(HaveLen(1))
				Expect(cfg.Auth.Provider[0].ProviderName).To(Equal(expectedProviderName))
				Expect(cfg.Auth.Provider[0].ClientID).To(Equal(expectedClientID))
				Expect(cfg.Auth.Provider[0].ClientSecret).To(Equal(expectedClientSecret))
			},
			Entry("basic provider flags", []string{
				"--client-id=test1234",
				"--client-secret=test4321",
				"--provider-name=test",
			}, "test", "test1234", "test4321"),
			Entry("provider with google name", []string{
				"--client-id=google-client",
				"--client-secret=google-secret",
				"--provider-name=google",
			}, "google", "google-client", "google-secret"),
			Entry("provider with okta name", []string{
				"--client-id=okta-client-id",
				"--client-secret=okta-client-secret",
				"--provider-name=okta",
			}, "okta", "okta-client-id", "okta-client-secret"),
		)
	})

	Describe("Server flag variations", func() {
		DescribeTable("server flag combinations",
			func(args []string, check func(cfg *config.Options)) {
				rootCmd.SetArgs(append([]string{fmt.Sprintf("--config=%s", currentCfgPath)}, args...))
				Expect(rootCmd.Execute()).To(Succeed())
				cfg, err := config.LoadConfiguration(rootCmd)
				Expect(err).To(BeNil())
				check(cfg)
			},
			Entry("TLS enable with custom cert", []string{
				"--tls-enable",
				"--tls-cert=/custom/cert.crt",
				"--tls-key=/custom/key.pem",
			}, func(cfg *config.Options) {
				Expect(cfg.Server.TLS.Enabled).To(BeTrue())
				Expect(cfg.Server.TLS.CertPath).To(Equal("/custom/cert.crt"))
				Expect(cfg.Server.TLS.KeyPath).To(Equal("/custom/key.pem"))
			}),
			Entry("custom hostname and port", []string{
				"--hostname=www.example.com",
				"--port=9000",
			}, func(cfg *config.Options) {
				Expect(cfg.Server.Hostname).To(Equal("www.example.com"))
				Expect(cfg.Server.Port).To(Equal(9000))
			}),
			Entry("custom timeouts", []string{
				"--idle-timeout=120",
				"--write-timeout=600",
				"--read-timeout=600",
			}, func(cfg *config.Options) {
				Expect(cfg.Server.IdleTimeout).To(Equal(120))
				Expect(cfg.Server.WriteTimeout).To(Equal(600))
				Expect(cfg.Server.ReadTimeout).To(Equal(600))
			}),
			Entry("force https and http2", []string{
				"--force-https",
				"--http2",
			}, func(cfg *config.Options) {
				Expect(cfg.Server.ForceHTTPS).To(BeTrue())
				Expect(cfg.Server.Http2).To(BeTrue())
			}),
			Entry("all server flags combined", []string{
				"--debug",
				"--tls-enable",
				"--hostname=secure.example.com",
				"--port=8443",
				"--idle-timeout=100",
				"--write-timeout=200",
				"--read-timeout=200",
				"--tls-cert=/full/cert.crt",
				"--tls-key=/full/key.pem",
				"--log-level=warn",
			}, func(cfg *config.Options) {
				Expect(cfg.Server.TLS.Enabled).To(BeTrue())
				Expect(cfg.Server.TLS.CertPath).To(Equal("/full/cert.crt"))
				Expect(cfg.Server.TLS.KeyPath).To(Equal("/full/key.pem"))
				Expect(cfg.Server.Hostname).To(Equal("secure.example.com"))
				Expect(cfg.Server.Port).To(Equal(8443))
				Expect(cfg.Server.IdleTimeout).To(Equal(100))
				Expect(cfg.Server.WriteTimeout).To(Equal(200))
				Expect(cfg.Server.ReadTimeout).To(Equal(200))
				Expect(cfg.Log.Level).To(Equal("debug"))
			}),
		)
	})

	Describe("Database flag variations", func() {
		DescribeTable("database flag combinations",
			func(args []string, check func(cfg *config.Options)) {
				rootCmd.SetArgs(append([]string{fmt.Sprintf("--config=%s", currentCfgPath)}, args...))
				Expect(rootCmd.Execute()).To(Succeed())
				cfg, err := config.LoadConfiguration(rootCmd)
				Expect(err).To(BeNil())
				check(cfg)
			},
			Entry("custom database host", []string{
				"--database-host=db.example.com",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.Hostname).To(Equal("db.example.com"))
			}),
			Entry("custom database port", []string{
				"--database-port=5433",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.Port).To(Equal(5433))
			}),
			Entry("custom database name", []string{
				"--database-name=mydb",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.Name).To(Equal("mydb"))
			}),
			Entry("custom database user", []string{
				"--database-user=admin",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.User).To(Equal("admin"))
			}),
			Entry("custom database password", []string{
				"--database-password=secret",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.Password.String()).To(Equal("secret"))
			}),
			Entry("database ssl mode require", []string{
				"--database-ssl-mode=require",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.SSL.Mode).To(Equal("require"))
			}),
			Entry("database ssl mode verify-full", []string{
				"--database-ssl-mode=verify-full",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.SSL.Mode).To(Equal("verify-full"))
			}),
			Entry("database connect timeout", []string{
				"--database-connect-timeout=10s",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.ConnectTimeout).To(Equal(10 * time.Second))
			}),
			Entry("all database flags combined", []string{
				"--database-host=postgres.example.com",
				"--database-port=5432",
				"--database-name=production",
				"--database-user=appuser",
				"--database-password=prodsecret",
				"--database-ssl-mode=verify-full",
				"--database-connect-timeout=30s",
			}, func(cfg *config.Options) {
				Expect(cfg.Database.Hostname).To(Equal("postgres.example.com"))
				Expect(cfg.Database.Port).To(Equal(5432))
				Expect(cfg.Database.Name).To(Equal("production"))
				Expect(cfg.Database.User).To(Equal("appuser"))
				Expect(cfg.Database.Password.String()).To(Equal("prodsecret"))
				Expect(cfg.Database.SSL.Mode).To(Equal("verify-full"))
				Expect(cfg.Database.ConnectTimeout).To(Equal(30 * time.Second))
			}),
		)
	})

	Describe("Config file validation", func() {
		DescribeTable("config file scenarios",
			func(args []string, expectError bool, errorContains string) {
				rootCmd := Command(testutils.ConfigPrinter)
				rootCmd.SetArgs(args)
				err := rootCmd.Execute()
				if expectError {
					Expect(err).To(HaveOccurred())
					if errorContains != "" {
						Expect(err.Error()).To(ContainSubstring(errorContains))
					}
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
			},
			Entry("config file not set in command (uses default)", []string{}, false, ""),
			Entry("config file set and exists", []string{fmt.Sprintf("--config=%s", currentCfgPath)}, false, ""),
			Entry("config file set but does not exist", []string{"--config=/nonexistent/path/config.yaml"}, true, "does not exist"),
			Entry("config file set to empty value", []string{"--config="}, true, "does not exist"),
		)
	})

	Describe("Flag combinations", func() {
		It("all flags combined: server, provider, database, log", func() {
			rootCmd.SetArgs([]string{
				fmt.Sprintf("--config=%s", currentCfgPath),
				"--debug",
				"--log-path=/var/log/ezauth",
				"--tls-enable",
				"--hostname=app.example.com",
				"--port=8080",
				"--idle-timeout=120",
				"--write-timeout=300",
				"--read-timeout=300",
				"--tls-cert=/etc/ezauth/tls.crt",
				"--tls-key=/etc/ezauth/tls.key",
				"--force-https",
				"--http2",
				"--client-id=oidc-client",
				"--client-secret=oidc-secret",
				"--provider-name=azure",
				"--database-host=db.example.com",
				"--database-port=5432",
				"--database-name=authdb",
				"--database-user=authuser",
				"--database-password=authpass",
				"--database-ssl-mode=require",
				"--database-connect-timeout=10s",
			})
			Expect(rootCmd.Execute()).To(Succeed())
			cfg, err := config.LoadConfiguration(rootCmd)
			Expect(err).To(BeNil())

			// Log
			Expect(cfg.Log.Level).To(Equal("debug"))
			Expect(cfg.Log.Path).To(Equal("/var/log/ezauth"))

			// Server
			Expect(cfg.Server.TLS.Enabled).To(BeTrue())
			Expect(cfg.Server.TLS.CertPath).To(Equal("/etc/ezauth/tls.crt"))
			Expect(cfg.Server.TLS.KeyPath).To(Equal("/etc/ezauth/tls.key"))
			Expect(cfg.Server.Hostname).To(Equal("app.example.com"))
			Expect(cfg.Server.Port).To(Equal(8080))
			Expect(cfg.Server.IdleTimeout).To(Equal(120))
			Expect(cfg.Server.WriteTimeout).To(Equal(300))
			Expect(cfg.Server.ReadTimeout).To(Equal(300))
			Expect(cfg.Server.ForceHTTPS).To(BeTrue())
			Expect(cfg.Server.Http2).To(BeTrue())

			// Provider
			Expect(cfg.Auth.Provider).To(HaveLen(1))
			Expect(cfg.Auth.Provider[0].ClientID).To(Equal("oidc-client"))
			Expect(cfg.Auth.Provider[0].ClientSecret).To(Equal("oidc-secret"))
			Expect(cfg.Auth.Provider[0].ProviderName).To(Equal("azure"))

			// Database
			Expect(cfg.Database.Hostname).To(Equal("db.example.com"))
			Expect(cfg.Database.Port).To(Equal(5432))
			Expect(cfg.Database.Name).To(Equal("authdb"))
			Expect(cfg.Database.User).To(Equal("authuser"))
			Expect(cfg.Database.Password.String()).To(Equal("authpass"))
			Expect(cfg.Database.SSL.Mode).To(Equal("require"))
			Expect(cfg.Database.ConnectTimeout).To(Equal(10 * time.Second))
		})
	})
})
