package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func config(path string) (string, error) {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	_, err := os.ReadFile(filepath.Join(dir, "../", path))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "../", path), err
}

func loadFromConfig(path string) Options {
	rootCmd := &cobra.Command{}
	rootCmd.Flags().StringP("config", "f", "/opt/ezauth/config.yaml", "Config file (default is /opt/ezauth/config.yaml)")
	AddServerFlags(rootCmd)
	currentCfgPath, _ := config(fmt.Sprintf("test/config/%s", path))

	rootCmd.SetArgs(
		[]string{
			fmt.Sprintf("--config=%s", currentCfgPath),
		},
	)
	Expect(rootCmd.Execute()).To(Succeed())
	cfg, _ := LoadConfiguration(rootCmd)
	return *cfg
}

func ptrBool(b bool) *bool {
	return &b
}

type stringValue string

func (s *stringValue) String() string { return string(*s) }
func (s *stringValue) Set(v string) error {
	*s = stringValue(v)
	return nil
}
func (s *stringValue) Type() string { return "string" }

var _ = Describe("Config Test Suite", func() {
	Context("Config Parsing", func() {
		It("default config check", func(ctx SpecContext) {
			cmd := &cobra.Command{}

			cfg, err := LoadConfiguration(cmd)

			Expect(err).To(BeNil())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Log.Level).To(Equal("info"))
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
			Expect(cfg.Server.AuthPrefix).To(Equal("/ezauth"))
			Expect(cfg.Auth.JWT.KeyPath).To(Equal("/opt/ezauth"))
			Expect(cfg.Auth.JWT.SigningMethod).To(Equal("hs256"))
			Expect(cfg.Auth.Proxy.ProxyPrefix).To(Equal("/"))
			Expect(cfg.Auth.Proxy.IsEnabled()).To(BeTrue())
			Expect(cfg.Auth.Session.RefreshPeriod).To(Equal(time.Minute * 15))
			Expect(cfg.Auth.Session.Cookie.Minimal).To(Equal(false))
			Expect(cfg.Auth.Session.Cookie).To(Equal(CookieStoreOptions{
				Name:     "_ez_proxy",
				Secret:   SecretRef{},
				Domains:  nil,
				Path:     "/",
				Expire:   24 * time.Hour,
				Refresh:  0,
				Secure:   false,
				HTTPOnly: ptrBool(true),
				SameSite: "lax",
			}))
			Expect(len(cfg.Auth.Proxy.SkipAuthPaths)).To(Equal(0))
			Expect(len(cfg.Auth.Proxy.AllowDomains)).To(Equal(0))
			Expect(len(cfg.Auth.Provider)).To(Equal(0))
			Expect(len(cfg.Auth.Static)).To(Equal(0))
		})
		It("auth config check", func(ctx SpecContext) {
			t := loadFromConfig("standard.yaml")
			Expect(t.Auth.JWT.SigningMethod).To(Equal("hs512"))
			Expect(len(t.Auth.Static)).To(Equal(2))
		})
		It("access.rbac config check", func(ctx SpecContext) {
			cfg := loadFromConfig("access_rbac.yaml")
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Access.RBAC.Enabled).To(BeTrue())
		})
		It("server config check", func(ctx SpecContext) {
			cmd := &cobra.Command{
				Use: "test",
				RunE: func(cmd *cobra.Command, args []string) error {
					cfg, err := LoadConfiguration(cmd)
					Expect(err).To(BeNil())
					Expect(cfg.Server.ForceHTTPS).To(Equal(true))
					Expect(cfg.Server.Http2).To(Equal(true))
					Expect(cfg.Server.Hostname).To(Equal("10.0.0.1"))
					Expect(cfg.Server.Port).To(Equal(8232))
					Expect(cfg.Server.IdleTimeout).To(Equal(3333))
					Expect(cfg.Server.WriteTimeout).To(Equal(3333))
					Expect(cfg.Server.ReadTimeout).To(Equal(3333))
					Expect(cfg.Server.TLS.Enabled).To(Equal(true))
					Expect(cfg.Server.TLS.CertPath).To(Equal("/path/to/cert.crt"))
					Expect(cfg.Server.TLS.KeyPath).To(Equal("/path/to/key.pem"))
					Expect(cfg.Server.Pprof.Enabled).To(Equal(true))
					return err
				},
			}
			AddServerFlags(cmd)
			cmd.SetArgs([]string{
				"--force-https",
				"--http2",
				"--port",
				"8232",
				"--hostname",
				"10.0.0.1",
				"--idle-timeout",
				"3333",
				"--write-timeout",
				"3333",
				"--read-timeout",
				"3333",
				"--tls-enable",
				"--tls-cert",
				"/path/to/cert.crt",
				"--tls-key",
				"/path/to/key.pem",
				"--pprof-enabled",
			})
			Expect(cmd.Execute()).To(Succeed())
		})
		It("metrics config flags test", func(ctx SpecContext) {
			cmd := &cobra.Command{
				Use: "test",
				RunE: func(cmd *cobra.Command, args []string) error {
					cfg, err := LoadConfiguration(cmd)
					Expect(err).To(BeNil())
					Expect(cfg.Server.Metrics.Enabled).To(Equal(true))
					Expect(cfg.Server.Metrics.Port).To(Equal(9091))
					Expect(cfg.Server.Metrics.Host).To(Equal("0.0.0.0"))
					Expect(cfg.Server.Metrics.Path).To(Equal("/metrics"))
					return err
				},
			}
			AddServerFlags(cmd)
			cmd.SetArgs([]string{
				"--metrics-enabled",
				"--metrics-port",
				"9091",
				"--metrics-host",
				"0.0.0.0",
			})
			Expect(cmd.Execute()).To(Succeed())
		})
		DescribeTable("client-id and client-secret flags",
			func(providerNameFlag string, expectedProviderName string) {
				cmd := &cobra.Command{}
				cmd.Flags().String("config", "/opt/ezauth/config.yaml", "Config file")
				cmd.Flags().String("client-id", "test-client-id", "Oauth2 client ID")
				cmd.Flags().String("client-secret", "test-client-secret", "Oauth2 client Secret")
				if providerNameFlag != "" {
					cmd.Flags().String("provider-name", providerNameFlag, "Oauth2 provider name")
				}

				cfg, err := LoadConfiguration(cmd)

				Expect(err).To(BeNil())
				Expect(cfg).NotTo(BeNil())
				Expect(len(cfg.Auth.Provider)).To(Equal(1))
				Expect(cfg.Auth.Provider[0].ClientID).To(Equal("test-client-id"))
				Expect(cfg.Auth.Provider[0].ClientSecret).To(Equal("test-client-secret"))
				Expect(cfg.Auth.Provider[0].ProviderName).To(Equal(expectedProviderName))
			},
			Entry("default provider name", "", "oauth2"),
			Entry("custom provider name", "custom-provider", "custom-provider"),
		)
		It("overrides existing provider client-id and client-secret", func(ctx SpecContext) {
			path, err := config("test/config/oauth2/invalid.yaml")
			Expect(err).ToNot(HaveOccurred())

			rootCmd := &cobra.Command{}
			rootCmd.Flags().StringP("config", "f", "/opt/ezauth/config.yaml", "Config file")
			rootCmd.Flags().String("client-id", "new-id", "Client ID")
			rootCmd.Flags().String("client-secret", "new-secret", "Client Secret")
			rootCmd.Flags().String("provider-name", "test", "Provider name")
			rootCmd.SetArgs([]string{fmt.Sprintf("--config=%s", path)})
			_ = rootCmd.Execute()

			cfg, err := LoadConfiguration(rootCmd)
			Expect(err).To(BeNil())
			Expect(len(cfg.Auth.Provider)).To(Equal(2))
			Expect(cfg.Auth.Provider[0].ProviderName).To(Equal("test"))
			Expect(cfg.Auth.Provider[0].ClientID).To(Equal("new-id"))
			Expect(cfg.Auth.Provider[0].ClientSecret).To(Equal("new-secret"))
		})
	})
	Context("LoadConfiguration edge cases", func() {
		It("returns error when config file explicitly set but does not exist", func(ctx SpecContext) {
			cmd := &cobra.Command{}
			cmd.Flags().String("config", "/opt/ezauth/config.yaml", "Config file")
			cmd.SetArgs([]string{"--config=/nonexistent/path/cfg.yaml"})
			_ = cmd.Execute()

			_, err := LoadConfiguration(cmd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not exist"))
		})
		It("debug flag sets log level to debug", func(ctx SpecContext) {
			cmd := &cobra.Command{}
			cmd.Flags().String("config", "/opt/ezauth/config.yaml", "Config file")
			cmd.Flags().Bool("debug", false, "Debug mode")
			cmd.SetArgs([]string{"--debug"})
			_ = cmd.Execute()

			cfg, err := LoadConfiguration(cmd)
			Expect(err).To(BeNil())
			Expect(cfg.Log.Level).To(Equal("debug"))
		})
	})
	Context("Environment Variables", func() {
		It("log.level env var test", func(ctx SpecContext) {
			Expect(os.Setenv("EZ_LOG_LEVEL", "debug")).To(Succeed())
			defer func() { Expect(os.Unsetenv("EZ_LOG_LEVEL")).To(Succeed()) }()

			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)

			Expect(err).To(BeNil())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Log.Level).To(Equal("debug"))
		})
		It("server.hostname env var test", func(ctx SpecContext) {
			Expect(os.Setenv("EZ_SERVER_HOSTNAME", "example.com")).To(Succeed())
			defer func() { Expect(os.Unsetenv("EZ_SERVER_HOSTNAME")).To(Succeed()) }()

			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)

			Expect(err).To(BeNil())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Server.Hostname).To(Equal("example.com"))
		})
		It("server.port env var test", func(ctx SpecContext) {
			Expect(os.Setenv("EZ_SERVER_PORT", "8080")).To(Succeed())
			defer func() { Expect(os.Unsetenv("EZ_SERVER_PORT")).To(Succeed()) }()

			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)

			Expect(err).To(BeNil())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Server.Port).To(Equal(8080))
		})
		It("auth.jwt.signingmethod env var test", func(ctx SpecContext) {
			Expect(os.Setenv("EZ_AUTH.JWT.SIGNINGMETHOD", "hs512")).To(Succeed())
			defer func() { Expect(os.Unsetenv("EZ_AUTH.JWT.SIGNINGMETHOD")).To(Succeed()) }()

			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)

			Expect(err).To(BeNil())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Auth.JWT.SigningMethod).To(Equal("hs512"))
		})
		It("multiple env vars test", func(ctx SpecContext) {
			Expect(os.Setenv("EZ_LOG_LEVEL", "debug")).To(Succeed())
			Expect(os.Setenv("EZ_SERVER_HOSTNAME", "test.example.com")).To(Succeed())
			Expect(os.Setenv("EZ_AUTH.JWT.SIGNINGMETHOD", "hs256")).To(Succeed())
			defer func() {
				Expect(os.Unsetenv("EZ_LOG_LEVEL")).To(Succeed())
				Expect(os.Unsetenv("EZ_SERVER_HOSTNAME")).To(Succeed())
				Expect(os.Unsetenv("EZ_AUTH.JWT.SIGNINGMETHOD")).To(Succeed())
			}()

			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)

			Expect(err).To(BeNil())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Log.Level).To(Equal("debug"))
			Expect(cfg.Server.Hostname).To(Equal("test.example.com"))
			Expect(cfg.Auth.JWT.SigningMethod).To(Equal("hs256"))
		})
	})
	Context("AuthProxyConfig.IsEnabled", func() {
		DescribeTable("returns correct enabled state",
			func(enabled *bool, expected bool) {
				cfg := AuthProxyConfig{Enabled: enabled}
				Expect(cfg.IsEnabled()).To(Equal(expected))
			},
			Entry("nil (not configured) should return true", nil, true),
			Entry("explicit true should return true", ptrBool(true), true),
			Entry("explicit false should return false", ptrBool(false), false),
		)
		It("nil receiver should return true", func() {
			var p *AuthProxyConfig
			Expect(p.IsEnabled()).To(BeTrue())
		})
	})
	Context("Error types", func() {
		DescribeTable("error types",
			func(construct func() error, assertAs func(error) bool) {
				err := construct()
				Expect(err).To(HaveOccurred())
				Expect(assertAs(err)).To(BeTrue())
			},
			Entry("ErrNotAStructPointer",
				func() error {
					var t struct{ Test string }
					return newErrNotAStructPointer(t)
				},
				func(err error) bool {
					var te ErrNotAStructPointer
					Expect(err.Error()).To(ContainSubstring("expected a struct"))
					return errors.As(err, &te)
				},
			),
			Entry("ErrorUnsettable",
				func() error {
					var t struct{ Test string }
					return newErrorUnsettable(t)
				},
				func(err error) bool {
					var te ErrorUnsettable
					Expect(err.Error()).To(ContainSubstring("can't set field"))
					return errors.As(err, &te)
				},
			),
			Entry("ErrorWhileSettingConfig",
				func() error {
					var t struct{ Test string }
					return newErrorWhileSettingConfig(t)
				},
				func(err error) bool {
					var te ErrorWhileSettingConfig
					Expect(err.Error()).To(ContainSubstring("err while setting field"))
					return errors.As(err, &te)
				},
			),
		)

		It("unsupported type check", func(ctx SpecContext) {
			var t struct{ Test string }
			e := ErrorUnsupportedType{t: reflect.TypeOf(t)}
			Expect(e.Error()).To(Equal(fmt.Sprintf("unsupported type %v", e.t)))
		})
	})
	Context("parseCfg", func() {
		It("returns error for non-pointer", func() {
			s := struct{}{}
			err := parseCfg(s, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("expected a struct"))
		})
		It("returns error for non-struct pointer", func() {
			var i int
			err := parseCfg(&i, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("expected a struct"))
		})
	})
	Context("parseFlagField", func() {
		It("returns error for unsettable field with flag tag", func() {
			type testCfg struct {
				unexported string `flag:"test-flag"`
			}
			tc := testCfg{}
			v := reflect.ValueOf(&tc).Elem()
			err := parseFlagField(v.Field(0), v.Type().Field(0), nil)
			Expect(err).To(HaveOccurred())
			_, ok := err.(ErrorUnsettable)
			Expect(ok).To(BeTrue())
		})
		It("returns nil for nil struct pointer", func() {
			type inner struct{ Val int }
			type testCfg struct {
				Inner *inner `flag:"inner-flag"`
			}
			tc := testCfg{}
			v := reflect.ValueOf(&tc).Elem()
			err := parseFlagField(v.Field(0), v.Type().Field(0), nil)
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns error when setValue fails for flag", func() {
			type testCfg struct {
				Port int `flag:"port-flag"`
			}
			tc := testCfg{}
			sv := stringValue("not-a-number")
			cmdFlags := map[string]*flag.Flag{
				"port-flag": {
					Name:  "port-flag",
					Value: &sv,
				},
			}
			v := reflect.ValueOf(&tc).Elem()
			err := parseFlagField(v.Field(0), v.Type().Field(0), cmdFlags)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int"))
		})
	})
	Context("parseFields", func() {
		It("returns error when parseFlagField fails on unsettable field", func() {
			type testCfg struct {
				unexported string `flag:"bad-flag"`
			}
			tc := testCfg{}
			v := reflect.ValueOf(&tc).Elem()
			err := parseFields(v, nil)
			Expect(err).To(HaveOccurred())
		})
		It("returns error when parseDefaultField fails on nested struct", func() {
			type inner struct {
				BadField int `default:"invalid-int"`
			}
			type testCfg struct {
				Inner inner
			}
			tc := testCfg{}
			v := reflect.ValueOf(&tc).Elem()
			err := parseFields(v, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int"))
		})
	})
	Context("parseDefaultField", func() {
		It("returns error for invalid default on struct sub-field", func() {
			type inner struct {
				BadField int `default:"invalid-int"`
			}
			type testCfg struct {
				Inner inner
			}
			tc := testCfg{}
			v := reflect.ValueOf(&tc).Elem()
			err := parseDefaultField(v.Field(0), v.Type().Field(0), nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int"))
		})
	})
	Context("upstream URL parsing", func() {
		It("should default to http://127.0.0.1:8080 when not configured", func() {
			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)
			Expect(err).To(BeNil())
			Expect(cfg.Server.Upstream).NotTo(BeNil())
			Expect(cfg.Server.Upstream.String()).To(Equal("http://127.0.0.1:8080"))
		})
		It("should use the upstream value from config file", func() {
			cfg := loadFromConfig("standard.yaml")
			Expect(cfg.Server.Upstream).NotTo(BeNil())
			Expect(cfg.Server.Upstream.String()).To(Equal("http://127.0.0.1:8080"))
		})
		It("should not override config value with default", func() {
			tmplPath := filepath.Join(os.TempDir(), "upstream-test-config.yaml")
			Expect(os.WriteFile(tmplPath, []byte("server:\n  upstream: http://example.com:9090\n"), 0600)).To(Succeed())
			defer func() { _ = os.Remove(tmplPath) }()

			rootCmd := &cobra.Command{}
			rootCmd.Flags().StringP("config", "f", "/opt/ezauth/config.yaml", "Config file")
			rootCmd.SetArgs([]string{fmt.Sprintf("--config=%s", tmplPath)})
			Expect(rootCmd.Execute()).To(Succeed())

			cfg, err := LoadConfiguration(rootCmd)
			Expect(err).To(BeNil())
			Expect(cfg.Server.Upstream).NotTo(BeNil())
			Expect(cfg.Server.Upstream.String()).To(Equal("http://example.com:9090"))
		})
	})
	Context("setURLValue", func() {
		It("should not overwrite an already set URL", func() {
			u, err := url.Parse("http://from-config:8080")
			Expect(err).To(BeNil())
			v := reflect.ValueOf(u)
			err = setURLValue(v, "http://default:9090")
			Expect(err).To(BeNil())
			Expect(u.String()).To(Equal("http://from-config:8080"))
		})
		It("should set URL when currently nil", func() {
			var u *url.URL
			v := reflect.ValueOf(&u).Elem()
			err := setURLValue(v, "http://default:9090")
			Expect(err).To(BeNil())
			Expect(u.String()).To(Equal("http://default:9090"))
		})
		It("should leave nil when raw is empty", func() {
			var u *url.URL
			v := reflect.ValueOf(&u).Elem()
			err := setURLValue(v, "")
			Expect(err).To(BeNil())
			Expect(u).To(BeNil())
		})
		It("should return error for invalid URL", func() {
			var u *url.URL
			v := reflect.ValueOf(&u).Elem()
			err := setURLValue(v, "://invalid")
			Expect(err).To(HaveOccurred())
		})
	})
	Context("default values", func() {
		It("should set IdentityHeadersConfig defaults when not configured", func() {
			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)
			Expect(err).To(BeNil())
			Expect(cfg.Auth.Proxy.IdentityHeaders.User).To(Equal("X-Auth-User"))
			Expect(cfg.Auth.Proxy.IdentityHeaders.Email).To(Equal("X-Auth-Email"))
			Expect(cfg.Auth.Proxy.IdentityHeaders.Groups).To(Equal("X-Auth-Groups"))
			Expect(cfg.Auth.Proxy.IdentityHeaders.Subject).To(Equal("X-Auth-Subject"))
		})
		It("should set TrustForwardedHeaders default to true", func() {
			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)
			Expect(err).To(BeNil())
			Expect(*cfg.Server.TrustForwardedHeaders).To(BeTrue())
		})
		It("should set all struct tag defaults when no config file is loaded", func() {
			cmd := &cobra.Command{}
			cfg, err := LoadConfiguration(cmd)
			Expect(err).To(BeNil())

			// LogConfig
			Expect(cfg.Log.Format).To(Equal("json"))
			Expect(cfg.Log.Path).To(Equal(""))

			// ServerConfig missing fields
			Expect(cfg.Server.StaticPrefix).To(Equal("/static"))
			Expect(cfg.Server.AppName).To(Equal("ezauth"))
			Expect(cfg.Server.HideAppName).To(BeFalse())
			Expect(cfg.Server.Portal.Enabled).To(BeFalse())
			Expect(cfg.Server.Pprof.Enabled).To(BeFalse())
			Expect(cfg.Server.Metrics.Enabled).To(BeFalse())
			Expect(cfg.Server.Metrics.Path).To(Equal("/metrics"))
			Expect(cfg.Server.Metrics.Port).To(Equal(9090))
			Expect(cfg.Server.Metrics.Host).To(Equal("127.0.0.1"))

			// DatabaseConfig
			Expect(cfg.Database.SkipInit).To(BeFalse())
			Expect(cfg.Database.SSL.Mode).To(Equal("disable"))

			// AuditConfig
			Expect(*cfg.Audit.Enabled).To(BeTrue())
			Expect(cfg.Audit.BufferSize).To(Equal(500))
			Expect(cfg.Audit.FlushInterval).To(Equal(5 * time.Minute))
			Expect(cfg.Audit.File).To(Equal(""))
			Expect(cfg.Audit.MaxFileSize).To(Equal(int64(104857600)))

			// AccessConfig
			Expect(cfg.Access.SystemAdminGroup).To(Equal("system-admins"))
			Expect(cfg.Access.RBAC.Enabled).To(BeFalse())
			Expect(cfg.Access.Bootstrap.SecretFile).To(Equal("/opt/ezauth/bootstrap/root_secret"))

			// JWTConfig
			Expect(cfg.Auth.JWT.ExpireDuration).To(Equal(24 * time.Hour))
			Expect(cfg.Auth.JWT.TokenIssuer).To(Equal(""))
			Expect(cfg.Auth.JWT.Audience).To(Equal(""))
			Expect(cfg.Auth.JWT.SecretKey.IsZero()).To(BeTrue())

			// AuthProxyConfig
			Expect(cfg.Auth.Proxy.JSONResponse).To(BeFalse())

			// ProviderCache (CacheConfig)
			Expect(cfg.Auth.ProviderCache.Size).To(Equal(30))
			Expect(cfg.Auth.ProviderCache.Shards).To(Equal(16))
			Expect(cfg.Auth.ProviderCache.RefreshInterval).To(BeZero())

			// RateLimitConfig (both login and oauth)
			Expect(cfg.Auth.LoginRateLimit.IPLimit).To(Equal(20))
			Expect(cfg.Auth.LoginRateLimit.UsernameLimit).To(Equal(5))
			Expect(cfg.Auth.LoginRateLimit.Window).To(Equal(time.Minute))
			Expect(cfg.Auth.LoginRateLimit.BlockDuration).To(Equal(15 * time.Minute))
			Expect(cfg.Auth.LoginRateLimit.CountMode).To(Equal("failures"))
			Expect(cfg.Auth.OAuthRateLimit.IPLimit).To(Equal(20))
			Expect(cfg.Auth.OAuthRateLimit.UsernameLimit).To(Equal(5))
			Expect(cfg.Auth.OAuthRateLimit.Window).To(Equal(time.Minute))
			Expect(cfg.Auth.OAuthRateLimit.BlockDuration).To(Equal(15 * time.Minute))
			Expect(cfg.Auth.OAuthRateLimit.CountMode).To(Equal("failures"))

			// OpaqueTokenConfig
			Expect(cfg.Auth.OpaqueToken.Prefix).To(Equal("ezauth_"))

			// Session
			Expect(cfg.Auth.Session.StoreType).To(Equal(""))
			Expect(cfg.Auth.Session.Cookie.MaxAge).To(Equal(time.Duration(0)))

			// CSRF
			Expect(cfg.Auth.Session.CSRF.Enabled).To(BeFalse())
			Expect(cfg.Auth.Session.CSRF.Name).To(Equal("_xw_csrf"))
			Expect(cfg.Auth.Session.CSRF.HeaderName).To(Equal("X-CSRF-Token"))
			Expect(cfg.Auth.Session.CSRF.MaxAge).To(Equal(12 * time.Hour))

			// StoreCacheConfig
			Expect(cfg.Cache.Memory.Size).To(Equal("200m"))
			Expect(cfg.Cache.Memory.TTL).To(Equal(5 * time.Minute))
			Expect(cfg.Cache.Memory.Shards).To(Equal(16))
			Expect(cfg.Cache.Redis.Addr).To(Equal(""))
			Expect(cfg.Cache.Redis.DB).To(Equal(0))
			Expect(cfg.Cache.Redis.TTL).To(Equal(10 * time.Minute))
			Expect(cfg.Cache.Redis.Prefix).To(Equal("ezauth::"))
		})
		It("explicit config values override struct tag defaults", func() {
			cfg := loadFromConfig("default_override.yaml")

			// ServerConfig — verify explicit values preserved, NOT defaults
			Expect(cfg.Server.ForceHTTPS).To(BeTrue())
			Expect(cfg.Server.Http2).To(BeTrue())
			Expect(cfg.Server.Hostname).To(Equal("custom.example.com"))
			Expect(cfg.Server.IdleTimeout).To(Equal(120))
			Expect(cfg.Server.WriteTimeout).To(Equal(600))
			Expect(cfg.Server.ReadTimeout).To(Equal(600))
			Expect(*cfg.Server.TrustForwardedHeaders).To(BeFalse())
			Expect(cfg.Server.StaticPrefix).To(Equal("/assets"))
			Expect(cfg.Server.AppName).To(Equal("my-app"))
			Expect(cfg.Server.HideAppName).To(BeTrue())
			Expect(cfg.Server.TLS.CertPath).To(Equal("/custom/cert.crt"))
			Expect(cfg.Server.TLS.KeyPath).To(Equal("/custom/key.pem"))
			Expect(cfg.Server.TLS.Version).To(Equal("TLS1.3"))
			Expect(cfg.Server.Pprof.Enabled).To(BeTrue())
			Expect(cfg.Server.Metrics.Enabled).To(BeTrue())
			Expect(cfg.Server.Metrics.Path).To(Equal("/custom/metrics"))
			Expect(cfg.Server.Metrics.Port).To(Equal(9095))
			Expect(cfg.Server.Metrics.Host).To(Equal("10.0.0.1"))
			Expect(cfg.Server.Portal.Enabled).To(BeTrue())

			// Auth/JWT
			Expect(cfg.Auth.JWT.SigningMethod).To(Equal("hs512"))
			Expect(cfg.Auth.JWT.KeyPath).To(Equal("/custom/jwt"))
			Expect(cfg.Auth.JWT.ExpireDuration).To(Equal(48 * time.Hour))

			// Session + Cookie
			Expect(cfg.Auth.Session.RefreshPeriod).To(Equal(30 * time.Minute))
			Expect(cfg.Auth.Session.Cookie.Minimal).To(BeTrue())
			Expect(cfg.Auth.Session.Cookie.Name).To(Equal("my_session"))
			Expect(cfg.Auth.Session.Cookie.Path).To(Equal("/app"))
			Expect(cfg.Auth.Session.Cookie.Expire).To(Equal(48 * time.Hour))
			Expect(cfg.Auth.Session.Cookie.Refresh).To(Equal(time.Hour))
			Expect(cfg.Auth.Session.Cookie.Secure).To(BeTrue())
			Expect(*cfg.Auth.Session.Cookie.HTTPOnly).To(BeFalse())
			Expect(cfg.Auth.Session.Cookie.SameSite).To(Equal("strict"))

			// CSRF
			Expect(cfg.Auth.Session.CSRF.Enabled).To(BeTrue())
			Expect(cfg.Auth.Session.CSRF.Name).To(Equal("my_csrf"))
			Expect(cfg.Auth.Session.CSRF.HeaderName).To(Equal("X-My-CSRF"))
			Expect(cfg.Auth.Session.CSRF.MaxAge).To(Equal(6 * time.Hour))

			// AuthProxyConfig
			Expect(cfg.Auth.Proxy.IsEnabled()).To(BeFalse())
			Expect(cfg.Auth.Proxy.JSONResponse).To(BeTrue())
			Expect(cfg.Auth.Proxy.ProxyPrefix).To(Equal("/proxy"))

			// LoginRateLimit
			Expect(cfg.Auth.LoginRateLimit.Enabled).To(BeTrue())
			Expect(cfg.Auth.LoginRateLimit.IPLimit).To(Equal(50))
			Expect(cfg.Auth.LoginRateLimit.UsernameLimit).To(Equal(10))
			Expect(cfg.Auth.LoginRateLimit.Window).To(Equal(2 * time.Minute))
			Expect(cfg.Auth.LoginRateLimit.BlockDuration).To(Equal(30 * time.Minute))
			Expect(cfg.Auth.LoginRateLimit.CountMode).To(Equal("all"))

			// OAuthRateLimit
			Expect(cfg.Auth.OAuthRateLimit.IPLimit).To(Equal(30))
			Expect(cfg.Auth.OAuthRateLimit.UsernameLimit).To(Equal(8))
			Expect(cfg.Auth.OAuthRateLimit.Window).To(Equal(3 * time.Minute))
			Expect(cfg.Auth.OAuthRateLimit.BlockDuration).To(Equal(45 * time.Minute))
			Expect(cfg.Auth.OAuthRateLimit.CountMode).To(Equal("all"))

			// OpaqueToken
			Expect(cfg.Auth.OpaqueToken.Prefix).To(Equal("custom_"))

			// ProviderCache
			Expect(cfg.Auth.ProviderCache.Size).To(Equal(100))
			Expect(cfg.Auth.ProviderCache.Shards).To(Equal(32))
			Expect(cfg.Auth.ProviderCache.RefreshInterval).To(Equal(5 * time.Minute))

			// AccessConfig
			Expect(cfg.Access.SystemAdminGroup).To(Equal("admin-group"))
			Expect(cfg.Access.RBAC.Enabled).To(BeTrue())
			Expect(cfg.Access.Bootstrap.SecretFile).To(Equal("/opt/secrets/root"))

			// AuditConfig
			Expect(*cfg.Audit.Enabled).To(BeFalse())
			Expect(cfg.Audit.BufferSize).To(Equal(1000))
			Expect(cfg.Audit.FlushInterval).To(Equal(10 * time.Minute))
			Expect(cfg.Audit.MaxFileSize).To(Equal(int64(1000000)))

			// StoreCacheConfig
			Expect(cfg.Cache.Memory.Size).To(Equal("500m"))
			Expect(cfg.Cache.Memory.TTL).To(Equal(10 * time.Minute))
			Expect(cfg.Cache.Memory.Shards).To(Equal(32))
			Expect(cfg.Cache.Redis.Addr).To(Equal("redis:6379"))
			Expect(cfg.Cache.Redis.DB).To(Equal(1))
			Expect(cfg.Cache.Redis.TTL).To(Equal(30 * time.Minute))
			Expect(cfg.Cache.Redis.Prefix).To(Equal("custom::"))

			// DatabaseConfig
			Expect(cfg.Database.SkipInit).To(BeTrue())
			Expect(cfg.Database.SSL.Mode).To(Equal("verify-full"))
		})
	})
})

var _ = Describe("ParseSize", func() {
	DescribeTable("valid sizes",
		func(input string, expected int64) {
			n, err := ParseSize(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(expected))
		},
		Entry("plain bytes", "1024", int64(1024)),
		Entry("kilobytes", "500k", int64(500_000)),
		Entry("megabytes", "200m", int64(200_000_000)),
		Entry("gigabytes", "1g", int64(1_000_000_000)),
		Entry("case-insensitive", "100M", int64(100_000_000)),
		Entry("trim whitespace", "  50m  ", int64(50_000_000)),
	)
	DescribeTable("invalid sizes",
		func(input string) {
			_, err := ParseSize(input)
			Expect(err).To(HaveOccurred())
		},
		Entry("empty string", ""),
		Entry("negative value", "-10m"),
		Entry("non-numeric", "abcm"),
	)
})
