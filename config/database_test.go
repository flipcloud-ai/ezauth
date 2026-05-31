package config

import (
	"github.com/spf13/cobra"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Database Config Test Suite", func() {
	Context("Database Config Parsing", func() {
		It("database config check", func(ctx SpecContext) {
			cmd := &cobra.Command{
				Use: "test",
				RunE: func(cmd *cobra.Command, args []string) error {
					cfg, err := LoadConfiguration(cmd)
					Expect(err).To(BeNil())
					Expect(cfg.Database.Driver).To(Equal(""))
					Expect(cfg.Database.Hostname).To(Equal("localhost"))
					Expect(cfg.Database.Port).To(Equal(5432))
					Expect(cfg.Database.SSL.Mode).To(Equal("disable"))
					Expect(cfg.Database.ConnectTimeout.Seconds()).To(Equal(float64(5)))
					Expect(cfg.Database.SSL.Cert).To(Equal(""))
					Expect(cfg.Database.SSL.Key).To(Equal(""))
					Expect(cfg.Database.SSL.Password).To(Equal(""))
					Expect(cfg.Database.SSL.RootCert).To(Equal(""))
					Expect(cfg.Database.SSL.SNI).To(Equal(""))
					Expect(cfg.Database.SSL.NegotiateTLS).To(Equal(""))
					Expect(cfg.Database.Name).To(Equal("ezauth"))
					Expect(cfg.Database.User).To(Equal(""))
					Expect(cfg.Database.Password.String()).To(Equal(""))
					Expect(cfg.Database.MaxConnLifetime).To(BeZero())
					Expect(cfg.Database.MaxConnLifetimeJitter).To(BeZero())
					Expect(cfg.Database.MaxConnIdleTime).To(BeZero())
					Expect(cfg.Database.PingTimeout).To(BeZero())
					Expect(cfg.Database.MaxConns).To(BeZero())
					Expect(cfg.Database.MinConns).To(BeZero())
					Expect(cfg.Database.MinIdleConns).To(BeZero())
					Expect(cfg.Database.HealthCheckPeriod).To(BeZero())
					return err
				},
			}
			AddDBFlags(cmd)
			cmd.SetArgs([]string{})
			Expect(cmd.Execute()).To(Succeed())
		})
		It("database config check with parameters", func(ctx SpecContext) {
			cmd := &cobra.Command{
				Use: "test",
				RunE: func(cmd *cobra.Command, args []string) error {
					cfg, err := LoadConfiguration(cmd)
					Expect(err).To(BeNil())
					Expect(cfg.Database.Driver).To(Equal("postgres"))
					Expect(cfg.Database.Hostname).To(Equal("test.db.com"))
					Expect(cfg.Database.Port).To(Equal(2345))
					Expect(cfg.Database.SSL.Mode).To(Equal("verify-ca"))
					Expect(cfg.Database.ConnectTimeout.Seconds()).To(Equal(float64(10)))
					Expect(cfg.Database.Name).To(Equal("randomcloud"))
					Expect(cfg.Database.User).To(Equal("testuser"))
					Expect(cfg.Database.Password.String()).To(Equal("123456"))
					return err
				},
			}
			AddDBFlags(cmd)
			cmd.SetArgs([]string{
				"--database-host", "test.db.com",
				"--database-port", "2345",
				"--database-ssl-mode", "verify-ca",
				"--database-connect-timeout", "10s",
				"--database-name", "randomcloud",
				"--database-user", "testuser",
				"--database-driver", "postgres",
				"--database-password", "123456",
			})
			Expect(cmd.Execute()).To(Succeed())
		})
	})
})
