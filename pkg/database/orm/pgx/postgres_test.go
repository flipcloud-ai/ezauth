package pgx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"gorm.io/gorm"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/DATA-DOG/go-sqlmock"
	"moul.io/zapgorm2"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

// ============== Helpers ==============

func newMockPGxDB() (*PGxDB, sqlmock.Sqlmock) {
	gormDB, mock, err := testutils.MockSQLPool()
	Expect(err).ToNot(HaveOccurred())
	gormDB.SkipDefaultTransaction = true
	logger, _ := testutils.SetupTestLogger()
	gormDB.Logger = zapgorm2.New(logger.Zap())
	db := &PGxDB{Database: ezdb.Database{Logger: logger}}
	db.DB = gormDB
	return db, mock
}

// base config for testing
func baseConfig() config.DatabaseConfig {
	return config.DatabaseConfig{
		Hostname: "localhost",
		Port:     5432,
		User:     "postgres",
		Password: config.NewResolvedSecretRef([]byte("password")),
		Name:     "testdb",
		SSL:      config.DatabaseTLSConfig{Mode: "disable"},
	}
}

// validate connection string using pgxpool
func validateConnString(cfg config.DatabaseConfig) {
	result := ConnString(cfg)
	poolConfig, err := pgxpool.ParseConfig(result)
	Expect(err).ToNot(HaveOccurred())
	Expect(poolConfig).ToNot(BeNil())
}

// testDBConfig returns config for PostgreSQL testing
func testDBConfig() config.DatabaseConfig {
	return config.DatabaseConfig{
		Hostname:        getTestDBHost(),
		Port:            5432,
		User:            "postgres",
		Password:        config.NewResolvedSecretRef([]byte("postgres")),
		Name:            "postgres",
		SSL:             config.DatabaseTLSConfig{Mode: "disable"},
		MaxConns:        10,
		MinConns:        1,
		MaxConnLifetime: 1 * time.Hour,
		ConnectTimeout:  5 * time.Second,
	}
}

func getTestDBHost() string {
	if host := os.Getenv("TEST_PG_HOST"); host != "" {
		return host
	}
	return "localhost"
}

// ============== Tests ==============

var _ = Describe("postgres connection", func() {
	var db *PGxDB
	var dbConfig config.DatabaseConfig

	BeforeEach(func() {
		dbConfig = testDBConfig()
	})

	AfterEach(func() {
		if db != nil && db.DB != nil {
			sqlDB, _ := db.DB.DB()
			if sqlDB != nil {
				_ = sqlDB.Close()
			}
		}
	})

	Describe("connString", func() {
		DescribeTable("basic config",
			func(cfg config.DatabaseConfig) {
				validateConnString(cfg)
			},
			Entry("SSL disabled", baseConfig()),
			Entry("SSL require", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.Hostname = "db.example.com"
				cfg.User = "admin"
				cfg.Password = config.NewResolvedSecretRef([]byte("secret"))
				cfg.Name = "production"
				cfg.SSL.Mode = "require"
				return cfg
			}()),
		)

		DescribeTable("connection pool settings",
			func(cfg config.DatabaseConfig, check func(*pgxpool.Config)) {
				result := ConnString(cfg)
				poolConfig, err := pgxpool.ParseConfig(result)
				Expect(err).ToNot(HaveOccurred())
				check(poolConfig)
			},
			Entry("max connections", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.MaxConns = 50
				return cfg
			}(), func(poolConfig *pgxpool.Config) {
				Expect(poolConfig.MaxConns).To(Equal(int32(50)))
			}),
			Entry("min connections", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.MinConns = 5
				return cfg
			}(), func(poolConfig *pgxpool.Config) {
				Expect(poolConfig.MinConns).To(Equal(int32(5)))
			}),
			Entry("max connection lifetime", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.MaxConnLifetime = 30 * time.Minute
				return cfg
			}(), func(poolConfig *pgxpool.Config) {
				Expect(poolConfig.MaxConnLifetime).To(Equal(30 * time.Minute))
			}),
			Entry("max connection idle time", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.MaxConnIdleTime = 10 * time.Minute
				return cfg
			}(), func(poolConfig *pgxpool.Config) {
				Expect(poolConfig.MaxConnIdleTime).To(Equal(10 * time.Minute))
			}),
			Entry("health check period", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.HealthCheckPeriod = 15 * time.Second
				return cfg
			}(), func(poolConfig *pgxpool.Config) {
				Expect(poolConfig.HealthCheckPeriod).To(Equal(15 * time.Second))
			}),
			Entry("max connection lifetime jitter", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.MaxConnLifetimeJitter = 5 * time.Minute
				return cfg
			}(), func(poolConfig *pgxpool.Config) {
				Expect(poolConfig.MaxConnLifetimeJitter).To(Equal(5 * time.Minute))
			}),
			Entry("all pool settings combined", func() config.DatabaseConfig {
				cfg := baseConfig()
				cfg.MaxConns = 100
				cfg.MinConns = 10
				cfg.MaxConnLifetime = 1 * time.Hour
				cfg.MaxConnIdleTime = 20 * time.Minute
				cfg.HealthCheckPeriod = 30 * time.Second
				cfg.MaxConnLifetimeJitter = 10 * time.Minute
				return cfg
			}(), func(poolConfig *pgxpool.Config) {
				Expect(poolConfig.MaxConns).To(Equal(int32(100)))
				Expect(poolConfig.MinConns).To(Equal(int32(10)))
				Expect(poolConfig.MaxConnLifetime).To(Equal(1 * time.Hour))
				Expect(poolConfig.MaxConnIdleTime).To(Equal(20 * time.Minute))
				Expect(poolConfig.HealthCheckPeriod).To(Equal(30 * time.Second))
				Expect(poolConfig.MaxConnLifetimeJitter).To(Equal(10 * time.Minute))
			}),
		)

		Describe("SSL with certificates", func() {
			var caCertPath, clientCertPath, clientKeyPath string

			BeforeEach(func() {
				caCertPath, clientCertPath, clientKeyPath = testutils.CreateTestCertificates()
			})

			DescribeTable("SSL modes",
				func(cfg config.DatabaseConfig) {
					validateConnString(cfg)
				},
				Entry("verify-ca with root cert", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.SSL.Mode = "verify-ca"
					cfg.SSL.RootCert = caCertPath
					return cfg
				}()),
				Entry("verify-full with root cert", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.SSL.Mode = "verify-full"
					cfg.SSL.RootCert = caCertPath
					return cfg
				}()),
				Entry("verify-full with client certificate", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.Hostname = "secure.example.com"
					cfg.User = "admin"
					cfg.Password = config.NewResolvedSecretRef([]byte("secret"))
					cfg.Name = "production"
					cfg.SSL.Mode = "verify-full"
					cfg.SSL.RootCert = caCertPath
					cfg.SSL.Cert = clientCertPath
					cfg.SSL.Key = clientKeyPath
					return cfg
				}()),
			)
		})

		Describe("connection string format", func() {
			It("should join fields with space", func() {
				result := ConnString(baseConfig())
				Expect(result).To(MatchRegexp(`\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+`))
			})

			It("should not have trailing spaces", func() {
				result := ConnString(baseConfig())
				Expect(result).ToNot(HaveSuffix(" "))
			})

			It("should not have duplicate spaces", func() {
				result := ConnString(baseConfig())
				Expect(result).ToNot(MatchRegexp(`\s{2,}`))
			})
		})
	})

	Describe("Escaping", func() {
		It("escapes password with spaces", func() {
			cfg := baseConfig()
			cfg.Password = config.NewResolvedSecretRef([]byte("pass word"))
			result := ConnString(cfg)
			_, err := pgxpool.ParseConfig(result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(ContainSubstring("password='pass word'"))
		})
		It("escapes password with backslash", func() {
			cfg := baseConfig()
			cfg.Password = config.NewResolvedSecretRef([]byte("pass\\word"))
			result := ConnString(cfg)
			_, err := pgxpool.ParseConfig(result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(ContainSubstring("password='pass\\\\word'"))
		})
		It("escapes password with single quote", func() {
			cfg := baseConfig()
			cfg.Password = config.NewResolvedSecretRef([]byte("pass'word"))
			result := ConnString(cfg)
			_, err := pgxpool.ParseConfig(result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(ContainSubstring("password='pass\\'word'"))
		})
		It("passes plain password through unchanged", func() {
			cfg := baseConfig()
			cfg.Password = config.NewResolvedSecretRef([]byte("plainpass"))
			result := ConnString(cfg)
			_, err := pgxpool.ParseConfig(result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(ContainSubstring("password=plainpass"))
		})
	})

	Describe("PGxPool", func() {
		Describe("connection", func() {
			It("should return error for invalid connection", func() {
				invalidConfig := dbConfig
				invalidConfig.Hostname = "invalid-host-that-does-not-exist"
				invalidConfig.Name = "nonexistent"
				invalidConfig.ConnectTimeout = 1 * time.Second
				ctx := context.Background()
				ctx = ezlog.ServerContext(ctx, ezlog.NewNop())
				db, err := PGxPool(ctx, invalidConfig)
				Expect(err).To(HaveOccurred())
				Expect(db).To(BeNil())
			})
		})

		Describe("error handling", func() {
			DescribeTable("config validation errors",
				func(cfg config.DatabaseConfig) {
					ctx := context.Background()
					ctx = ezlog.ServerContext(ctx, ezlog.NewNop())
					db, err := PGxPool(ctx, cfg)
					Expect(err).To(HaveOccurred())
					Expect(db).To(BeNil())
				},
				Entry("invalid port", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.Port = -1
					return cfg
				}()),
				Entry("empty hostname", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.Hostname = ""
					return cfg
				}()),
				Entry("invalid SSL mode", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.SSL.Mode = "invalid-ssl-mode"
					return cfg
				}()),
				Entry("invalid SSL certificate path", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.SSL.Mode = "verify-ca"
					cfg.SSL.RootCert = "/nonexistent/path/to/cert.pem"
					return cfg
				}()),
				Entry("invalid SSL key path", func() config.DatabaseConfig {
					cfg := baseConfig()
					cfg.SSL.Mode = "verify-full"
					cfg.SSL.Cert = "/nonexistent/path/to/cert.pem"
					cfg.SSL.Key = "/nonexistent/path/to/key.pem"
					return cfg
				}()),
			)

			DescribeTable("runtime errors (using gomonkey)",
				func(cfg config.DatabaseConfig, mockErr error, expectErr string) {
					// Patch pgxpool.NewWithConfig to return error
					patch := gomonkey.ApplyFunc(pgxpool.NewWithConfig,
						func(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
							return nil, mockErr
						})
					defer patch.Reset()

					ctx := context.Background()
					ctx = ezlog.ServerContext(ctx, ezlog.NewNop())
					_, err := PGxPool(ctx, cfg)
					Expect(err).To(HaveOccurred())
					if expectErr != "" {
						Expect(err.Error()).To(Equal(expectErr))
					}
				},
				Entry("non-existent database", func() config.DatabaseConfig {
					cfg := testDBConfig()
					cfg.Name = "this-database-does-not-exist-12345"
					return cfg
				}(), errors.New("database does not exist"), "database does not exist"),
				Entry("invalid credentials", func() config.DatabaseConfig {
					cfg := testDBConfig()
					cfg.User = "invaliduser"
					cfg.Password = config.NewResolvedSecretRef([]byte("invalidpassword"))
					return cfg
				}(), errors.New("invalid username or password"), "invalid username or password"),
			)

			It("returns error when database does not exist", func() {
				cfg := testDBConfig()
				cfg.Name = "nonexistent"
				// Patch pgxpool.NewWithConfig to return error
				patch := gomonkey.ApplyFunc(pgxpool.NewWithConfig,
					func(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
						return nil, nil
					})
				defer patch.Reset()
				gormPatch := gomonkey.ApplyFunc(gorm.Open,
					func(dialector gorm.Dialector, opts ...gorm.Option) (*gorm.DB, error) {
						err1 := &pgconn.PgError{Message: "database does not exist", Code: "3D000"}
						err2 := fmt.Errorf("error2: [%w]", err1)
						return nil, err2
					})
				defer gormPatch.Reset()
				ctx := context.Background()
				ctx = ezlog.ServerContext(ctx, ezlog.NewNop())
				_, err := PGxPool(ctx, cfg)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("database does not exist"))
			})
		})
	})
})
var _ = Describe("txErrorToDBError", func() {
	It("returns a DatabaseErr for validation error", func() {
		err := txErrorToDBError(fmt.Errorf("validation error: invalid group name"))
		_, ok := err.(*ezdb.DatabaseErr)
		Expect(ok).To(BeTrue())
	})

	It("returns ErrConflict for duplicated key", func() {
		err := txErrorToDBError(gorm.ErrDuplicatedKey)
		Expect(err).To(Equal(ezdb.ErrConflict))
	})

	It("returns ErrOperation for unknown errors", func() {
		err := txErrorToDBError(fmt.Errorf("some random db error"))
		Expect(err).To(Equal(ezdb.ErrOperation))
	})
})
