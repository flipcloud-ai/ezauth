package orm_test

import (
	"context"

	"github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var testDBConfig = config.DatabaseConfig{
	Hostname: "localhost",
	Port:     5432,
	User:     "testuser",
	Password: config.NewResolvedSecretRef([]byte("testpass")),
	Name:     "testdb",
	Driver:   "pgx",
	SSL:      config.DatabaseTLSConfig{Mode: "disable"},
}

var _ = Describe("DSN", func() {
	DescribeTable("should return a valid connection string",
		func(driver string) {
			cfg := testDBConfig
			cfg.Driver = driver

			result := orm.DSN(cfg)
			Expect(result).ToNot(BeEmpty())
			Expect(result).To(ContainSubstring("host=localhost"))
			Expect(result).To(ContainSubstring("port=5432"))
			Expect(result).To(ContainSubstring("user=testuser"))
			Expect(result).To(ContainSubstring("password=testpass"))
			Expect(result).To(ContainSubstring("dbname=testdb"))
			Expect(result).To(ContainSubstring("sslmode=disable"))
		},
		Entry("pgx driver", "pgx"),
		Entry("postgres driver", "postgres"),
		Entry("postgresql driver", "postgresql"),
	)

	It("should return empty string for an unsupported driver", func() {
		cfg := testDBConfig
		cfg.Driver = "mysql"

		result := orm.DSN(cfg)
		Expect(result).To(BeEmpty())
	})
})

var _ = Describe("NewDB", func() {
	It("should return an error for an invalid database name", func() {
		cfg := testDBConfig
		cfg.Name = "invalid-db-name-with-hyphen"

		_, err := orm.NewDB(context.Background(), cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid database name"))
	})

	It("should return an error for an unsupported driver", func() {
		cfg := testDBConfig
		cfg.Driver = "sqlite"

		_, err := orm.NewDB(context.Background(), cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unsupported database driver"))
	})

	It("should return an error for an empty database name", func() {
		cfg := testDBConfig
		cfg.Name = ""

		_, err := orm.NewDB(context.Background(), cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid database name"))
	})

})
