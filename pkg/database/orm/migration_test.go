package orm_test

import (
	"github.com/flipcloud-ai/ezauth/pkg/database/orm"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Init", func() {
	DescribeTable("rejects invalid database names",
		func(dbname string) {
			err := orm.Init("postgres", dbname, "host=/nonexistent dbname=test", true)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid database name"))
		},
		Entry("hyphen in name", "my-app-db"),
		Entry("space in name", "my app"),
		Entry("leading digit", "1db"),
		Entry("SQL injection", "foo;DROP TABLE users;--"),
		Entry("special chars", "prod$dev"),
		Entry("empty string", ""),
	)

	It("rejects unsupported driver", func() {
		err := orm.Init("mysql", "testdb", "host=/nonexistent dbname=test", true)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unsupported database driver"))
	})

	DescribeTable("connStr without dbname fails at init connection",
		func(connStr string) {
			// connStr without dbname= cannot be rewritten to target postgres;
			// pgx defaults to user's own database which is unlikely to exist.
			err := orm.Init("postgres", "ezauth", connStr, true)
			Expect(err).To(HaveOccurred())
		},
		Entry("bootstrap-style connStr (no dbname)", "host=localhost user=postgres password=secret port=5432 sslmode=disable"),
		Entry("dbinit-style connStr (no dbname)", "host=localhost user=ezauth_admin password=secret port=5432 sslmode=disable"),
	)

	DescribeTable("connStr with dbname rewrites init connection to postgres",
		func(connStr string) {
			// With dbname= present, the regex replaces it with dbname=postgres
			// for the CREATE DATABASE step. The connection will fail (no real DB),
			// but the error confirms we hit the right code path.
			err := orm.Init("postgres", "ezauth", connStr, true)
			Expect(err).To(HaveOccurred())
			// Must not fail with "invalid database name" — that's tested above.
			Expect(err.Error()).ToNot(ContainSubstring("invalid database name"))
		},
		Entry("dbname at end", "host=localhost user=postgres password=secret port=5432 sslmode=disable dbname=ezauth"),
		Entry("dbname at start", "dbname=ezauth host=localhost user=postgres password=secret"),
		Entry("dbname in middle", "host=localhost dbname=ezauth user=postgres password=secret"),
	)
})

var _ = Describe("ValidateDBName", func() {
	DescribeTable("validates database name pattern",
		func(dbname string, expectErr bool) {
			err := orm.ValidateDBName(dbname)
			if expectErr {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("must match"))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		},
		Entry("valid normal name", "myapp_db", false),
		Entry("valid single char", "a", false),
		Entry("valid with digits", "db_2024_v2", false),
		Entry("valid underscore start", "_test", false),
		Entry("max length boundary (63 chars)", "a"+repeat("b", 62), false),
		Entry("invalid hyphen", "my-app-db", true),
		Entry("invalid space", "my app", true),
		Entry("invalid leading digit", "1db", true),
		Entry("invalid SQL injection", "foo;DROP TABLE users;--", true),
		Entry("invalid special chars", "prod$dev", true),
		Entry("invalid empty", "", true),
		Entry("exceeds max length (64 chars)", "a"+repeat("b", 63), true),
	)
})

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
