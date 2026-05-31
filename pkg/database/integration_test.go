//go:build integration

package database_test

import (
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"moul.io/zapgorm2"

	"github.com/flipcloud-ai/ezauth/pkg/database"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

var _ = Describe("DropUnusedColumns (integration)", func() {
	type dropTestModel struct {
		ID   uint   `gorm:"primaryKey"`
		Name string `gorm:"size:64"`
	}

	var (
		gormDB  *gorm.DB
		d       *database.Database
		cleanup func()
	)

	BeforeEach(func() {
		dsn, c := testutils.NewPostgresContainer()
		cleanup = c

		var err error
		gormDB, err = gorm.Open(postgres.New(postgres.Config{
			DriverName:           "pgx",
			DSN:                  dsn,
			PreferSimpleProtocol: false,
		}), &gorm.Config{
			TranslateError: true,
			NowFunc:        func() time.Time { return time.Now().UTC() },
		})
		Expect(err).ToNot(HaveOccurred())

		logger, _ := testutils.SetupTestLogger()
		gormDB.Logger = zapgorm2.New(logger.Zap())

		d = &database.Database{DB: gormDB, Logger: logger}
		Expect(d.AutoMigrate(&dropTestModel{})).To(Succeed())
	})

	AfterEach(func() {
		if cleanup != nil {
			cleanup()
		}
	})

	It("drops columns not present in the struct", func() {
		Expect(gormDB.Exec("ALTER TABLE drop_test_models ADD COLUMN IF NOT EXISTS orphan_col VARCHAR(32)").Error).To(Succeed())

		cols, err := gormDB.Migrator().ColumnTypes(&dropTestModel{})
		Expect(err).ToNot(HaveOccurred())
		Expect(cols).To(ContainElement(WithTransform(func(c gorm.ColumnType) string { return c.Name() }, Equal("orphan_col"))))

		d.DropUnusedTableColumns(&dropTestModel{})

		cols, err = gormDB.Migrator().ColumnTypes(&dropTestModel{})
		Expect(err).ToNot(HaveOccurred())
		for _, c := range cols {
			Expect(c.Name()).ToNot(Equal("orphan_col"))
		}
	})

	It("is a no-op when no orphaned columns exist", func() {
		Expect(func() { d.DropUnusedTableColumns(&dropTestModel{}) }).ToNot(Panic())

		cols, err := gormDB.Migrator().ColumnTypes(&dropTestModel{})
		Expect(err).ToNot(HaveOccurred())
		Expect(cols).To(HaveLen(2))
	})
})
