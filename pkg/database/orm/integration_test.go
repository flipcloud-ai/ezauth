//go:build integration

package orm

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

var ormTestGormDB *gorm.DB
var ormCleanup func()
var ormContainer *tcpostgres.PostgresContainer

var _ = BeforeSuite(func() {
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, "postgres:15-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
	)
	if err != nil {
		Skip("PostgreSQL container not available: " + err.Error())
		return
	}

	connStr, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pg.Terminate(ctx)
		Skip("Failed to get connection string: " + err.Error())
		return
	}

	ormContainer = pg
	ormCleanup = func() { _ = pg.Terminate(ctx) }

	for i := 0; i < 20; i++ {
		db, err := gorm.Open(postgres.New(postgres.Config{
			DriverName:           "pgx",
			DSN:                  connStr,
			PreferSimpleProtocol: false,
		}), &gorm.Config{TranslateError: true})
		if err == nil {
			sqlDB, _ := db.DB()
			if sqlDB.Ping() == nil {
				ormTestGormDB = db
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	Expect(ormTestGormDB).ToNot(BeNil())

	ezlog.NewLogger(ctx, config.LogConfig{}, GinkgoWriter, GinkgoWriter)
})

var _ = AfterSuite(func() {
	if ormCleanup != nil {
		ormCleanup()
	}
})

var _ = Describe("orm package (integration)", func() {
	It("Init creates database and migrates", func() {
		ctx := context.Background()
		host, err := ormContainer.Host(ctx)
		Expect(err).ToNot(HaveOccurred())
		port, err := ormContainer.MappedPort(ctx, "5432")
		Expect(err).ToNot(HaveOccurred())

		_ = ormTestGormDB.Exec("DROP DATABASE IF EXISTS orm_init_test WITH (FORCE)")

		connStr := fmt.Sprintf("host=%s port=%s user=postgres password=postgres dbname=orm_init_test sslmode=disable",
			host, port.Port())
		err = Init("pgx", "orm_init_test", connStr)
		Expect(err).ToNot(HaveOccurred())

		Expect(ormTestGormDB.Exec("DROP DATABASE IF EXISTS orm_init_test WITH (FORCE)").Error).To(Succeed())
	})

	It("Migrate with DropUnusedColumns enabled runs without error", func() {
		logger, _ := testutils.SetupTestLogger()
		d := &ezdb.Database{DB: ormTestGormDB.Session(&gorm.Session{}), Logger: logger, DropUnusedColumns: true}

		Expect(d.Migrate(context.Background())).To(Succeed())
	})

	It("creates join table indexes and FK constraint, idempotent", func() {
		d := &ezdb.Database{DB: ormTestGormDB.Session(&gorm.Session{}), Logger: nil}
		Expect(d.Migrate(context.Background())).To(Succeed())

		expected := []string{
			"idx_user_roles_role",
			"idx_group_roles_role",
			"idx_group_roles_group",
			"idx_user_groups_group",
			"idx_policy_roles_role",
			"idx_policy_roles_policy",
		}
		for _, name := range expected {
			var exists bool
			err := d.Raw("SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = ?)", name).Scan(&exists).Error
			Expect(err).ToNot(HaveOccurred())
			Expect(exists).To(BeTrue(), "index %s should exist", name)
		}

		// FK constraint on pat_tokens.user_id — ON DELETE CASCADE.
		var fkExists bool
		err := d.Raw(`SELECT EXISTS(
			SELECT 1 FROM pg_constraint WHERE conname = 'fk_pat_tokens_user'
		)`).Scan(&fkExists).Error
		Expect(err).ToNot(HaveOccurred())
		Expect(fkExists).To(BeTrue())

		// Second Migrate must not fail (idempotent).
		Expect(d.Migrate(context.Background())).To(Succeed())
	})
})
