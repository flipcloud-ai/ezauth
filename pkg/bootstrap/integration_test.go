//go:build integration

package bootstrap

import (
	"context"
	"net/url"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

var (
	pgHost    string
	pgPort    int
	pgCleanup func()
)

func mustDB(ctx context.Context) database.DatabaseInterface {
	db, err := orm.NewDB(ctx, ezcfg.DatabaseConfig{
		Driver:   "pgx",
		Hostname: pgHost,
		Port:     pgPort,
		Name:     "ezauth",
		User:     "postgres",
		Password: ezcfg.NewResolvedSecretRef([]byte("password")),
		SSL:      ezcfg.DatabaseTLSConfig{Mode: "disable"},
	})
	ExpectWithOffset(1, err).ToNot(HaveOccurred())
	return db
}

func tryDB(ctx context.Context) (database.DatabaseInterface, error) {
	return orm.NewDB(ctx, ezcfg.DatabaseConfig{
		Driver:   "pgx",
		Hostname: pgHost,
		Port:     pgPort,
		Name:     "ezauth",
		User:     "postgres",
		Password: ezcfg.NewResolvedSecretRef([]byte("password")),
		SSL:      ezcfg.DatabaseTLSConfig{Mode: "disable"},
	})
}

var _ = BeforeSuite(func() {
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:15",
		postgres.WithDatabase("ezauth"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("password"),
	)
	if err != nil {
		Skip("PostgreSQL container not available: " + err.Error())
	}

	cs, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		Skip("connection string: " + err.Error())
	}

	h, p := hostPortFromDSN(cs)
	pgHost = h
	pgPort = p
	pgCleanup = func() { _ = pg.Terminate(context.Background()) }

	Eventually(func() error {
		db, err := tryDB(ctx)
		if err != nil {
			return err
		}
		sqlDB, dbErr := db.Manager().DB()
		if dbErr != nil {
			return dbErr
		}
		defer sqlDB.Close()
		return sqlDB.PingContext(ctx)
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())

	_ = orm.Init("pgx", "ezauth", cs)
})

var _ = AfterSuite(func() {
	if pgCleanup != nil {
		pgCleanup()
	}
})

var _ = BeforeEach(func(ctx SpecContext) {
	// Truncate tables for isolation between specs.
	db := mustDB(ctx)
	db.Manager().WithContext(ctx).Exec("DELETE FROM user_groups")
	db.Manager().WithContext(ctx).Exec("DELETE FROM users")
	db.Manager().WithContext(ctx).Exec("DELETE FROM groups")
})

var _ = Describe("Bootstrap integration", func() {
	Describe("Bootstrap", func() {
		It("creates root user and system admin group on first run", func(ctx SpecContext) {
			db := mustDB(ctx)
			logger, _ := testutils.SetupTestLogger()

			Bootstrap(ctx, db, logger, Config{
				SystemAdminGroup: "system-admins",
				SecretFile:       GinkgoT().TempDir() + "/root_secret",
			})

			var user models.UserDB
			err := db.Manager().WithContext(ctx).Where("username = ?", "root").First(&user).Error
			Expect(err).ToNot(HaveOccurred())
			Expect(user.Username).To(Equal("root"))
			Expect(user.Active).To(BeTrue())

			var group models.GroupDB
			err = db.Manager().WithContext(ctx).Where("name = ?", "system-admins").First(&group).Error
			Expect(err).ToNot(HaveOccurred())

			err = db.Manager().WithContext(ctx).
				Preload("Users", "id = ?", user.ID).
				Where("name = ?", "system-admins").
				First(&group).Error
			Expect(err).ToNot(HaveOccurred())
			Expect(group.Users).To(HaveLen(1))
			Expect(group.Users[0].ID).To(Equal(user.ID))
		})

		It("is idempotent", func(ctx SpecContext) {
			db := mustDB(ctx)
			logger, _ := testutils.SetupTestLogger()

			cfg := Config{SystemAdminGroup: "system-admins", SecretFile: GinkgoT().TempDir() + "/root_secret"}
			Bootstrap(ctx, db, logger, cfg)
			Bootstrap(ctx, db, logger, cfg)

			var count int64
			db.Manager().WithContext(ctx).Model(&models.UserDB{}).
				Where("username = ?", "root").Count(&count)
			Expect(count).To(Equal(int64(1)))

			db.Manager().WithContext(ctx).Model(&models.GroupDB{}).
				Where("name = ?", "system-admins").Count(&count)
			Expect(count).To(Equal(int64(1)))
		})
	})

	Describe("ensureRootUser", func() {
		It("creates root user when it does not exist", func(ctx SpecContext) {
			db := mustDB(ctx)
			userID, created, err := ensureRootUser(ctx, db, "root", "TestPass1")
			Expect(err).ToNot(HaveOccurred())
			Expect(created).To(BeTrue())
			Expect(userID).ToNot(BeEmpty())

			var user models.UserDB
			err = db.Manager().WithContext(ctx).Where("id = ?", userID).First(&user).Error
			Expect(err).ToNot(HaveOccurred())
			Expect(user.Username).To(Equal("root"))
			Expect(user.Active).To(BeTrue())
		})

		It("returns existing user ID when root already exists", func(ctx SpecContext) {
			db := mustDB(ctx)
			userID1, created, err := ensureRootUser(ctx, db, "root", "ValidPass2")
			Expect(err).ToNot(HaveOccurred())
			Expect(created).To(BeTrue())

			userID2, created, err := ensureRootUser(ctx, db, "root", "ValidPass2")
			Expect(err).ToNot(HaveOccurred())
			Expect(created).To(BeFalse())
			Expect(userID2).To(Equal(userID1))
		})
	})

	Describe("ensureSystemAdminGroup", func() {
		It("creates group when it does not exist", func(ctx SpecContext) {
			db := mustDB(ctx)
			created, err := ensureSystemAdminGroup(ctx, db, "system-admins")
			Expect(err).ToNot(HaveOccurred())
			Expect(created).To(BeTrue())

			var group models.GroupDB
			err = db.Manager().WithContext(ctx).Where("name = ?", "system-admins").First(&group).Error
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns false when group already exists", func(ctx SpecContext) {
			db := mustDB(ctx)
			_, err := ensureSystemAdminGroup(ctx, db, "system-admins")
			Expect(err).ToNot(HaveOccurred())

			created, err := ensureSystemAdminGroup(ctx, db, "system-admins")
			Expect(err).ToNot(HaveOccurred())
			Expect(created).To(BeFalse())
		})
	})

	Describe("ensureGroupMembership", func() {
		It("adds user to group when not already a member", func(ctx SpecContext) {
			db := mustDB(ctx)
			userID, _, err := ensureRootUser(ctx, db, "root", "ValidPass3")
			Expect(err).ToNot(HaveOccurred())
			_, err = ensureSystemAdminGroup(ctx, db, "system-admins")
			Expect(err).ToNot(HaveOccurred())

			logger, _ := testutils.SetupTestLogger()
			err = ensureGroupMembership(ctx, db, logger, "system-admins", userID)
			Expect(err).ToNot(HaveOccurred())

			var group models.GroupDB
			err = db.Manager().WithContext(ctx).
				Preload("Users", "id = ?", userID).
				Where("name = ?", "system-admins").
				First(&group).Error
			Expect(err).ToNot(HaveOccurred())
			Expect(group.Users).To(HaveLen(1))
		})

		It("is idempotent when user is already in group", func(ctx SpecContext) {
			db := mustDB(ctx)
			userID, _, err := ensureRootUser(ctx, db, "root", "ValidPass3")
			Expect(err).ToNot(HaveOccurred())
			_, err = ensureSystemAdminGroup(ctx, db, "system-admins")
			Expect(err).ToNot(HaveOccurred())

			logger, _ := testutils.SetupTestLogger()
			Expect(ensureGroupMembership(ctx, db, logger, "system-admins", userID)).To(Succeed())
			Expect(ensureGroupMembership(ctx, db, logger, "system-admins", userID)).To(Succeed())

			var group models.GroupDB
			err = db.Manager().WithContext(ctx).
				Preload("Users", "id = ?", userID).
				Where("name = ?", "system-admins").
				First(&group).Error
			Expect(err).ToNot(HaveOccurred())
			Expect(group.Users).To(HaveLen(1))
		})
	})
})

func hostPortFromDSN(dsn string) (host string, port int) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "localhost", 5432
	}
	host = u.Hostname()
	port = 5432
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	return
}
