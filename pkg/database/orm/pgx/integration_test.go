//go:build integration

package pgx

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"moul.io/zapgorm2"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

// ============================================================================
// Infrastructure
// ============================================================================

var pgxGormDB *gorm.DB
var pgContainerCleanup func()
var pgContainer *tcpostgres.PostgresContainer

var _ = BeforeSuite(func() {
	ctx := context.Background()

	connStr, cleanup := newPostgresContainer()
	pgContainerCleanup = cleanup

	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		DriverName:           "pgx",
		DSN:                  connStr,
		PreferSimpleProtocol: false,
	}), &gorm.Config{TranslateError: true})
	Expect(err).ToNot(HaveOccurred())

	logger, _ := testutils.SetupTestLogger()
	gormDB.Logger = zapgorm2.New(logger.Zap())

	err = gormDB.AutoMigrate(
		&models.UserDB{},
		&models.GroupDB{},
		&models.ProviderDB{},
		&models.Permission{},
		&models.Policy{},
		&models.RoleDB{},
		&models.PATDB{},
		&models.AuditEventDB{},
	)
	Expect(err).ToNot(HaveOccurred())

	pgxGormDB = gormDB
	ezlog.NewLogger(ctx, config.LogConfig{}, GinkgoWriter, GinkgoWriter)
})

var _ = AfterSuite(func() {
	if pgContainerCleanup != nil {
		pgContainerCleanup()
	}
})

var _ = BeforeEach(func() {
	tables := []string{
		"audit_events", "pat_tokens",
		"user_roles", "user_groups", "group_roles",
		"policy_roles", "policy_permissions",
		"rbac_permissions", "rbac_policies", "roles",
		"users", "groups", "providers",
	}
	for _, t := range tables {
		Expect(pgxGormDB.Exec("DELETE FROM " + t).Error).To(Succeed())
	}
})

func newTestPGxDB() *PGxDB {
	logger, _ := testutils.SetupTestLogger()
	return &PGxDB{
		Database: ezdb.Database{
			DB:     pgxGormDB.Session(&gorm.Session{}),
			Logger: logger,
		},
	}
}

func newPostgresContainer() (string, func()) {
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, "postgres:15-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
	)
	if err != nil {
		Skip("PostgreSQL container not available: " + err.Error())
		return "", func() {}
	}

	connStr, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pg.Terminate(ctx)
		Skip("Failed to get connection string: " + err.Error())
		return "", func() {}
	}

	pgContainer = pg
	cleanup := func() { _ = pg.Terminate(ctx) }

	for i := 0; i < 20; i++ {
		db, err := sql.Open("pgx", connStr)
		if err == nil {
			if err := db.Ping(); err == nil {
				db.Close()
				return connStr, cleanup
			}
			db.Close()
		}
		time.Sleep(2 * time.Second)
	}

	cleanup()
	Skip("PostgreSQL not ready after 40 seconds")
	return "", func() {}
}

// ============================================================================
// Seed helpers
// ============================================================================

func seedPerm(db *PGxDB, name, service, action, method, path string) {
	Expect(db.AddPermission(context.Background(), &models.Permission{
		Name: name, Service: service, Action: action, Method: method, Path: path, Effect: true,
	})).To(Succeed())
}

func seedPolicy(db *PGxDB, name string, permNames ...string) {
	perms := make([]*models.Permission, len(permNames))
	for i, n := range permNames {
		perms[i] = &models.Permission{Name: n}
	}
	Expect(db.AddPolicy(context.Background(), &models.Policy{Name: name, Permission: perms})).To(Succeed())
}

func seedRole(db *PGxDB, name string, policyNames ...string) {
	policies := make([]*models.Policy, len(policyNames))
	for i, n := range policyNames {
		policies[i] = &models.Policy{Name: n}
	}
	Expect(db.AddRole(context.Background(), &models.RoleDB{ID: uuid.New(), RoleName: name, Policies: policies})).To(Succeed())
}

func seedGroup(db *PGxDB, name string) *models.GroupDB {
	g := &models.GroupDB{ID: uuid.New(), GroupName: name}
	Expect(db.AddGroup(context.Background(), g)).To(Succeed())
	return g
}

// ============================================================================
// Database + orm package coverage via container
// ============================================================================

var _ = Describe("Database Migrate (integration)", func() {
	It("Migrate runs auto-migration and DropUnusedColumns", func() {
		logger, _ := testutils.SetupTestLogger()
		d := &ezdb.Database{DB: pgxGormDB, Logger: logger}
		Expect(d.Migrate(context.Background())).To(Succeed())
	})
})

// ============================================================================
// User CRUD
// ============================================================================

var _ = Describe("User CRUD (integration)", func() {
	var db *PGxDB
	testBirthDate := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	BeforeEach(func() { db = newTestPGxDB() })

	It("creates and retrieves a user", func() {
		u := &models.UserDB{ID: uuid.New(), Email: "test@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u)).To(Succeed())

		found, err := db.GetUser(context.Background(), u.ID.String())
		Expect(err).ToNot(HaveOccurred())
		Expect(found.Email).To(Equal("test@example.com"))
		Expect(found.Password).To(BeEmpty())
	})

	It("updates user fields", func() {
		u := &models.UserDB{ID: uuid.New(), Email: "update@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u)).To(Succeed())

		u.FirstName = "Jane"
		Expect(db.UpdateUser(context.Background(), u)).To(Succeed())

		found, _ := db.GetUser(context.Background(), u.ID.String())
		Expect(found.FirstName).To(Equal("Jane"))
	})

	It("deletes a user", func() {
		u := &models.UserDB{ID: uuid.New(), Email: "delete@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u)).To(Succeed())

		Expect(db.DeleteUser(context.Background(), u.ID.String())).To(Succeed())
		_, err := db.GetUser(context.Background(), u.ID.String())
		Expect(err).To(Equal(ezdb.ErrNoRecord))
	})

	It("lists users with pagination", func() {
		for i := 1; i <= 5; i++ {
			suffix := fmt.Sprintf("user%02d", i)
			Expect(db.AddUser(context.Background(), &models.UserDB{ID: uuid.New(), Username: suffix, Email: suffix + "@test.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}})).To(Succeed())
		}
		users, err := db.ListUsers(context.Background(), 3, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(users).To(HaveLen(3))
	})

	It("resets password and logs in", func() {
		u := &models.UserDB{ID: uuid.New(), Username: "loginuser", Email: "login@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u)).To(Succeed())

		Expect(db.ResetPassword(context.Background(), u.ID.String(), "NewPass456")).To(Succeed())

		profile, err := db.UserLogin(context.Background(), "loginuser", "NewPass456")
		Expect(err).ToNot(HaveOccurred())
		Expect(profile.User).To(Equal("loginuser"))
	})

	It("UserLogin rejects invalid password", func() {
		u := &models.UserDB{ID: uuid.New(), Username: "badpw", Email: "badpw@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u)).To(Succeed())

		_, err := db.UserLogin(context.Background(), "badpw", "WrongPassword")
		Expect(err).To(Equal(ezdb.ErrInvalidCreds))
	})

	It("UserLogin rejects non-existent user", func() {
		_, err := db.UserLogin(context.Background(), "nobody", "Test1234")
		Expect(err).To(Equal(ezdb.ErrNoRecord))
	})

	It("returns ErrConflict on duplicate email", func() {
		u1 := &models.UserDB{ID: uuid.New(), Email: "dup@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u1)).To(Succeed())
		u2 := &models.UserDB{ID: uuid.New(), Email: "dup@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u2)).To(Equal(ezdb.ErrConflict))
	})
})

// ============================================================================
// Group CRUD
// ============================================================================

var _ = Describe("Group CRUD (integration)", func() {
	var db *PGxDB

	BeforeEach(func() { db = newTestPGxDB() })

	It("creates and retrieves a group", func() {
		g := &models.GroupDB{ID: uuid.New(), GroupName: "test-group"}
		Expect(db.AddGroup(context.Background(), g)).To(Succeed())

		found, err := db.GetGroup(context.Background(), "test-group")
		Expect(err).ToNot(HaveOccurred())
		Expect(found.GroupName).To(Equal("test-group"))
	})

	It("renames a group", func() {
		seedGroup(db, "old-name")
		Expect(db.UpdateGroup(context.Background(), "old-name", &models.GroupDB{GroupName: "new-name"})).To(Succeed())

		_, err := db.GetGroup(context.Background(), "old-name")
		Expect(err).To(Equal(ezdb.ErrNoRecord))
		found, err := db.GetGroup(context.Background(), "new-name")
		Expect(err).ToNot(HaveOccurred())
		Expect(found.GroupName).To(Equal("new-name"))
	})

	It("deletes a group", func() {
		seedGroup(db, "to-delete")
		Expect(db.DeleteGroup(context.Background(), "to-delete")).To(Succeed())
		_, err := db.GetGroup(context.Background(), "to-delete")
		Expect(err).To(Equal(ezdb.ErrNoRecord))
	})

	It("adds and removes users from a group", func() {
		seedGroup(db, "admins")
		u := &models.UserDB{ID: uuid.New(), Username: "guser", Email: "guser@example.com", Password: "Test1234", BirthDate: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), Address: models.AddressDB{Country: "US"}}
		Expect(newTestPGxDB().AddUser(context.Background(), u)).To(Succeed())

		Expect(db.AddUserToGroup(context.Background(), "admins", []string{u.ID.String()})).To(Succeed())
		group, _ := db.GetGroup(context.Background(), "admins")
		Expect(group.Users).To(HaveLen(1))

		Expect(db.RemoveUserFromGroup(context.Background(), "admins", []string{u.ID.String()})).To(Succeed())
		group, _ = db.GetGroup(context.Background(), "admins")
		Expect(group.Users).To(HaveLen(0))
	})

	It("lists groups with pagination", func() {
		for _, name := range []string{"alpha", "beta", "gamma"} {
			seedGroup(db, name)
		}
		groups, err := db.ListGroups(context.Background(), 2, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(groups).To(HaveLen(2))
	})

	It("returns ErrConflict on duplicate group", func() {
		seedGroup(db, "admins")
		Expect(db.AddGroup(context.Background(), &models.GroupDB{ID: uuid.New(), GroupName: "admins"})).To(Equal(ezdb.ErrConflict))
	})
})

// ============================================================================
// Permission CRUD
// ============================================================================

var _ = Describe("Permission CRUD (integration)", func() {
	var db *PGxDB
	BeforeEach(func() { db = newTestPGxDB() })

	It("creates and retrieves a permission", func() {
		Expect(db.AddPermission(context.Background(), &models.Permission{
			Name: "auth::user::read", Service: "auth", Action: "user::read", Method: "GET", Path: "/users/", Effect: true,
		})).To(Succeed())

		p, err := db.GetPermission(context.Background(), "auth::user::read")
		Expect(err).ToNot(HaveOccurred())
		Expect(p.Service).To(Equal("auth"))
	})

	It("updates and deletes a permission", func() {
		seedPerm(db, "auth::user::read", "auth", "user::read", "GET", "/users/")
		Expect(db.UpdatePermission(context.Background(), &models.Permission{
			Name: "auth::user::read", Method: "POST", Path: "/users/new",
		})).To(Succeed())

		p, _ := db.GetPermission(context.Background(), "auth::user::read")
		Expect(p.Method).To(Equal("POST"))

		Expect(db.DeletePermission(context.Background(), "auth::user::read")).To(Succeed())
		_, err := db.GetPermission(context.Background(), "auth::user::read")
		Expect(err).To(Equal(ezdb.ErrNoRecord))
	})

	It("lists permissions grouped by service", func() {
		seedPerm(db, "auth::user::read", "auth", "user::read", "GET", "/users/")
		seedPerm(db, "auth::user::write", "auth", "user::write", "POST", "/users/")
		seedPerm(db, "api::item::get", "api", "item::get", "GET", "/items/")

		result, err := db.ListPermissions(context.Background(), "", 30, 0)
		Expect(err).ToNot(HaveOccurred())
		total := 0
		for _, perms := range result {
			total += len(perms)
		}
		Expect(total).To(Equal(3))
	})
})

// ============================================================================
// Policy CRUD
// ============================================================================

var _ = Describe("Policy CRUD (integration)", func() {
	var db *PGxDB
	BeforeEach(func() { db = newTestPGxDB() })

	It("creates and retrieves a policy with permissions", func() {
		seedPerm(db, "auth::user::read", "auth", "user::read", "GET", "/users/")
		seedPerm(db, "auth::user::write", "auth", "user::write", "POST", "/users/")

		Expect(db.AddPolicy(context.Background(), &models.Policy{
			Name: "admin-policy", Permission: []*models.Permission{{Name: "auth::user::read"}, {Name: "auth::user::write"}},
		})).To(Succeed())

		policy, err := db.GetPolicy(context.Background(), "admin-policy")
		Expect(err).ToNot(HaveOccurred())
		Expect(policy.Permission).To(HaveLen(2))
	})

	It("updates policy with new permissions", func() {
		seedPerm(db, "auth::user::read", "auth", "user::read", "GET", "/users/")
		seedPerm(db, "auth::user::write", "auth", "user::write", "POST", "/users/")
		seedPolicy(db, "admin-policy", "auth::user::read")

		Expect(db.UpdatePolicy(context.Background(), "admin-policy", &models.Policy{
			Name: "admin-policy", Permission: []*models.Permission{{Name: "auth::user::read"}, {Name: "auth::user::write"}},
		})).To(Succeed())

		policy, _ := db.GetPolicy(context.Background(), "admin-policy")
		Expect(policy.Permission).To(HaveLen(2))
	})

	It("lists policies", func() {
		seedPolicy(db, "policy-a")
		seedPolicy(db, "policy-b")
		policies, err := db.ListPolicies(context.Background(), 30, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(policies).To(HaveLen(2))
	})

	It("deletes policy", func() {
		seedPolicy(db, "to-delete")
		Expect(db.DeletePolicy(context.Background(), "to-delete")).To(Succeed())
		_, err := db.GetPolicy(context.Background(), "to-delete")
		Expect(err).To(Equal(ezdb.ErrNoRecord))
	})
})

// ============================================================================
// Role CRUD
// ============================================================================

var _ = Describe("Role CRUD (integration)", func() {
	var db *PGxDB
	BeforeEach(func() { db = newTestPGxDB() })

	It("creates and retrieves a role with policies", func() {
		seedPolicy(db, "admin-policy")
		Expect(db.AddRole(context.Background(), &models.RoleDB{ID: uuid.New(), RoleName: "admin", Policies: []*models.Policy{{Name: "admin-policy"}}})).To(Succeed())

		role, err := db.GetRole(context.Background(), "admin")
		Expect(err).ToNot(HaveOccurred())
		Expect(role.Policies).To(HaveLen(1))
	})

	It("updates role with new policies", func() {
		seedPolicy(db, "admin-policy")
		seedRole(db, "admin", "admin-policy")

		seedPolicy(db, "viewer-policy")
		Expect(db.UpdateRole(context.Background(), "admin", &models.RoleDB{RoleName: "admin", Policies: []*models.Policy{{Name: "admin-policy"}, {Name: "viewer-policy"}}})).To(Succeed())

		role, _ := db.GetRole(context.Background(), "admin")
		Expect(role.Policies).To(HaveLen(2))
	})

	It("lists roles", func() {
		names := []string{"role-a", "role-b", "role-c"}
		for _, name := range names {
			seedRole(db, name)
		}
		roles, err := db.ListRoles(context.Background(), 30, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(roles).To(HaveLen(3))
	})

	It("deletes role", func() {
		seedRole(db, "admin")
		Expect(db.DeleteRole(context.Background(), "admin")).To(Succeed())
		_, err := db.GetRole(context.Background(), "admin")
		Expect(err).To(Equal(ezdb.ErrNoRecord))
	})
})

// ============================================================================
// Role Associations
// ============================================================================

var _ = Describe("Role Associations (integration)", func() {
	var db *PGxDB
	var testUserID string
	testBirthDate := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	BeforeEach(func() {
		db = newTestPGxDB()
		seedPerm(db, "auth::user::read", "auth", "user::read", "GET", "/users/")
		seedPolicy(db, "admin-policy", "auth::user::read")
		seedRole(db, "admin", "admin-policy")

		u := &models.UserDB{ID: uuid.New(), Username: "testuser", Email: "testuser@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u)).To(Succeed())
		testUserID = u.ID.String()

		g := &models.GroupDB{ID: uuid.New(), GroupName: "admins"}
		Expect(db.AddGroup(context.Background(), g)).To(Succeed())
	})

	It("assigns and removes roles from users", func() {
		Expect(db.AddRoleToUser(context.Background(), testUserID, []string{"admin"})).To(Succeed())
		Expect(db.RemoveRoleFromUser(context.Background(), testUserID, []string{"admin"})).To(Succeed())
	})

	It("assigns roles to groups", func() {
		Expect(db.AddRoleToGroup(context.Background(), "admins", []string{"admin"})).To(Succeed())
		Expect(db.RemoveRoleFromGroup(context.Background(), "admins", []string{"admin"})).To(Succeed())
	})

	It("resolves user permissions through role assignments", func() {
		Expect(db.AddRoleToUser(context.Background(), testUserID, []string{"admin"})).To(Succeed())

		perms, err := db.GetUserPermissions(context.Background(), testUserID)
		Expect(err).ToNot(HaveOccurred())
		Expect(perms).To(HaveLen(1))
		Expect(perms[0].Name).To(Equal("auth::user::read"))
	})

	It("resolves role permissions", func() {
		perms, err := db.GetRolePermissions(context.Background(), "admin")
		Expect(err).ToNot(HaveOccurred())
		Expect(perms).To(HaveLen(1))
	})

	It("resolves group permissions through role assignments", func() {
		Expect(db.AddRoleToGroup(context.Background(), "admins", []string{"admin"})).To(Succeed())

		perms, err := db.GetGroupPermissions(context.Background(), "admins")
		Expect(err).ToNot(HaveOccurred())
		Expect(perms).To(HaveLen(1))
	})

	It("returns user IDs by role", func() {
		Expect(db.AddRoleToUser(context.Background(), testUserID, []string{"admin"})).To(Succeed())

		ids, err := db.GetUserIDsByRole(context.Background(), "admin")
		Expect(err).ToNot(HaveOccurred())
		Expect(ids).To(ContainElement(testUserID))
	})

	It("returns user IDs by policy", func() {
		Expect(db.AddRoleToUser(context.Background(), testUserID, []string{"admin"})).To(Succeed())

		ids, err := db.GetUserIDsByPolicy(context.Background(), "admin-policy")
		Expect(err).ToNot(HaveOccurred())
		Expect(ids).To(ContainElement(testUserID))
	})

	It("returns role users", func() {
		Expect(db.AddRoleToUser(context.Background(), testUserID, []string{"admin"})).To(Succeed())

		usernames, err := db.GetRoleUsers(context.Background(), "admin")
		Expect(err).ToNot(HaveOccurred())
		Expect(usernames).To(ContainElement("testuser"))
	})
})

// ============================================================================
// PAT / Audit
// ============================================================================

var _ = Describe("PAT/Audit (integration)", func() {
	var db *PGxDB
	patBirthDate := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	// newPatUser creates a user in the DB and returns its UUID.
	// Required because pat_tokens.user_id has a FK constraint to users.
	newPatUser := func(email string) uuid.UUID {
		u := &models.UserDB{ID: uuid.New(), Email: email, Password: "Test1234", BirthDate: patBirthDate, Address: models.AddressDB{Country: "US"}}
		Expect(db.AddUser(context.Background(), u)).To(Succeed())
		return u.ID
	}

	BeforeEach(func() { db = newTestPGxDB() })

	It("creates and retrieves a PAT", func() {
		userID := newPatUser("pat-create@example.com")
		pat := &models.PATDB{ID: uuid.New(), Name: "my-token", Prefix: "xwpat_", Hash: "my-hash", UserID: userID}
		Expect(db.CreatePAT(context.Background(), pat)).To(Succeed())

		found, err := db.GetPATByHash(context.Background(), "my-hash")
		Expect(err).ToNot(HaveOccurred())
		Expect(found.Name).To(Equal("my-token"))
	})

	It("lists PATs by user", func() {
		userID := newPatUser("pat-list@example.com")
		for i := 0; i < 3; i++ {
			Expect(db.CreatePAT(context.Background(), &models.PATDB{
				ID: uuid.New(), Name: "token", Prefix: "xwpat_", Hash: fmt.Sprintf("hash-%c", 'a'+i), UserID: userID,
			})).To(Succeed())
		}
		pats, err := db.ListPATs(context.Background(), userID.String())
		Expect(err).ToNot(HaveOccurred())
		Expect(pats).To(HaveLen(3))
	})

	It("deletes a PAT and updates last_used_at", func() {
		userID := newPatUser("pat-delete@example.com")
		pat := &models.PATDB{ID: uuid.New(), Name: "token", Prefix: "xwpat_", Hash: "del-hash", UserID: userID}
		Expect(db.CreatePAT(context.Background(), pat)).To(Succeed())

		Expect(db.UpdatePATLastUsed(context.Background(), pat.ID.String())).To(Succeed())

		Expect(db.DeletePAT(context.Background(), pat.ID.String(), pat.UserID.String())).To(Succeed())
		_, err := db.GetPATByHash(context.Background(), "del-hash")
		Expect(err).To(Equal(ezdb.ErrNoRecord))
	})

	It("inserts and lists audit events", func() {
		for i := 0; i < 5; i++ {
			Expect(db.InsertAuditEvents(context.Background(), []*models.AuditEventDB{
				{Type: "login", User: "u1", IP: "127.0.0.1", Success: true},
			})).To(Succeed())
		}
		events, err := db.ListAuditEventsDB(context.Background(), 3, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(events).To(HaveLen(3))
	})
})

// ============================================================================
// Advanced: UpdatePolicy/UpdateRole with role/group changes, fallback paths
// ============================================================================

var _ = Describe("Advanced coverage (integration)", func() {
	var db *PGxDB
	testBirthDate := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	BeforeEach(func() { db = newTestPGxDB() })

	Describe("UpdatePolicy with role changes", func() {
		It("updates policy and replaces role associations", func() {
			seedPerm(db, "auth::user::read", "auth", "user::read", "GET", "/users/")
			seedPolicy(db, "admin-policy", "auth::user::read")
			seedRole(db, "admin", "admin-policy")

			Expect(db.UpdatePolicy(context.Background(), "admin-policy", &models.Policy{
				Name:       "admin-policy",
				Permission: []*models.Permission{{Name: "auth::user::read"}},
				Roles:      []*models.RoleDB{{RoleName: "admin"}},
			})).To(Succeed())

			policy, _ := db.GetPolicy(context.Background(), "admin-policy")
			Expect(policy.Roles).To(HaveLen(1))
		})
	})

	Describe("UpdateRole with group changes", func() {
		It("updates role and replaces group associations", func() {
			seedPolicy(db, "admin-policy")
			seedRole(db, "admin", "admin-policy")
			g := &models.GroupDB{ID: uuid.New(), GroupName: "admins"}
			Expect(db.AddGroup(context.Background(), g)).To(Succeed())

			Expect(db.UpdateRole(context.Background(), "admin", &models.RoleDB{
				RoleName: "admin",
				Policies: []*models.Policy{{Name: "admin-policy"}},
				Groups:   []*models.GroupDB{{GroupName: "admins"}},
			})).To(Succeed())

			role, _ := db.GetRole(context.Background(), "admin")
			Expect(role.Groups).To(HaveLen(1))
		})
	})

	Describe("UpdatePolicy error paths", func() {
		It("returns ErrNoRecord for non-existent policy", func() {
			err := db.UpdatePolicy(context.Background(), "no-such-policy", &models.Policy{Name: "no-such-policy"})
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("UpdateRole error paths", func() {
		It("returns ErrNoRecord for non-existent role", func() {
			err := db.UpdateRole(context.Background(), "no-such-role", &models.RoleDB{RoleName: "no-such-role"})
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("UpdateUser fallback paths", func() {
		It("updates user identified by email when no ID set", func() {
			u := &models.UserDB{ID: uuid.New(), Email: "byemail@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			Expect(db.AddUser(context.Background(), u)).To(Succeed())

			err := db.UpdateUser(context.Background(), &models.UserDB{Email: "byemail@example.com", FirstName: "EmailUpdate", BirthDate: testBirthDate})
			Expect(err).ToNot(HaveOccurred())

			found, _ := db.GetUser(context.Background(), u.ID.String())
			Expect(found.FirstName).To(Equal("EmailUpdate"))
		})

		It("updates user identified by mobile when no ID or email set", func() {
			u := &models.UserDB{ID: uuid.New(), MobileNumber: "+1234567890", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			Expect(db.AddUser(context.Background(), u)).To(Succeed())

			err := db.UpdateUser(context.Background(), &models.UserDB{MobileNumber: "+1234567890", FirstName: "MobileUpdate", BirthDate: testBirthDate})
			Expect(err).ToNot(HaveOccurred())

			found, _ := db.GetUser(context.Background(), u.ID.String())
			Expect(found.FirstName).To(Equal("MobileUpdate"))
		})
	})

	Describe("GetUserIDsByRole group-transitive", func() {
		It("returns user IDs from group role assignments", func() {
			seedPolicy(db, "admin-policy")
			seedRole(db, "admin", "admin-policy")

			u := &models.UserDB{ID: uuid.New(), Username: "groupuser", Email: "groupuser@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			Expect(db.AddUser(context.Background(), u)).To(Succeed())

			g := &models.GroupDB{ID: uuid.New(), GroupName: "engineers"}
			Expect(db.AddGroup(context.Background(), g)).To(Succeed())
			Expect(db.AddRoleToGroup(context.Background(), "engineers", []string{"admin"})).To(Succeed())
			Expect(db.AddUserToGroup(context.Background(), "engineers", []string{u.ID.String()})).To(Succeed())

			ids, err := db.GetUserIDsByRole(context.Background(), "admin")
			Expect(err).ToNot(HaveOccurred())
			Expect(ids).To(ContainElement(u.ID.String()))
		})
	})

	Describe("GetRoleUsers group-transitive", func() {
		It("returns usernames from group role assignments", func() {
			seedPolicy(db, "admin-policy")
			seedRole(db, "admin", "admin-policy")

			u := &models.UserDB{ID: uuid.New(), Username: "grproleuser", Email: "grproleuser@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			Expect(db.AddUser(context.Background(), u)).To(Succeed())

			g := &models.GroupDB{ID: uuid.New(), GroupName: "designers"}
			Expect(db.AddGroup(context.Background(), g)).To(Succeed())
			Expect(db.AddRoleToGroup(context.Background(), "designers", []string{"admin"})).To(Succeed())
			Expect(db.AddUserToGroup(context.Background(), "designers", []string{u.ID.String()})).To(Succeed())

			usernames, err := db.GetRoleUsers(context.Background(), "admin")
			Expect(err).ToNot(HaveOccurred())
			Expect(usernames).To(ContainElement("grproleuser"))
		})
	})

	Describe("ListProviders", func() {
		It("lists providers", func() {
			cbURL := datatypes.URL(url.URL{Scheme: "https", Host: "example.com", Path: "/callback"})
			Expect(db.AddProvider(context.Background(), &models.ProviderDB{
				ProviderName: "google", Type: "oidc", ClientID: "c1", ClientSecret: "s1",
				RedirectURL: &cbURL, Scope: "openid",
			})).To(Succeed())

			providers, err := db.ListProviders(context.Background(), 10, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(providers).To(HaveLen(1))
		})
	})
})
