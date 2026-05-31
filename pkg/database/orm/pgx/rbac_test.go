package pgx

import (
	"context"
	"fmt"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/gorm"

	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

var _ = Describe("RBAC Permission CRUD Operations", func() {
	var db *PGxDB
	var mock sqlmock.Sqlmock

	BeforeEach(func() { db, mock = newMockPGxDB() })

	Describe("AddPermission", func() {
		It("creates a valid permission", func() {
			mock.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("auth::user::read"))

			err := db.AddPermission(context.Background(), &models.Permission{
				Name: "auth::user::read", Service: "auth", Action: "user::read", Method: "GET", Path: "/users/", Effect: true,
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrConflict on duplicate", func() {
			pgErr := &pgconn.PgError{Code: "23505"}
			mock.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnError(fmt.Errorf("%w: duplicate key", pgErr))

			err := db.AddPermission(context.Background(), &models.Permission{
				Name: "auth::user::read", Service: "auth", Action: "user::read", Method: "GET", Path: "/users/",
			})
			Expect(err).To(Equal(ezdb.ErrConflict))
		})

		It("rejects permission with invalid action format", func() {
			err := db.AddPermission(context.Background(), &models.Permission{
				Name: "auth::user::read", Service: "auth", Action: "invalid", Method: "GET", Path: "/users/",
			})
			Expect(err).To(HaveOccurred())
		})

		It("rejects permission with empty name", func() {
			err := db.AddPermission(context.Background(), &models.Permission{
				Name: "", Service: "auth", Action: "user::read", Method: "GET", Path: "/users/",
			})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("GetPermission", func() {
		It("returns existing permission", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_permissions" WHERE name = \$1`).
				WithArgs("auth::user::read", 1).
				WillReturnRows(sqlmock.NewRows([]string{"name", "service", "method", "path", "action", "effect"}).
					AddRow("auth::user::read", "auth", "GET", "/users/", "user::read", true))

			perm, err := db.GetPermission(context.Background(), "auth::user::read")
			Expect(err).ToNot(HaveOccurred())
			Expect(perm.Name).To(Equal("auth::user::read"))
			Expect(perm.Service).To(Equal("auth"))
		})

		It("returns ErrNoRecord for non-existent permission", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetPermission(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("UpdatePermission", func() {
		It("updates existing permission", func() {
			mock.ExpectExec(`UPDATE "rbac_permissions" SET`).
				WithArgs("auth::user::read", "POST", "/users/update", "auth::user::read").
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := db.UpdatePermission(context.Background(), &models.Permission{
				Name: "auth::user::read", Method: "POST", Path: "/users/update",
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent permission", func() {
			mock.ExpectExec(`UPDATE "rbac_permissions" SET`).
				WithArgs("nonexistent", "GET", "/test", "nonexistent").
				WillReturnResult(sqlmock.NewResult(0, 0))

			err := db.UpdatePermission(context.Background(), &models.Permission{
				Name: "nonexistent", Method: "GET", Path: "/test",
			})
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("DeletePermission", func() {
		It("deletes existing permission", func() {
			mock.ExpectExec(`DELETE FROM "rbac_permissions" WHERE name = \$1`).
				WithArgs("auth::user::read").
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := db.DeletePermission(context.Background(), "auth::user::read")
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent permission", func() {
			mock.ExpectExec(`DELETE FROM "rbac_permissions" WHERE name = \$1`).
				WithArgs("nonexistent").
				WillReturnResult(sqlmock.NewResult(0, 0))

			err := db.DeletePermission(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("ListPermissions", func() {
		It("lists permissions grouped by service", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_permissions" ORDER BY name LIMIT \$1`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"name", "service", "action", "method", "path", "effect"}).
					AddRow("auth::user::read", "auth", "user::read", "GET", "/users/", true).
					AddRow("api::item::get", "api", "item::get", "GET", "/items/", true))

			result, err := db.ListPermissions(context.Background(), "", 30, 0)
			Expect(err).ToNot(HaveOccurred())
			total := 0
			for _, perms := range result {
				total += len(perms)
			}
			Expect(total).To(Equal(2))
		})

		It("filters by service", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_permissions" WHERE service = \$1 ORDER BY action LIMIT \$2`).
				WithArgs("auth", 30).
				WillReturnRows(sqlmock.NewRows([]string{"name", "service", "action", "method", "path", "effect"}).
					AddRow("auth::user::read", "auth", "user::read", "GET", "/users/", true))

			result, err := db.ListPermissions(context.Background(), "auth", 30, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(result["auth"]).To(HaveLen(1))
		})

		It("returns empty map when no permissions exist", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"name", "service", "action", "method", "path"}))

			result, err := db.ListPermissions(context.Background(), "", 30, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(BeEmpty())
		})
	})
})

var _ = Describe("RBAC Policy CRUD Operations", func() {
	var db *PGxDB
	var mock sqlmock.Sqlmock

	BeforeEach(func() { db, mock = newMockPGxDB() })

	Describe("AddPolicy", func() {
		It("creates policy without permissions", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`INSERT INTO "rbac_policies"`).
				WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("empty-policy"))
			mock.ExpectCommit()

			err := db.AddPolicy(context.Background(), &models.Policy{Name: "empty-policy"})
			Expect(err).ToNot(HaveOccurred())
		})

		It("creates policy with existing permissions", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "rbac_permissions" WHERE name = \$1`).
				WithArgs("auth::user::read", 1).
				WillReturnRows(sqlmock.NewRows([]string{"name", "service", "action", "method", "path", "effect"}).
					AddRow("auth::user::read", "auth", "user::read", "GET", "/users/", true))
			mock.ExpectQuery(`INSERT INTO "rbac_policies"`).
				WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin-policy"))
			// Permission association insert
			mock.ExpectQuery(`INSERT INTO "policy_permissions"`).
				WillReturnRows(sqlmock.NewRows([]string{"policy_name", "permission_name"}).
					AddRow("admin-policy", "auth::user::read"))
			mock.ExpectCommit()

			err := db.AddPolicy(context.Background(), &models.Policy{
				Name: "admin-policy", Permission: []*models.Permission{{Name: "auth::user::read"}},
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects policy referencing non-existent permission", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "rbac_permissions" WHERE name = \$1`).
				WithArgs("nonexistent-perm", 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.AddPolicy(context.Background(), &models.Policy{
				Name: "bad-policy", Permission: []*models.Permission{{Name: "nonexistent-perm"}},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not exist"))
		})

		It("returns ErrConflict on duplicate", func() {
			pgErr := &pgconn.PgError{Code: "23505"}
			mock.ExpectBegin()
			mock.ExpectQuery(`INSERT INTO "rbac_policies"`).
				WillReturnError(fmt.Errorf("%w: duplicate key", pgErr))
			mock.ExpectRollback()

			err := db.AddPolicy(context.Background(), &models.Policy{Name: "admin-policy"})
			Expect(err).To(Equal(ezdb.ErrConflict))
		})

		It("rejects policy with empty name", func() {
			err := db.AddPolicy(context.Background(), &models.Policy{Name: ""})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("GetPolicy", func() {
		It("returns existing policy with permissions", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_policies" WHERE name = \$1`).
				WithArgs("admin-policy", 1).
				WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin-policy"))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))

			policy, err := db.GetPolicy(context.Background(), "admin-policy")
			Expect(err).ToNot(HaveOccurred())
			Expect(policy.Name).To(Equal("admin-policy"))
		})

		It("returns ErrNoRecord for non-existent policy", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetPolicy(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("DeletePolicy", func() {
		It("deletes existing policy", func() {
			mock.ExpectBegin()
			mock.ExpectExec(`DELETE FROM "policy_permissions"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectExec(`DELETE FROM "rbac_policies"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()

			err := db.DeletePolicy(context.Background(), "admin-policy")
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent policy", func() {
			mock.ExpectBegin()
			mock.ExpectExec(`DELETE FROM "policy_permissions"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(`DELETE FROM "rbac_policies"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectCommit()

			err := db.DeletePolicy(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("ListPolicies", func() {
		It("lists policies with pagination", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_policies" ORDER BY name LIMIT \$1`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"name"}).
					AddRow("policy-a").AddRow("policy-b").AddRow("policy-c"))
			// Preload Permission queries
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))

			policies, err := db.ListPolicies(context.Background(), 30, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(policies).To(HaveLen(3))
		})

		It("returns empty list when no policies exist", func() {
			mock.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"name"}))

			policies, err := db.ListPolicies(context.Background(), 30, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(policies).To(BeEmpty())
		})
	})
})

var _ = Describe("RBAC Role CRUD Operations", func() {
	var db *PGxDB
	var mock sqlmock.Sqlmock

	BeforeEach(func() { db, mock = newMockPGxDB() })

	Describe("AddRole", func() {
		It("creates role without policies", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`INSERT INTO "roles"`).
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
			mock.ExpectCommit()

			err := db.AddRole(context.Background(), &models.RoleDB{ID: uuid.New(), RoleName: "empty-role"})
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects role with empty name", func() {
			err := db.AddRole(context.Background(), &models.RoleDB{RoleName: ""})
			Expect(err).To(HaveOccurred())
		})

		It("returns ErrConflict on duplicate", func() {
			pgErr := &pgconn.PgError{Code: "23505"}
			mock.ExpectBegin()
			mock.ExpectQuery(`INSERT INTO "roles"`).
				WillReturnError(fmt.Errorf("%w: duplicate key", pgErr))
			mock.ExpectRollback()

			err := db.AddRole(context.Background(), &models.RoleDB{ID: uuid.New(), RoleName: "admin"})
			Expect(err).To(Equal(ezdb.ErrConflict))
		})
	})

	Describe("GetRole", func() {
		It("returns existing role", func() {
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
				WithArgs("admin", 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(uuid.New(), "admin"))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))

			role, err := db.GetRole(context.Background(), "admin")
			Expect(err).ToNot(HaveOccurred())
			Expect(role.RoleName).To(Equal("admin"))
		})

		It("returns ErrNoRecord for non-existent role", func() {
			mock.ExpectQuery(`SELECT \* FROM "roles"`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetRole(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("DeleteRole", func() {
		It("deletes existing role", func() {
			mock.ExpectExec(`DELETE FROM "roles" WHERE name = \$1`).
				WithArgs("admin").
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := db.DeleteRole(context.Background(), "admin")
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent role", func() {
			mock.ExpectExec(`DELETE FROM "roles" WHERE name = \$1`).
				WithArgs("nonexistent").
				WillReturnResult(sqlmock.NewResult(0, 0))

			err := db.DeleteRole(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("ListRoles", func() {
		It("lists roles with pagination", func() {
			mock.ExpectQuery(`SELECT \* FROM "roles" ORDER BY name LIMIT \$1`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
					AddRow(uuid.New(), "role-1").AddRow(uuid.New(), "role-2").AddRow(uuid.New(), "role-3"))

			roles, err := db.ListRoles(context.Background(), 30, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(roles).To(HaveLen(3))
		})

		It("returns empty list when no roles exist", func() {
			mock.ExpectQuery(`SELECT \* FROM "roles"`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

			roles, err := db.ListRoles(context.Background(), 30, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(roles).To(BeEmpty())
		})
	})
})

var _ = Describe("RBAC Role Association Operations", func() {
	var db *PGxDB
	var mock sqlmock.Sqlmock

	BeforeEach(func() { db, mock = newMockPGxDB() })

	Describe("AddRoleToUser", func() {
		It("returns error for non-existent user", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.AddRoleToUser(context.Background(), "nonexistent", []string{"admin"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("user nonexistent not found"))
		})

		It("returns error for non-existent role", func() {
			userID := uuid.New()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs(userID.String(), 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username"}).AddRow(userID, "testuser"))
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name IN \(\$1\)`).
				WithArgs("nonexistent").
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))
			mock.ExpectRollback()

			err := db.AddRoleToUser(context.Background(), userID.String(), []string{"nonexistent"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("role nonexistent not found"))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs(sqlmock.AnyArg(), 1).
				WillReturnError(fmt.Errorf("connection refused"))
			mock.ExpectRollback()

			err := db.AddRoleToUser(context.Background(), uuid.New().String(), []string{"admin"})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("RemoveRoleFromUser", func() {
		It("returns error for non-existent user", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.RemoveRoleFromUser(context.Background(), "nonexistent", []string{"admin"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("user nonexistent not found"))
		})

		It("returns error for non-existent role", func() {
			userID := uuid.New()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs(userID.String(), 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username"}).AddRow(userID, "testuser"))
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name IN \(\$1\)`).
				WithArgs("nonexistent").
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))
			mock.ExpectRollback()

			err := db.RemoveRoleFromUser(context.Background(), userID.String(), []string{"nonexistent"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("role nonexistent not found"))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs(sqlmock.AnyArg(), 1).
				WillReturnError(fmt.Errorf("connection refused"))
			mock.ExpectRollback()

			err := db.RemoveRoleFromUser(context.Background(), uuid.New().String(), []string{"admin"})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("AddRoleToGroup", func() {
		It("returns error for non-existent group", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.AddRoleToGroup(context.Background(), "nonexistent", []string{"admin"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("group nonexistent not found"))
		})

		It("returns error for non-existent role", func() {
			groupID := uuid.New()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(groupID, "admins"))
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name IN \(\$1\)`).
				WithArgs("nonexistent").
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))
			mock.ExpectRollback()

			err := db.AddRoleToGroup(context.Background(), "admins", []string{"nonexistent"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("role nonexistent not found"))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnError(fmt.Errorf("connection refused"))
			mock.ExpectRollback()

			err := db.AddRoleToGroup(context.Background(), "admins", []string{"admin"})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("RemoveRoleFromGroup", func() {
		It("returns error for non-existent group", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.RemoveRoleFromGroup(context.Background(), "nonexistent", []string{"admin"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("group nonexistent not found"))
		})

		It("returns error for non-existent role", func() {
			groupID := uuid.New()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(groupID, "admins"))
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name IN \(\$1\)`).
				WithArgs("nonexistent").
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))
			mock.ExpectRollback()

			err := db.RemoveRoleFromGroup(context.Background(), "admins", []string{"nonexistent"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("role nonexistent not found"))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnError(fmt.Errorf("connection refused"))
			mock.ExpectRollback()

			err := db.RemoveRoleFromGroup(context.Background(), "admins", []string{"admin"})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})
})

var _ = Describe("GetUserIDsByPolicy", func() {
	It("returns user IDs when policy has roles assigned to users", func() {
		db, mock := newMockPGxDB()
		userID := uuid.New().String()
		mock.ExpectQuery(`SELECT DISTINCT ru.user_db_id`).
			WithArgs("admin-policy").
			WillReturnRows(sqlmock.NewRows([]string{"user_db_id"}).AddRow(userID))

		ids, err := db.GetUserIDsByPolicy(context.Background(), "admin-policy")
		Expect(err).ToNot(HaveOccurred())
		Expect(ids).To(ConsistOf(userID))
	})

	It("returns nil when no users have the policy", func() {
		db, mock := newMockPGxDB()
		mock.ExpectQuery(`SELECT DISTINCT ru.user_db_id`).
			WithArgs("admin-policy").
			WillReturnRows(sqlmock.NewRows([]string{"user_db_id"}))

		ids, err := db.GetUserIDsByPolicy(context.Background(), "admin-policy")
		Expect(err).ToNot(HaveOccurred())
		Expect(ids).To(BeNil())
	})

	It("returns ErrOperation on DB error", func() {
		db, mock := newMockPGxDB()
		mock.ExpectQuery(`SELECT DISTINCT ru.user_db_id`).
			WithArgs("admin-policy").
			WillReturnError(fmt.Errorf("connection refused"))

		_, err := db.GetUserIDsByPolicy(context.Background(), "admin-policy")
		Expect(err).To(Equal(ezdb.ErrOperation))
	})
})

var _ = Describe("GetRoleUsers", func() {
	It("returns usernames for direct user-role assignment", func() {
		db, mock := newMockPGxDB()
		roleID := uuid.New()
		mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
			WithArgs("admin", 1).
			WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(roleID, "admin"))
		mock.ExpectQuery(`SELECT DISTINCT u.username FROM users u`).
			WithArgs(roleID.String(), roleID.String()).
			WillReturnRows(sqlmock.NewRows([]string{"username"}).AddRow("alice").AddRow("bob"))

		users, err := db.GetRoleUsers(context.Background(), "admin")
		Expect(err).ToNot(HaveOccurred())
		Expect(users).To(ConsistOf("alice", "bob"))
	})

	It("returns nil when role does not exist", func() {
		db, mock := newMockPGxDB()
		mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
			WithArgs("nonexistent", 1).
			WillReturnError(gorm.ErrRecordNotFound)

		users, err := db.GetRoleUsers(context.Background(), "nonexistent")
		Expect(err).ToNot(HaveOccurred())
		Expect(users).To(BeNil())
	})

	It("returns ErrOperation on DB error", func() {
		db, mock := newMockPGxDB()
		mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
			WithArgs("admin", 1).
			WillReturnError(fmt.Errorf("connection refused"))

		_, err := db.GetRoleUsers(context.Background(), "admin")
		Expect(err).To(Equal(ezdb.ErrOperation))
	})
})

var _ = Describe("Permission resolution", func() {
	Describe("GetRolePermissions", func() {
		It("returns ErrNoRecord for non-existent role", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetRolePermissions(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
				WithArgs("admin", 1).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.GetRolePermissions(context.Background(), "admin")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("GetGroupPermissions", func() {
		It("returns ErrNoRecord for non-existent group", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetGroupPermissions(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("engineering", 1).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.GetGroupPermissions(context.Background(), "engineering")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("GetUserPermissions", func() {
		It("returns ErrNoRecord for non-existent user", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetUserPermissions(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs("test-uuid", 1).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.GetUserPermissions(context.Background(), "test-uuid")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("GetUserIDsByRole", func() {
		It("returns nil when role does not exist", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			ids, err := db.GetUserIDsByRole(context.Background(), "nonexistent")
			Expect(err).ToNot(HaveOccurred())
			Expect(ids).To(BeNil())
		})

		It("returns ErrOperation on DB error", func() {
			db, mock := newMockPGxDB()
			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
				WithArgs("admin", 1).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.GetUserIDsByRole(context.Background(), "admin")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})

		It("returns user IDs for direct user-role assignments", func() {
			db, mock := newMockPGxDB()
			roleID := uuid.New()
			userID := uuid.New().String()

			mock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1`).
				WithArgs("admin", 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(roleID, "admin"))
			mock.ExpectQuery(`SELECT user_db_id FROM user_roles WHERE role_db_id`).
				WithArgs(roleID.String()).
				WillReturnRows(sqlmock.NewRows([]string{"user_db_id"}).AddRow(userID))
			mock.ExpectQuery(`SELECT group_db_id FROM group_roles WHERE role_db_id`).
				WithArgs(roleID.String()).
				WillReturnRows(sqlmock.NewRows([]string{"group_db_id"}))

			ids, err := db.GetUserIDsByRole(context.Background(), "admin")
			Expect(err).ToNot(HaveOccurred())
			Expect(ids).To(ConsistOf(userID))
		})
	})

})

var _ = Describe("ListPolicies table-not-exists", func() {
	It("returns ErrNeedInit for 42P01", func() {
		db, mock := newMockPGxDB()
		pgErr := &pgconn.PgError{Code: "42P01"}
		mock.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
			WillReturnError(fmt.Errorf("%w: relation does not exist", pgErr))

		_, err := db.ListPolicies(context.Background(), 10, 0)
		Expect(err).To(Equal(ezdb.ErrNeedInit))
	})
})

var _ = Describe("ListPermissions Rows error", func() {
	It("returns error for non-42P01 Rows error", func() {
		db, mock := newMockPGxDB()
		mock.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
			WillReturnError(fmt.Errorf("connection lost"))

		_, err := db.ListPermissions(context.Background(), "", 30, 0)
		Expect(err).To(HaveOccurred())
	})

	It("returns ErrNeedInit for 42P01", func() {
		db, mock := newMockPGxDB()
		pgErr := &pgconn.PgError{Code: "42P01"}
		mock.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
			WillReturnError(fmt.Errorf("%w: table missing", pgErr))

		_, err := db.ListPermissions(context.Background(), "", 30, 0)
		Expect(err).To(Equal(ezdb.ErrNeedInit))
	})
})
