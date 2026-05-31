package rbac

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgconn"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	ezerror "github.com/flipcloud-ai/ezauth/pkg/error"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Column helpers

func permissionColumns() []string {
	return []string{
		"name", "effect", "service", "method", "path", "action", "system",
		"created_at", "updated_at",
	}
}

func createPermissionRow(name, service, action, method, path string, system bool) []driver.Value {
	return []driver.Value{
		name, true, service, method, path, action, system,
		time.Now(), time.Now(),
	}
}

func policyColumns() []string {
	return []string{
		"name", "system", "created_at", "updated_at",
	}
}

func createPolicyRow(name string, system bool) []driver.Value {
	return []driver.Value{
		name, system, time.Now(), time.Now(),
	}
}

func roleColumns() []string {
	return []string{
		"id", "name", "system", "created_at", "updated_at",
	}
}

func createRoleRow(name string, system bool) []driver.Value {
	return []driver.Value{
		"550e8400-e29b-41d4-a716-446655440000", name, system,
		time.Now(), time.Now(),
	}
}

// setupMockDB creates a PGxDB backed by sqlmock.
// Pass ordered=false for tests with non-deterministic SQL ordering (e.g., map iteration).
func setupMockDB(logger ezlog.Logger, ordered ...bool) (*pgx.PGxDB, sqlmock.Sqlmock) {
	gormDB, mockSQL, err := testutils.MockSQLPool()
	Expect(err).ToNot(HaveOccurred())
	if len(ordered) > 0 && !ordered[0] {
		mockSQL.MatchExpectationsInOrder(false)
	}
	mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
	mockDB.DB = gormDB
	return mockDB, mockSQL
}

func testCache() cache.Cache[string, []byte] {
	return cache.NewMemoryCache[string, []byte](10000, CacheTTL)
}

// newControllerWithEmptyRouter creates a Controller using an empty router (no routes to walk).
func newControllerWithEmptyRouter(logger ezlog.Logger, mockDB *pgx.PGxDB) Controller {
	ctx := ezlog.ServerContext(context.Background(), logger)
	ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
	Expect(err).ToNot(HaveOccurred())
	return ctrl
}

func groupColumns() []string {
	return []string{"id", "name", "created_at", "updated_at"}
}

func createGroupRow(name string) []driver.Value {
	return []driver.Value{uuid.New().String(), name, time.Now(), time.Now()}
}

func userColumns() []string {
	return []string{"id", "username"}
}

func createUserRow(id, username string) []driver.Value {
	return []driver.Value{id, username}
}

var _ = Describe("RBAC Controller", func() {
	testLogger, _ := testutils.SetupTestLogger()

	// ===== routeWalk / NewController Tests =====

	Describe("NewController and routeWalk", func() {
		It("should populate cache and save permissions to DB for named routes", func() {
			mockDB, mockSQL := setupMockDB(testLogger)

			// Build a router with named routes that match the RBAC permission format.
			// Paths use /ezauth/ prefix to match production depth (wildcard path >= 4 segments).
			router := mux.NewRouter()
			router.HandleFunc("/ezauth/users/", func(w http.ResponseWriter, r *http.Request) {}).
				Methods("GET").Name("auth::user::list")
			router.HandleFunc("/ezauth/users/{id}", func(w http.ResponseWriter, r *http.Request) {}).
				Methods("POST").Name("auth::user::create")

			// routeWalk calls session.Save(&permission) per route with SkipDefaultTransaction.
			// GORM Save on string-PK model does UPDATE first, then INSERT if 0 rows affected.
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("auth::user::list", "auth", "user::list", "GET", "/ezauth/users/", true)...))
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("auth::user::create", "auth", "user::create", "POST", "/ezauth/users/{id}", true)...))
			// Wildcard permission for resource "user"
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("auth::user::*", "auth", "user::*", "ALL", "/ezauth/users/*", true)...))
			// Global admin wildcard
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("admin::*::*", "admin", "admin::*", "ALL", "/ezauth/*", true)...))

			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())
			Expect(ctrl).ToNot(BeNil())

			err = ctrl.RouteWalk(router)
			Expect(err).ToNot(HaveOccurred())

			// Verify the permissions were cached
			authCtrl := ctrl.(*AuthController)

			data, err := authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::user::list"))
			Expect(err).ToNot(HaveOccurred())
			var perm models.Permission
			Expect(json.Unmarshal(data, &perm)).To(Succeed())
			Expect(perm.Name).To(Equal("auth::user::list"))
			Expect(perm.Service).To(Equal("auth"))
			Expect(perm.Action).To(Equal("user::list"))
			Expect(perm.Method).To(Equal("GET"))
			Expect(perm.Path).To(Equal("/ezauth/users/"))
			Expect(perm.System).To(BeTrue())

			data, err = authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::user::create"))
			Expect(err).ToNot(HaveOccurred())
			var perm2 models.Permission
			Expect(json.Unmarshal(data, &perm2)).To(Succeed())
			Expect(perm2.Name).To(Equal("auth::user::create"))
			Expect(perm2.Method).To(Equal("POST"))
			Expect(perm2.Path).To(Equal("/ezauth/users/{id}"))

			// Verify wildcard permission was cached with derived path
			data, err = authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::user::*"))
			Expect(err).ToNot(HaveOccurred())
			var wildcardPerm models.Permission
			Expect(json.Unmarshal(data, &wildcardPerm)).To(Succeed())
			Expect(wildcardPerm.Name).To(Equal("auth::user::*"))
			Expect(wildcardPerm.Service).To(Equal("auth"))
			Expect(wildcardPerm.Action).To(Equal("user::*"))
			Expect(wildcardPerm.Method).To(Equal("ALL"))
			Expect(wildcardPerm.Path).To(Equal("/ezauth/users/*"))
			Expect(wildcardPerm.System).To(BeTrue())

			// Verify global admin wildcard
			data, err = authCtrl.cache.Get(context.Background(), permissionCacheKey("admin::*::*"))
			Expect(err).ToNot(HaveOccurred())
			var adminPerm models.Permission
			Expect(json.Unmarshal(data, &adminPerm)).To(Succeed())
			Expect(adminPerm.Path).To(Equal("/ezauth/*"))

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("should skip routes without names", func() {
			mockDB, mockSQL := setupMockDB(testLogger)

			router := mux.NewRouter()
			// Route without a name — should be skipped
			router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {}).Methods("GET")
			// One named route
			router.HandleFunc("/ezauth/items/", func(w http.ResponseWriter, r *http.Request) {}).
				Methods("GET").Name("svc::item::list")

			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("svc::item::list", "svc", "item::list", "GET", "/ezauth/items/", true)...))
			// Wildcard permission for resource "item"
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("svc::item::*", "svc", "item::*", "ALL", "/ezauth/items/*", true)...))
			// Global admin wildcard
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("admin::*::*", "admin", "admin::*", "ALL", "/ezauth/*", true)...))

			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())
			Expect(ctrl).ToNot(BeNil())

			err = ctrl.RouteWalk(router)
			Expect(err).ToNot(HaveOccurred())

			// Only the named route and its wildcard should be cached
			authCtrl := ctrl.(*AuthController)
			_, err = authCtrl.cache.Get(context.Background(), permissionCacheKey("svc::item::list"))
			Expect(err).ToNot(HaveOccurred())
			_, err = authCtrl.cache.Get(context.Background(), permissionCacheKey("svc::item::*"))
			Expect(err).ToNot(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("should skip routes with names that don't match RBAC format", func() {
			mockDB, mockSQL := setupMockDB(testLogger)

			router := mux.NewRouter()
			// Name doesn't match Service::Resource::Action pattern
			router.HandleFunc("/legacy", func(w http.ResponseWriter, r *http.Request) {}).
				Methods("GET").Name("plain-name")

			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())
			Expect(ctrl).ToNot(BeNil())

			// Nothing should be cached
			authCtrl := ctrl.(*AuthController)
			_, err = authCtrl.cache.Get(context.Background(), permissionCacheKey("plain-name"))
			Expect(err).To(HaveOccurred()) // cache returns ErrNotFound

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("should handle DB save failure gracefully and still cache", func() {
			mockDB, mockSQL := setupMockDB(testLogger)

			router := mux.NewRouter()
			router.HandleFunc("/ezauth/data/", func(w http.ResponseWriter, r *http.Request) {}).
				Methods("DELETE").Name("data::record::delete")

			// DB save: UPDATE first, then fails on INSERT
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnError(&pgconn.PgError{Code: "42P01", Message: "table does not exist"})
			// Wildcard permission for resource "record" — also fails gracefully
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnError(&pgconn.PgError{Code: "42P01", Message: "table does not exist"})
			// Global admin wildcard — also fails gracefully
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
				WillReturnError(&pgconn.PgError{Code: "42P01", Message: "table does not exist"})

			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())
			Expect(ctrl).ToNot(BeNil())

			err = ctrl.RouteWalk(router)
			Expect(err).ToNot(HaveOccurred())

			// The permission should still be in the cache despite DB failure
			authCtrl := ctrl.(*AuthController)
			data, err := authCtrl.cache.Get(context.Background(), permissionCacheKey("data::record::delete"))
			Expect(err).ToNot(HaveOccurred())
			var perm models.Permission
			Expect(json.Unmarshal(data, &perm)).To(Succeed())
			Expect(perm.Name).To(Equal("data::record::delete"))

			// Wildcard should also be cached despite DB failure with derived path
			data, err = authCtrl.cache.Get(context.Background(), permissionCacheKey("data::record::*"))
			Expect(err).ToNot(HaveOccurred())
			var wildcardPerm models.Permission
			Expect(json.Unmarshal(data, &wildcardPerm)).To(Succeed())
			Expect(wildcardPerm.Name).To(Equal("data::record::*"))
			Expect(wildcardPerm.Action).To(Equal("record::*"))
			Expect(wildcardPerm.Path).To(Equal("/ezauth/data/*"))

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("should work without calling RouteWalk", func() {
			mockDB, _ := setupMockDB(testLogger)

			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())
			Expect(ctrl).ToNot(BeNil())
		})
	})

	// ===== Permission CRUD Tests =====

	Describe("Permission CRUD", func() {
		Describe("GetPermission", func() {
			It("should return permission from DB on cache miss", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("auth::user::read", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "auth", "user::read", "GET", "/users/", false)...))

				perm, err := ctrl.GetPermission(context.Background(), "auth::user::read")
				Expect(err).ToNot(HaveOccurred())
				Expect(perm.Name).To(Equal("auth::user::read"))
				Expect(perm.Service).To(Equal("auth"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return permission from cache on cache hit", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				// Pre-populate the cache
				perm := models.Permission{
					Name:    "auth::user::read",
					Service: "auth",
					Action:  "user::read",
					Method:  "GET",
					Path:    "/users/",
				}
				data, _ := json.Marshal(perm)
				_ = authCtrl.cache.Set(context.Background(), permissionCacheKey("auth::user::read"), data, CacheTTL)

				// No DB call expected — should come from cache
				result, err := ctrl.GetPermission(context.Background(), "auth::user::read")
				Expect(err).ToNot(HaveOccurred())
				Expect(result.Name).To(Equal("auth::user::read"))
				Expect(result.Service).To(Equal("auth"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when permission not found", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()))

				_, err := ctrl.GetPermission(context.Background(), "nonexistent")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("ListPermissions", func() {
			It("should return permissions grouped by service", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				rows := mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("auth::user::read", "auth", "user::read", "GET", "/users/", false)...).
					AddRow(createPermissionRow("data::item::list", "data", "item::list", "GET", "/items/", false)...)
				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).WillReturnRows(rows)

				result, err := ctrl.ListPermissions(context.Background(), "", 30, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(HaveKey("auth"))
				Expect(result).To(HaveKey("data"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("AddPermission", func() {
			It("should add permission and invalidate cache", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				// Pre-populate cache to verify invalidation
				_ = authCtrl.cache.Set(context.Background(), permissionCacheKey("auth::item::read"), []byte(`{}`), CacheTTL)

				mockSQL.ExpectBegin()
				mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
					WillReturnRows(mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::item::read", "auth", "item::read", "GET", "/items/", false)...))
				mockSQL.ExpectCommit()

				err := ctrl.AddPermission(context.Background(), &models.Permission{
					Name:    "auth::item::read",
					Service: "auth",
					Action:  "item::read",
					Method:  "GET",
					Path:    "/items/",
					Effect:  true,
				})
				Expect(err).ToNot(HaveOccurred())

				// Cache should be invalidated
				_, cacheErr := authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::item::read"))
				Expect(cacheErr).To(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return conflict error for duplicate permission", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectBegin()
				mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
					WillReturnError(&pgconn.PgError{Code: "23505"})
				mockSQL.ExpectRollback()

				err := ctrl.AddPermission(context.Background(), &models.Permission{
					Name:    "auth::user::read",
					Service: "auth",
					Action:  "user::read",
					Method:  "GET",
					Path:    "/users/",
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("conflict"))
			})
		})

		Describe("UpdatePermission", func() {
			It("should update non-system permission and invalidate cache", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				// GetPermission call (cache miss → DB)
				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("auth::user::read", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "auth", "user::read", "GET", "/users/", false)...))
				// Update call
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mockSQL.ExpectCommit()

				err := ctrl.UpdatePermission(context.Background(), &models.Permission{
					Name:   "auth::user::read",
					Method: "POST",
					Path:   "/users/update",
				})
				Expect(err).ToNot(HaveOccurred())

				// Cache should be invalidated
				_, cacheErr := authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::user::read"))
				Expect(cacheErr).To(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should reject update of system permission", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("auth::system::read", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::system::read", "auth", "system::read", "GET", "/system/", true)...))

				err := ctrl.UpdatePermission(context.Background(), &models.Permission{
					Name:   "auth::system::read",
					Method: "POST",
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("system resource"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when permission not found", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()))

				err := ctrl.UpdatePermission(context.Background(), &models.Permission{Name: "nonexistent"})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("DeletePermission", func() {
			It("should delete non-system permission and invalidate cache", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				// Pre-populate cache with a non-system permission so GetPermission returns from cache
				perm := models.Permission{Name: "auth::user::read", System: false}
				data, _ := json.Marshal(perm)
				_ = authCtrl.cache.Set(context.Background(), permissionCacheKey("auth::user::read"), data, CacheTTL)

				// Delete (GetPermission hits cache, no SELECT needed)
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`DELETE FROM "rbac_permissions"`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mockSQL.ExpectCommit()

				err := ctrl.DeletePermission(context.Background(), "auth::user::read")
				Expect(err).ToNot(HaveOccurred())

				// Cache should be invalidated
				_, cacheErr := authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::user::read"))
				Expect(cacheErr).To(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should reject deletion of system permission", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("auth::system::read", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::system::read", "auth", "system::read", "GET", "/system/", true)...))

				err := ctrl.DeletePermission(context.Background(), "auth::system::read")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("system resource"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when permission not found", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()))

				err := ctrl.DeletePermission(context.Background(), "nonexistent")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})
	})

	// ===== Policy CRUD Tests =====

	Describe("Policy CRUD", func() {
		Describe("GetPolicy", func() {
			It("should return policy from DB on cache miss", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("admin-policy", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("admin-policy", false)...))
				// Preload Permission (many-to-many)
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
				// Preload Roles (many-to-many)
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))

				policy, err := ctrl.GetPolicy(context.Background(), "admin-policy")
				Expect(err).ToNot(HaveOccurred())
				Expect(policy.Name).To(Equal("admin-policy"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return policy from cache on cache hit", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				policy := models.Policy{Name: "admin-policy"}
				data, _ := json.Marshal(policy)
				_ = authCtrl.cache.Set(context.Background(), policyCacheKey("admin-policy"), data, CacheTTL)

				result, err := ctrl.GetPolicy(context.Background(), "admin-policy")
				Expect(err).ToNot(HaveOccurred())
				Expect(result.Name).To(Equal("admin-policy"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when policy not found", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()))

				_, err := ctrl.GetPolicy(context.Background(), "nonexistent")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("ListPolicies", func() {
			It("should return policies list", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				rows := mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("policy-a", false)...).
					AddRow(createPolicyRow("policy-b", false)...)
				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).WillReturnRows(rows)
				// Preload Permission (many-to-many through policy_permissions)
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))

				policies, err := ctrl.ListPolicies(context.Background(), 30, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(policies).To(HaveLen(2))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("AddPolicy", func() {
			It("should add policy and invalidate cache", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				_ = authCtrl.cache.Set(context.Background(), policyCacheKey("new-policy"), []byte(`{}`), CacheTTL)

				mockSQL.ExpectBegin()
				// Validate referenced permission exists
				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("auth::user::read", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "auth", "user::read", "GET", "/users/", false)...))
				// Create policy
				mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
					WillReturnRows(mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("new-policy", false)...))
				// Join table insert
				mockSQL.ExpectQuery(`INSERT INTO "policy_permissions"`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}).
						AddRow("new-policy", "auth::user::read"))
				mockSQL.ExpectCommit()

				err := ctrl.AddPolicy(context.Background(), &models.Policy{
					Name:       "new-policy",
					Permission: []*models.Permission{{Name: "auth::user::read"}},
				})
				Expect(err).ToNot(HaveOccurred())

				_, cacheErr := authCtrl.cache.Get(context.Background(), policyCacheKey("new-policy"))
				Expect(cacheErr).To(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return conflict error for duplicate policy", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectBegin()
				mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
					WillReturnError(&pgconn.PgError{Code: "23505"})
				mockSQL.ExpectRollback()

				err := ctrl.AddPolicy(context.Background(), &models.Policy{Name: "admin-policy"})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("conflict"))
			})

			It("should return error when referenced permission does not exist", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectBegin()
				// Permission validation fails — not found
				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
					WithArgs("nonexistent-perm", 1).
					WillReturnRows(mockSQL.NewRows(permissionColumns()))
				mockSQL.ExpectRollback()

				err := ctrl.AddPolicy(context.Background(), &models.Policy{
					Name:       "bad-policy",
					Permission: []*models.Permission{{Name: "nonexistent-perm"}},
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("does not exist"))
			})
		})

		Describe("UpdatePolicy", func() {
			It("should reject update of system policy", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("system-policy", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("system-policy", true)...))
				// Preload Permission
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
				// Preload Roles
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))

				err := ctrl.UpdatePolicy(context.Background(), "system-policy", &models.Policy{Name: "system-policy"})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("system resource"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when policy not found for update", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()))

				err := ctrl.UpdatePolicy(context.Background(), "nonexistent", &models.Policy{Name: "nonexistent"})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("DeletePolicy", func() {
			It("should reject deletion of system policy", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("system-policy", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("system-policy", true)...))
				// Preload Permission
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
				// Preload Roles
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))

				err := ctrl.DeletePolicy(context.Background(), "system-policy")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("system resource"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when policy not found for delete", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()))

				err := ctrl.DeletePolicy(context.Background(), "nonexistent")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should delete non-system policy and invalidate cache", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				// Pre-populate cache with a non-system policy so GetPolicy returns from cache
				policy := models.Policy{Name: "test-policy", System: false}
				data, _ := json.Marshal(policy)
				_ = authCtrl.cache.Set(context.Background(), policyCacheKey("test-policy"), data, CacheTTL)

				// GetUserIDsByPolicy runs before deletion
				mockSQL.ExpectQuery(`SELECT DISTINCT ru\.user_db_id`).
					WithArgs("test-policy").
					WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}))

				// DeletePolicy: Clear + Delete wrapped in a single transaction
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`DELETE FROM "policy_permissions"`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mockSQL.ExpectExec(`DELETE FROM "rbac_policies"`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mockSQL.ExpectCommit()

				err := ctrl.DeletePolicy(context.Background(), "test-policy")
				Expect(err).ToNot(HaveOccurred())

				_, cacheErr := authCtrl.cache.Get(context.Background(), policyCacheKey("test-policy"))
				Expect(cacheErr).To(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error and rollback when Clear fails", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				policy := models.Policy{Name: "test-policy", System: false}
				data, _ := json.Marshal(policy)
				_ = authCtrl.cache.Set(context.Background(), policyCacheKey("test-policy"), data, CacheTTL)

				mockSQL.ExpectQuery(`SELECT DISTINCT ru\.user_db_id`).
					WithArgs("test-policy").
					WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}))

				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`DELETE FROM "policy_permissions"`).
					WillReturnError(fmt.Errorf("association clear failed"))
				mockSQL.ExpectRollback()

				err := ctrl.DeletePolicy(context.Background(), "test-policy")
				Expect(err).To(HaveOccurred())

				// Cache entry should remain since deletion did not complete
				_, cacheErr := authCtrl.cache.Get(context.Background(), policyCacheKey("test-policy"))
				Expect(cacheErr).ToNot(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})
	})

	// ===== Role CRUD Tests =====

	Describe("Role CRUD", func() {
		Describe("GetRole", func() {
			It("should return role from DB on cache miss", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
					WithArgs("admin", 1).
					WillReturnRows(mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("admin", false)...))
				// Preload Policies
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
				// Preload Groups
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))

				role, err := ctrl.GetRole(context.Background(), "admin")
				Expect(err).ToNot(HaveOccurred())
				Expect(role.RoleName).To(Equal("admin"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return role from cache on cache hit", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				role := models.RoleDB{RoleName: "admin"}
				data, _ := json.Marshal(role)
				_ = authCtrl.cache.Set(context.Background(), roleCacheKey("admin"), data, CacheTTL)

				result, err := ctrl.GetRole(context.Background(), "admin")
				Expect(err).ToNot(HaveOccurred())
				Expect(result.RoleName).To(Equal("admin"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when role not found", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(roleColumns()))

				_, err := ctrl.GetRole(context.Background(), "nonexistent")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("ListRoles", func() {
			It("should return roles list", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				rows := mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("admin", false)...).
					AddRow(createRoleRow("viewer", false)...)
				mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).WillReturnRows(rows)

				roles, err := ctrl.ListRoles(context.Background(), 30, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(roles).To(HaveLen(2))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("AddRole", func() {
			It("should add role and invalidate cache", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				_ = authCtrl.cache.Set(context.Background(), roleCacheKey("new-role"), []byte(`{}`), CacheTTL)

				mockSQL.ExpectBegin()
				// Validate referenced policy exists
				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("admin-policy", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("admin-policy", false)...))
				// Create role
				mockSQL.ExpectQuery(`INSERT INTO "roles"`).
					WillReturnRows(mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("new-role", false)...))
				// GORM upserts the associated policy
				mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
					WillReturnRows(mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("admin-policy", false)...))
				// Join table insert
				mockSQL.ExpectQuery(`INSERT INTO "policy_roles"`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}).
						AddRow("admin-policy", "550e8400-e29b-41d4-a716-446655440000"))
				mockSQL.ExpectCommit()

				err := ctrl.AddRole(context.Background(), &models.RoleDB{
					RoleName: "new-role",
					Policies: []*models.Policy{{Name: "admin-policy"}},
				})
				Expect(err).ToNot(HaveOccurred())

				_, cacheErr := authCtrl.cache.Get(context.Background(), roleCacheKey("new-role"))
				Expect(cacheErr).To(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return conflict error for duplicate role", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectBegin()
				mockSQL.ExpectQuery(`INSERT INTO "roles"`).
					WillReturnError(&pgconn.PgError{Code: "23505"})
				mockSQL.ExpectRollback()

				err := ctrl.AddRole(context.Background(), &models.RoleDB{RoleName: "admin"})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("conflict"))
			})

			It("should return error when referenced policy does not exist", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectBegin()
				mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
					WithArgs("nonexistent-policy", 1).
					WillReturnRows(mockSQL.NewRows(policyColumns()))
				mockSQL.ExpectRollback()

				err := ctrl.AddRole(context.Background(), &models.RoleDB{
					RoleName: "bad-role",
					Policies: []*models.Policy{{Name: "nonexistent-policy"}},
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("does not exist"))
			})
		})

		Describe("UpdateRole", func() {
			It("should reject update of system role", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
					WithArgs("system-admin", 1).
					WillReturnRows(mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("system-admin", true)...))
				// Preload Policies
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
				// Preload Groups
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))

				err := ctrl.UpdateRole(context.Background(), "system-admin", &models.RoleDB{RoleName: "system-admin"})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("system resource"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when role not found for update", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(roleColumns()))

				err := ctrl.UpdateRole(context.Background(), "nonexistent", &models.RoleDB{RoleName: "nonexistent"})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})

		Describe("DeleteRole", func() {
			It("should reject deletion of system role", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
					WithArgs("system-admin", 1).
					WillReturnRows(mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("system-admin", true)...))
				// Preload Policies
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
				// Preload Groups
				mockSQL.ExpectQuery(`.+`).
					WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))

				err := ctrl.DeleteRole(context.Background(), "system-admin")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("system resource"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should return error when role not found for delete", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

				mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
					WithArgs("nonexistent", 1).
					WillReturnRows(mockSQL.NewRows(roleColumns()))

				err := ctrl.DeleteRole(context.Background(), "nonexistent")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("record not found"))

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})

			It("should delete non-system role and invalidate cache", func() {
				mockDB, mockSQL := setupMockDB(testLogger)
				ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
				authCtrl := ctrl.(*AuthController)

				// Pre-populate cache with a non-system role so GetRole returns from cache
				role := models.RoleDB{RoleName: "test-role", System: false}
				data, _ := json.Marshal(role)
				_ = authCtrl.cache.Set(context.Background(), roleCacheKey("test-role"), data, CacheTTL)

				// Delete (GetRole hits cache, no SELECT needed)
				mockSQL.ExpectBegin()
				mockSQL.ExpectExec(`DELETE FROM "roles"`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mockSQL.ExpectCommit()

				err := ctrl.DeleteRole(context.Background(), "test-role")
				Expect(err).ToNot(HaveOccurred())

				_, cacheErr := authCtrl.cache.Get(context.Background(), roleCacheKey("test-role"))
				Expect(cacheErr).To(HaveOccurred())

				Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
			})
		})
	})

	// ===== parsePermission Tests =====

	Describe("parsePermission", func() {
		It("should parse valid permission string", func() {
			svc, resource, action, err := parsePermission("auth::user::read")
			Expect(err).ToNot(HaveOccurred())
			Expect(svc).To(Equal("auth"))
			Expect(resource).To(Equal("user"))
			Expect(action).To(Equal("read"))
		})

		It("should reject invalid permission string", func() {
			_, _, _, err := parsePermission("invalid")
			Expect(err).To(HaveOccurred())
		})

		It("should reject empty string", func() {
			_, _, _, err := parsePermission("")
			Expect(err).To(HaveOccurred())
		})

		It("should reject single-segment name", func() {
			_, _, _, err := parsePermission("only-one-part")
			Expect(err).To(HaveOccurred())
		})

		It("should parse permission with hyphens and digits", func() {
			svc, resource, action, err := parsePermission("svc-1::res_2::act-3")
			Expect(err).ToNot(HaveOccurred())
			Expect(svc).To(Equal("svc-1"))
			Expect(resource).To(Equal("res_2"))
			Expect(action).To(Equal("act-3"))
		})
	})

	// ===== Cache key helpers =====

	Describe("Cache key helpers", func() {
		It("should generate correct cache keys", func() {
			Expect(string(permissionCacheKey("test"))).To(Equal(PermissionCachePrefix + "test"))
			Expect(string(policyCacheKey("test"))).To(Equal(PolicyCachePrefix + "test"))
			Expect(string(roleCacheKey("test"))).To(Equal(RoleCachePrefix + "test"))
		})
	})

	// ===== Cache behavior =====

	Describe("Cache behavior", func() {
		It("should cache permission after first DB fetch", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WithArgs("auth::user::read", 1).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("auth::user::read", "auth", "user::read", "GET", "/users/", false)...))

			// First call — DB hit
			perm, err := ctrl.GetPermission(context.Background(), "auth::user::read")
			Expect(err).ToNot(HaveOccurred())
			Expect(perm.Name).To(Equal("auth::user::read"))

			// Verify it's now in cache
			data, err := authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::user::read"))
			Expect(err).ToNot(HaveOccurred())
			Expect(data).ToNot(BeEmpty())

			// Second call — should come from cache (no additional DB expectation)
			perm2, err := ctrl.GetPermission(context.Background(), "auth::user::read")
			Expect(err).ToNot(HaveOccurred())
			Expect(perm2.Name).To(Equal("auth::user::read"))

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("should cache policy after first DB fetch", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WithArgs("test-policy", 1).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("test-policy", false)...))
			// Preload Permission (many-to-many)
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
			// Preload Roles (many-to-many)
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))

			policy, err := ctrl.GetPolicy(context.Background(), "test-policy")
			Expect(err).ToNot(HaveOccurred())
			Expect(policy.Name).To(Equal("test-policy"))

			data, err := authCtrl.cache.Get(context.Background(), policyCacheKey("test-policy"))
			Expect(err).ToNot(HaveOccurred())
			Expect(data).ToNot(BeEmpty())

			policy2, err := ctrl.GetPolicy(context.Background(), "test-policy")
			Expect(err).ToNot(HaveOccurred())
			Expect(policy2.Name).To(Equal("test-policy"))

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("should cache role after first DB fetch", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WithArgs("test-role", 1).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("test-role", false)...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))

			role, err := ctrl.GetRole(context.Background(), "test-role")
			Expect(err).ToNot(HaveOccurred())
			Expect(role.RoleName).To(Equal("test-role"))

			data, err := authCtrl.cache.Get(context.Background(), roleCacheKey("test-role"))
			Expect(err).ToNot(HaveOccurred())
			Expect(data).ToNot(BeEmpty())

			role2, err := ctrl.GetRole(context.Background(), "test-role")
			Expect(err).ToNot(HaveOccurred())
			Expect(role2.RoleName).To(Equal("test-role"))

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	// ===== NewController validation =====

	Describe("NewController", func() {
		It("should use provided AuthConfig", func() {
			mockDB, _ := setupMockDB(testLogger)
			rbacCfg := &ezcfg.RBACConfig{Enabled: true}
			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, rbacCfg, mockDB, testCache(), "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())

			authCtrl := ctrl.(*AuthController)
			Expect(authCtrl.rbacCfg.Enabled).To(BeTrue())
		})

		It("should initialize cache", func() {
			mockDB, _ := setupMockDB(testLogger)
			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())

			authCtrl := ctrl.(*AuthController)
			Expect(authCtrl.cache).ToNot(BeNil())

			// Verify cache is functional
			_ = authCtrl.cache.Set(context.Background(), "test-key", []byte("test-value"), CacheTTL)
			val, err := authCtrl.cache.Get(context.Background(), "test-key")
			Expect(err).ToNot(HaveOccurred())
			Expect(string(val)).To(Equal("test-value"))
		})
	})
})

var _ = Describe("RBACErr", func() {
	Describe("Unwrap", func() {
		It("returns the embedded GeneralError", func() {
			inner := ezerror.GeneralError{Code: 403, Err: "forbidden"}
			e := &RBACErr{GeneralError: inner}

			wrapped := e.Unwrap()
			Expect(wrapped).ToNot(BeNil())

			var ge *ezerror.GeneralError
			Expect(errors.As(wrapped, &ge)).To(BeTrue())
			Expect(ge.Code).To(Equal(403))
			Expect(ge.Err).To(Equal("forbidden"))
		})

		It("allows errors.Is to unwrap sentinel errors", func() {
			Expect(errors.Is(ErrSystemResource, ErrSystemResource)).To(BeTrue())
			Expect(errors.Is(ErrExplicitDeny, ErrExplicitDeny)).To(BeTrue())
			Expect(errors.Is(ErrNoSession, ErrNoSession)).To(BeTrue())
		})
	})
})

var _ = Describe("wildcardPathFromPaths", func() {
	It("returns empty string for nil input", func() {
		Expect(wildcardPathFromPaths(nil)).To(Equal(""))
	})

	It("returns empty string for empty slice", func() {
		Expect(wildcardPathFromPaths([]string{})).To(Equal(""))
	})

	It("handles a single path ending with slash", func() {
		Expect(wildcardPathFromPaths([]string{"/admin/users/"})).To(Equal("/admin/users/*"))
	})

	It("handles a single path without trailing slash", func() {
		Expect(wildcardPathFromPaths([]string{"/admin/users/{id}"})).To(Equal("/admin/users/*"))
	})

	It("derives the common directory prefix from multiple paths sharing a parent", func() {
		paths := []string{"/admin/users/", "/admin/users/{id}"}
		Expect(wildcardPathFromPaths(paths)).To(Equal("/admin/users/*"))
	})

	It("falls back to root wildcard when paths share no directory prefix", func() {
		paths := []string{"/admin/users/", "/other/items/"}
		Expect(wildcardPathFromPaths(paths)).To(Equal("/*"))
	})

	It("handles a path with no slash at all", func() {
		Expect(wildcardPathFromPaths([]string{"nopath"})).To(Equal("/*"))
	})

	It("uses the common intermediate directory for three related paths", func() {
		paths := []string{
			"/api/v1/users/",
			"/api/v1/users/{id}",
			"/api/v1/users/{id}/roles",
		}
		Expect(wildcardPathFromPaths(paths)).To(Equal("/api/v1/users/*"))
	})
})

var _ = Describe("Role Associations", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	Describe("AddRoleToUser", func() {
		It("evicts user permission cache on success", func() {
			mockDB, mockSQL := setupMockDB(testLogger, false)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			userID := uuid.New().String()

			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+userID, []byte(`[]`), CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(userID, 1).
				WillReturnRows(mockSQL.NewRows(userColumns()).
					AddRow(createUserRow(userID, "alice")...))
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("viewer", false)...))
			mockSQL.ExpectQuery(`INSERT INTO "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("viewer", false)...))
			mockSQL.ExpectExec(`UPDATE "users"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectQuery(`INSERT INTO "user_roles"`).
				WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "role_db_id"}).
					AddRow(userID, "550e8400-e29b-41d4-a716-446655440000"))
			mockSQL.ExpectCommit()

			err := ctrl.AddRoleToUser(context.Background(), userID, []string{"viewer"})
			Expect(err).ToNot(HaveOccurred())

			_, cacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+userID)
			Expect(cacheErr).To(HaveOccurred())
		})

		It("propagates DB error and does not evict cache", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			userID := uuid.New().String()
			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+userID, []byte(`[]`), CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(userID, 1).
				WillReturnRows(mockSQL.NewRows(userColumns()))
			mockSQL.ExpectRollback()

			err := ctrl.AddRoleToUser(context.Background(), userID, []string{"viewer"})
			Expect(err).To(HaveOccurred())

			_, cacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+userID)
			Expect(cacheErr).ToNot(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("RemoveRoleFromUser", func() {
		It("evicts user permission cache on success", func() {
			mockDB, mockSQL := setupMockDB(testLogger, false)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			userID := uuid.New().String()
			roleID := "550e8400-e29b-41d4-a716-446655440000"

			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+userID, []byte(`[]`), CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(userID, 1).
				WillReturnRows(mockSQL.NewRows(userColumns()).
					AddRow(createUserRow(userID, "alice")...))
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("viewer", false)...))
			mockSQL.ExpectExec(`DELETE FROM "user_roles"`).
				WithArgs(userID, roleID).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectCommit()

			err := ctrl.RemoveRoleFromUser(context.Background(), userID, []string{"viewer"})
			Expect(err).ToNot(HaveOccurred())

			_, cacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+userID)
			Expect(cacheErr).To(HaveOccurred())
		})

		It("propagates DB error", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			userID := uuid.New().String()

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(userID, 1).
				WillReturnRows(mockSQL.NewRows(userColumns()))
			mockSQL.ExpectRollback()

			err := ctrl.RemoveRoleFromUser(context.Background(), userID, []string{"viewer"})
			Expect(err).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("AddRoleToGroup", func() {
		It("evicts group member permission cache entries on success", func() {
			mockDB, mockSQL := setupMockDB(testLogger, false)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			memberID := uuid.New().String()
			groupID := uuid.New().String()
			roleID := "550e8400-e29b-41d4-a716-446655440000"

			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+memberID, []byte(`[]`), CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("eng", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()).
					AddRow([]driver.Value{groupID, "eng", time.Now(), time.Now()}...))
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("viewer", false)...))
			mockSQL.ExpectQuery(`INSERT INTO "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("viewer", false)...))
			mockSQL.ExpectExec(`UPDATE "groups"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectQuery(`INSERT INTO "group_roles"`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}).
					AddRow(groupID, roleID))
			mockSQL.ExpectCommit()

			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("eng", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()).
					AddRow([]driver.Value{groupID, "eng", time.Now(), time.Now()}...))
			mockSQL.ExpectQuery(`SELECT \* FROM "group_roles"`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
			mockSQL.ExpectQuery(`SELECT \* FROM "user_groups"`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "user_db_id"}).
					AddRow(groupID, memberID))
			mockSQL.ExpectQuery(`SELECT .+ FROM "users"`).
				WillReturnRows(mockSQL.NewRows([]string{"id", "username"}).
					AddRow(memberID, "alice"))

			err := ctrl.AddRoleToGroup(context.Background(), "eng", []string{"viewer"})
			Expect(err).ToNot(HaveOccurred())

			_, cacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+memberID)
			Expect(cacheErr).To(HaveOccurred())
		})

		It("propagates DB error on add failure", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("unknown-group", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()))
			mockSQL.ExpectRollback()

			err := ctrl.AddRoleToGroup(context.Background(), "unknown-group", []string{"viewer"})
			Expect(err).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("RemoveRoleFromGroup", func() {
		It("evicts group member permission cache entries on success", func() {
			mockDB, mockSQL := setupMockDB(testLogger, false)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			memberID := uuid.New().String()
			groupID := uuid.New().String()
			roleID := "550e8400-e29b-41d4-a716-446655440000"

			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+memberID, []byte(`[]`), CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("eng", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()).
					AddRow([]driver.Value{groupID, "eng", time.Now(), time.Now()}...))
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("viewer", false)...))
			mockSQL.ExpectExec(`DELETE FROM "group_roles"`).
				WithArgs(groupID, roleID).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectCommit()

			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("eng", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()).
					AddRow([]driver.Value{groupID, "eng", time.Now(), time.Now()}...))
			mockSQL.ExpectQuery(`SELECT \* FROM "group_roles"`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
			mockSQL.ExpectQuery(`SELECT \* FROM "user_groups"`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "user_db_id"}).
					AddRow(groupID, memberID))
			mockSQL.ExpectQuery(`SELECT .+ FROM "users"`).
				WillReturnRows(mockSQL.NewRows([]string{"id", "username"}).
					AddRow(memberID, "alice"))

			err := ctrl.RemoveRoleFromGroup(context.Background(), "eng", []string{"viewer"})
			Expect(err).ToNot(HaveOccurred())

			_, cacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+memberID)
			Expect(cacheErr).To(HaveOccurred())
		})

		It("propagates DB error on remove failure", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("unknown-group", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()))
			mockSQL.ExpectRollback()

			err := ctrl.RemoveRoleFromGroup(context.Background(), "unknown-group", []string{"viewer"})
			Expect(err).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})
})

var _ = Describe("Permission resolution", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	Describe("GetUserPermissions", func() {
		It("returns permissions from DB and caches the result on cache miss", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			userID := uuid.New().String()

			mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(userID, 1).
				WillReturnRows(mockSQL.NewRows(userColumns()).
					AddRow(createUserRow(userID, "alice")...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "role_db_id"}))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}))

			perms, err := ctrl.GetUserPermissions(context.Background(), userID)
			Expect(err).ToNot(HaveOccurred())
			Expect(perms).To(BeEmpty())

			data, cacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+userID)
			Expect(cacheErr).ToNot(HaveOccurred())
			var cached []*models.Permission
			Expect(json.Unmarshal(data, &cached)).To(Succeed())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("returns permissions from cache on cache hit (no DB call)", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			userID := uuid.New().String()
			expectedPerms := []*models.Permission{
				{Name: "auth::user::read", Effect: true, Path: "/users/", Method: "GET"},
			}
			data, _ := json.Marshal(expectedPerms)
			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+userID, data, CacheTTL)

			perms, err := ctrl.GetUserPermissions(context.Background(), userID)
			Expect(err).ToNot(HaveOccurred())
			Expect(perms).To(HaveLen(1))
			Expect(perms[0].Name).To(Equal("auth::user::read"))

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("propagates DB error", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			userID := uuid.New().String()
			mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(userID, 1).
				WillReturnError(fmt.Errorf("db connection error"))

			_, err := ctrl.GetUserPermissions(context.Background(), userID)
			Expect(err).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("GetGroupPermissions", func() {
		It("returns permissions for a group from DB", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("eng", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()).
					AddRow(createGroupRow("eng")...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))

			perms, err := ctrl.GetGroupPermissions(context.Background(), "eng")
			Expect(err).ToNot(HaveOccurred())
			Expect(perms).To(BeEmpty())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("propagates DB error when group not found", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("nonexistent", 1).
				WillReturnRows(mockSQL.NewRows(groupColumns()))

			_, err := ctrl.GetGroupPermissions(context.Background(), "nonexistent")
			Expect(err).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("GetRolePermissions", func() {
		It("returns permissions for a role from DB", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WithArgs("viewer", 1).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("viewer", false)...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"name", "system", "created_at", "updated_at"}))

			perms, err := ctrl.GetRolePermissions(context.Background(), "viewer")
			Expect(err).ToNot(HaveOccurred())
			Expect(perms).To(BeEmpty())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("propagates DB error when role not found", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WithArgs("nonexistent", 1).
				WillReturnRows(mockSQL.NewRows(roleColumns()))

			_, err := ctrl.GetRolePermissions(context.Background(), "nonexistent")
			Expect(err).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})
})

var _ = Describe("UpdatePolicy and UpdateRole cache invalidation", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	Describe("UpdatePolicy success path (covers invalidateUserPermissionsByPolicy)", func() {
		It("evicts policy cache and affected user permission cache after update", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			userID := uuid.New().String()

			policy := models.Policy{Name: "my-policy", System: false}
			policyData, _ := json.Marshal(policy)
			_ = authCtrl.cache.Set(context.Background(), policyCacheKey("my-policy"), policyData, CacheTTL)
			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+userID, []byte(`[]`), CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectExec(`UPDATE "rbac_policies"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("my-policy", false)...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()))
			mockSQL.ExpectExec(`DELETE FROM "policy_permissions"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectCommit()

			mockSQL.ExpectQuery(`SELECT DISTINCT ru\.user_db_id`).
				WithArgs("my-policy").
				WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}).
					AddRow(userID))

			err := ctrl.UpdatePolicy(context.Background(), "my-policy", &models.Policy{Name: "my-policy"})
			Expect(err).ToNot(HaveOccurred())

			_, pCacheErr := authCtrl.cache.Get(context.Background(), policyCacheKey("my-policy"))
			Expect(pCacheErr).To(HaveOccurred())

			_, uCacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+userID)
			Expect(uCacheErr).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("does not propagate error when GetUserIDsByPolicy fails (best-effort)", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			policy := models.Policy{Name: "my-policy", System: false}
			policyData, _ := json.Marshal(policy)
			_ = authCtrl.cache.Set(context.Background(), policyCacheKey("my-policy"), policyData, CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectExec(`UPDATE "rbac_policies"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("my-policy", false)...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()))
			mockSQL.ExpectExec(`DELETE FROM "policy_permissions"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectCommit()

			mockSQL.ExpectQuery(`SELECT DISTINCT ru\.user_db_id`).
				WithArgs("my-policy").
				WillReturnError(fmt.Errorf("db error"))

			err := ctrl.UpdatePolicy(context.Background(), "my-policy", &models.Policy{Name: "my-policy"})
			Expect(err).ToNot(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("UpdateRole success path (covers invalidateUserPermissionsByRole)", func() {
		It("evicts role cache and affected user permission cache after update", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			userID := uuid.New().String()

			role := models.RoleDB{RoleName: "editor", System: false}
			roleData, _ := json.Marshal(role)
			_ = authCtrl.cache.Set(context.Background(), roleCacheKey("editor"), roleData, CacheTTL)
			_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+userID, []byte(`[]`), CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectExec(`UPDATE "roles"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("editor", false)...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows(policyColumns()))
			mockSQL.ExpectExec(`DELETE FROM "policy_roles"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectCommit()

			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WithArgs("editor", 1).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("editor", false)...))
			mockSQL.ExpectQuery(`SELECT user_db_id FROM user_roles`).
				WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}).
					AddRow(userID))
			mockSQL.ExpectQuery(`SELECT group_db_id FROM group_roles`).
				WillReturnRows(mockSQL.NewRows([]string{"group_db_id"}))

			err := ctrl.UpdateRole(context.Background(), "editor", &models.RoleDB{RoleName: "editor"})
			Expect(err).ToNot(HaveOccurred())

			_, rCacheErr := authCtrl.cache.Get(context.Background(), roleCacheKey("editor"))
			Expect(rCacheErr).To(HaveOccurred())

			_, uCacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+userID)
			Expect(uCacheErr).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("does not propagate error when GetUserIDsByRole fails (best-effort)", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			role := models.RoleDB{RoleName: "editor", System: false}
			roleData, _ := json.Marshal(role)
			_ = authCtrl.cache.Set(context.Background(), roleCacheKey("editor"), roleData, CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectExec(`UPDATE "roles"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("editor", false)...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows(policyColumns()))
			mockSQL.ExpectExec(`DELETE FROM "policy_roles"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectCommit()

			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WithArgs("editor", 1).
				WillReturnError(fmt.Errorf("database down"))

			err := ctrl.UpdateRole(context.Background(), "editor", &models.RoleDB{RoleName: "editor"})
			Expect(err).ToNot(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})
})

var _ = Describe("invalidateGroupUserPermissions: GetGroup failure (via AddRoleToGroup)", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	It("logs a warning and does not propagate when GetGroup fails after a successful add", func() {
		mockDB, mockSQL := setupMockDB(testLogger, false)
		ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

		groupID := uuid.New().String()

		mockSQL.ExpectBegin()
		mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
			WithArgs("ghost-group", 1).
			WillReturnRows(mockSQL.NewRows(groupColumns()).
				AddRow([]driver.Value{groupID, "ghost-group", time.Now(), time.Now()}...))
		mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
			WillReturnRows(mockSQL.NewRows(roleColumns()).
				AddRow(createRoleRow("viewer", false)...))
		mockSQL.ExpectQuery(`INSERT INTO "roles"`).
			WillReturnRows(mockSQL.NewRows(roleColumns()).
				AddRow(createRoleRow("viewer", false)...))
		mockSQL.ExpectExec(`UPDATE "groups"`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mockSQL.ExpectQuery(`INSERT INTO "group_roles"`).
			WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}).
				AddRow(groupID, "550e8400-e29b-41d4-a716-446655440000"))
		mockSQL.ExpectCommit()

		mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
			WithArgs("ghost-group", 1).
			WillReturnRows(mockSQL.NewRows(groupColumns()))

		err := ctrl.AddRoleToGroup(context.Background(), "ghost-group", []string{"viewer"})
		Expect(err).ToNot(HaveOccurred())
	})
})

var _ = Describe("SeedDefaults", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	It("returns error when the transaction cannot begin", func() {
		mockDB, mockSQL := setupMockDB(testLogger)
		ctx := ezlog.ServerContext(context.Background(), testLogger)
		ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
		Expect(err).ToNot(HaveOccurred())

		mockSQL.ExpectBegin().WillReturnError(fmt.Errorf("cannot begin transaction"))

		err = ctrl.SeedDefaults()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("seed defaults transaction"))
	})

	It("completes without error when all policies and roles seed successfully (no admin group)", func() {
		mockDB, mockSQL := setupMockDB(testLogger, false)
		ctx := ezlog.ServerContext(context.Background(), testLogger)
		ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
		Expect(err).ToNot(HaveOccurred())

		mockSQL.ExpectBegin()

		nPolicies := len(defaultPolicies)
		for i := 0; i < nPolicies; i++ {
			mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("any-policy", true)...))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()))
			mockSQL.ExpectExec(`UPDATE "rbac_policies"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectExec(`DELETE FROM "policy_permissions"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		nRoles := len(defaultRoles)
		for i := 0; i < nRoles; i++ {
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()))
			mockSQL.ExpectQuery(`INSERT INTO "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("any-role", true)...))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("any-policy", true)...))
			mockSQL.ExpectExec(`UPDATE "roles"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectExec(`DELETE FROM "policy_roles"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "policy_roles"`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}).
					AddRow("any-policy", "550e8400-e29b-41d4-a716-446655440000"))
		}

		mockSQL.ExpectCommit()

		err = ctrl.SeedDefaults()
		Expect(err).ToNot(HaveOccurred())
	})

	It("completes without error and binds system-admin role to admin group when adminGroupName is set", func() {
		mockDB, mockSQL := setupMockDB(testLogger, false)
		ctx := ezlog.ServerContext(context.Background(), testLogger)
		ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "admin")
		Expect(err).ToNot(HaveOccurred())

		mockSQL.ExpectBegin()

		nPolicies := len(defaultPolicies)
		for i := 0; i < nPolicies; i++ {
			mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("any-policy", true)...))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WillReturnRows(mockSQL.NewRows(permissionColumns()))
			mockSQL.ExpectExec(`UPDATE "rbac_policies"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectExec(`DELETE FROM "policy_permissions"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		nRoles := len(defaultRoles)
		for i := 0; i < nRoles; i++ {
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()))
			mockSQL.ExpectQuery(`INSERT INTO "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("any-role", true)...))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("any-policy", true)...))
			mockSQL.ExpectExec(`UPDATE "roles"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectExec(`DELETE FROM "policy_roles"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectQuery(`INSERT INTO "policy_roles"`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}).
					AddRow("any-policy", "550e8400-e29b-41d4-a716-446655440000"))
		}

		adminGroupID := uuid.New().String()
		mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
			WithArgs("admin", 1).
			WillReturnRows(mockSQL.NewRows(groupColumns()).
				AddRow([]driver.Value{adminGroupID, "admin", time.Now(), time.Now()}...))
		mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
			WithArgs("system-admin", 1).
			WillReturnRows(mockSQL.NewRows(roleColumns()).
				AddRow(createRoleRow("system-admin", true)...))
		mockSQL.ExpectExec(`UPDATE "groups"`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mockSQL.ExpectExec(`DELETE FROM "group_roles"`).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mockSQL.ExpectQuery(`INSERT INTO "group_roles"`).
			WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}).
				AddRow(adminGroupID, "550e8400-e29b-41d4-a716-446655440000"))

		mockSQL.ExpectCommit()

		err = ctrl.SeedDefaults()
		Expect(err).ToNot(HaveOccurred())
	})

	It("tolerates policy insert errors (res.Error != nil → logs Debug and continues)", func() {
		mockDB, mockSQL := setupMockDB(testLogger, false)
		ctx := ezlog.ServerContext(context.Background(), testLogger)
		ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
		Expect(err).ToNot(HaveOccurred())

		mockSQL.ExpectBegin()

		nPolicies := len(defaultPolicies)
		for i := 0; i < nPolicies; i++ {
			mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
				WillReturnError(fmt.Errorf("unique violation"))
		}

		nRoles := len(defaultRoles)
		for i := 0; i < nRoles; i++ {
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnError(fmt.Errorf("db error"))
		}

		mockSQL.ExpectCommit()

		err = ctrl.SeedDefaults()
		Expect(err).ToNot(HaveOccurred())
	})

	It("tolerates permission fetch failure within policy seeding (continues to next policy)", func() {
		mockDB, mockSQL := setupMockDB(testLogger, false)
		ctx := ezlog.ServerContext(context.Background(), testLogger)
		ctrl, err := NewController(ctx, nil, mockDB, testCache(), "/ezauth", "")
		Expect(err).ToNot(HaveOccurred())

		mockSQL.ExpectBegin()

		nPolicies := len(defaultPolicies)
		for i := 0; i < nPolicies; i++ {
			mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("any-policy", true)...))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WillReturnError(fmt.Errorf("permissions table missing"))
		}

		nRoles := len(defaultRoles)
		for i := 0; i < nRoles; i++ {
			mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
				WillReturnRows(mockSQL.NewRows(roleColumns()).
					AddRow(createRoleRow("any-role", true)...))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WillReturnError(fmt.Errorf("policies table missing"))
		}

		mockSQL.ExpectCommit()

		err = ctrl.SeedDefaults()
		Expect(err).ToNot(HaveOccurred())
	})
})

var _ = Describe("DeleteRole cache eviction", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	It("evicts affected user permission cache entries after deleting a non-system role", func() {
		mockDB, mockSQL := setupMockDB(testLogger)
		ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
		authCtrl := ctrl.(*AuthController)

		userID := uuid.New().String()

		role := models.RoleDB{RoleName: "temp-role", System: false}
		roleData, _ := json.Marshal(role)
		_ = authCtrl.cache.Set(context.Background(), roleCacheKey("temp-role"), roleData, CacheTTL)
		_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+userID, []byte(`[]`), CacheTTL)

		mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
			WithArgs("temp-role", 1).
			WillReturnRows(mockSQL.NewRows(roleColumns()).
				AddRow(createRoleRow("temp-role", false)...))
		mockSQL.ExpectQuery(`SELECT user_db_id FROM user_roles`).
			WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}).
				AddRow(userID))
		mockSQL.ExpectQuery(`SELECT group_db_id FROM group_roles`).
			WillReturnRows(mockSQL.NewRows([]string{"group_db_id"}))

		mockSQL.ExpectBegin()
		mockSQL.ExpectExec(`DELETE FROM "roles"`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mockSQL.ExpectCommit()

		err := ctrl.DeleteRole(context.Background(), "temp-role")
		Expect(err).ToNot(HaveOccurred())

		_, rCacheErr := authCtrl.cache.Get(context.Background(), roleCacheKey("temp-role"))
		Expect(rCacheErr).To(HaveOccurred())

		_, uCacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+userID)
		Expect(uCacheErr).To(HaveOccurred())

		Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
	})

	It("evicts group member permission cache entries when group has this role", func() {
		mockDB, mockSQL := setupMockDB(testLogger)
		ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
		authCtrl := ctrl.(*AuthController)

		groupID := uuid.New().String()
		groupMemberID := uuid.New().String()

		role := models.RoleDB{RoleName: "dept-role", System: false}
		roleData, _ := json.Marshal(role)
		_ = authCtrl.cache.Set(context.Background(), roleCacheKey("dept-role"), roleData, CacheTTL)
		_ = authCtrl.cache.Set(context.Background(), UserPermissionCachePrefix+groupMemberID, []byte(`[]`), CacheTTL)

		mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
			WithArgs("dept-role", 1).
			WillReturnRows(mockSQL.NewRows(roleColumns()).
				AddRow(createRoleRow("dept-role", false)...))
		mockSQL.ExpectQuery(`SELECT user_db_id FROM user_roles`).
			WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}))
		mockSQL.ExpectQuery(`SELECT group_db_id FROM group_roles`).
			WillReturnRows(mockSQL.NewRows([]string{"group_db_id"}).
				AddRow(groupID))
		mockSQL.ExpectQuery(`SELECT user_db_id FROM user_groups`).
			WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}).
				AddRow(groupMemberID))

		mockSQL.ExpectBegin()
		mockSQL.ExpectExec(`DELETE FROM "roles"`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mockSQL.ExpectCommit()

		err := ctrl.DeleteRole(context.Background(), "dept-role")
		Expect(err).ToNot(HaveOccurred())

		_, uCacheErr := authCtrl.cache.Get(context.Background(), UserPermissionCachePrefix+groupMemberID)
		Expect(uCacheErr).To(HaveOccurred())

		Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
	})
})

var _ = Describe("singleflight double-check cache path", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	It("GetPolicy: singleflight double-check returns from cache without DB call", func() {
		mockDB, mockSQL := setupMockDB(testLogger)
		ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
		authCtrl := ctrl.(*AuthController)

		p := models.Policy{Name: "cached-policy", System: false}
		data, _ := json.Marshal(p)
		_ = authCtrl.cache.Set(context.Background(), policyCacheKey("cached-policy"), data, CacheTTL)

		result, err := ctrl.GetPolicy(context.Background(), "cached-policy")
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Name).To(Equal("cached-policy"))

		Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
	})

	It("GetUserPermissions: second call hits cache (verifies post-DB caching)", func() {
		mockDB, mockSQL := setupMockDB(testLogger)
		ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

		userID := uuid.New().String()

		mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
			WithArgs(userID, 1).
			WillReturnRows(mockSQL.NewRows(userColumns()).
				AddRow(createUserRow(userID, "bob")...))
		mockSQL.ExpectQuery(`.+`).
			WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "role_db_id"}))
		mockSQL.ExpectQuery(`.+`).
			WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}))

		perms1, err := ctrl.GetUserPermissions(context.Background(), userID)
		Expect(err).ToNot(HaveOccurred())
		Expect(perms1).To(BeEmpty())

		perms2, err := ctrl.GetUserPermissions(context.Background(), userID)
		Expect(err).ToNot(HaveOccurred())
		Expect(perms2).To(BeEmpty())

		Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
	})
})

var _ = Describe("UpdatePermission and DeletePermission DB error paths", func() {
	var testLogger ezlog.Logger

	BeforeEach(func() {
		testLogger, _ = testutils.SetupTestLogger()
	})

	Describe("UpdatePermission", func() {
		It("propagates DB error when update query fails", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)

			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WithArgs("auth::user::read", 1).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("auth::user::read", "auth", "user::read", "GET", "/users/", false)...))
			mockSQL.ExpectBegin()
			mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).
				WillReturnError(fmt.Errorf("constraint violation"))
			mockSQL.ExpectRollback()

			err := ctrl.UpdatePermission(context.Background(), &models.Permission{
				Name:   "auth::user::read",
				Method: "POST",
			})
			Expect(err).To(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})

	Describe("DeletePermission", func() {
		It("propagates DB error when delete query fails", func() {
			mockDB, mockSQL := setupMockDB(testLogger)
			ctrl := newControllerWithEmptyRouter(testLogger, mockDB)
			authCtrl := ctrl.(*AuthController)

			perm := models.Permission{Name: "auth::user::read", System: false}
			data, _ := json.Marshal(perm)
			_ = authCtrl.cache.Set(context.Background(), permissionCacheKey("auth::user::read"), data, CacheTTL)

			mockSQL.ExpectBegin()
			mockSQL.ExpectExec(`DELETE FROM "rbac_permissions"`).
				WillReturnError(fmt.Errorf("db error"))
			mockSQL.ExpectRollback()

			err := ctrl.DeletePermission(context.Background(), "auth::user::read")
			Expect(err).To(HaveOccurred())

			_, cacheErr := authCtrl.cache.Get(context.Background(), permissionCacheKey("auth::user::read"))
			Expect(cacheErr).ToNot(HaveOccurred())

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})
	})
})
