package server

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgconn"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	"github.com/flipcloud-ai/ezauth/pkg/server/rbac"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// permissionColumns returns the columns for rbac_permissions mock rows.
func permissionColumns() []string {
	return []string{
		"name", "effect", "service", "method", "path", "action", "system",
		"created_at", "updated_at",
	}
}

// createPermissionRow creates a mock row for a permission.
func createPermissionRow(name, action, method, path string, system bool) []driver.Value {
	return []driver.Value{
		name, true, "auth", method, path, action, system,
		time.Now(), time.Now(),
	}
}

// policyColumns returns the columns for rbac_policies mock rows.
func policyColumns() []string {
	return []string{
		"name", "system", "created_at", "updated_at",
	}
}

// createPolicyRow creates a mock row for a policy.
func createPolicyRow(name string, system bool) []driver.Value {
	return []driver.Value{
		name, system, time.Now(), time.Now(),
	}
}

// roleColumns returns the columns for roles mock rows.
func roleColumns() []string {
	return []string{
		"id", "name", "system", "created_at", "updated_at",
	}
}

// createRoleRow creates a mock row for a role.
func createRoleRow(name string, system bool) []driver.Value {
	return []driver.Value{
		"550e8400-e29b-41d4-a716-446655440000", name, system,
		time.Now(), time.Now(),
	}
}

// setupRBACServer creates a Server with a mock database and an initialized rbacController.
func setupRBACServer(logger ezlog.Logger, mockSetup func(sqlmock.Sqlmock)) *Server {
	return setupRBACServerWithConfig(logger, ezcfg.ServerConfig{TrustForwardedHeaders: testutils.BoolPtr(true)}, mockSetup)
}

// setupRBACServerWithConfig creates a Server with the given ServerConfig, a mock database, and an initialized rbacController.
func setupRBACServerWithConfig(logger ezlog.Logger, serveCfg ezcfg.ServerConfig, mockSetup func(sqlmock.Sqlmock)) *Server {
	gormDB, mockSQL, err := testutils.MockSQLPool()
	Expect(err).ToNot(HaveOccurred())
	Expect(gormDB).ToNot(BeNil())

	mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
	mockDB.DB = gormDB

	ctx := ezlog.ServerContext(context.Background(), logger)
	ctrl, err := rbac.NewController(ctx, nil, mockDB, ezcache.NewMemoryCache[string, []byte](10000, 5*time.Minute), "/ezauth", "")
	Expect(err).ToNot(HaveOccurred())

	if mockSetup != nil {
		mockSetup(mockSQL)
	}

	s := &Server{Logger: logger, DB: mockDB, rbacController: ctrl, ServeCfg: serveCfg}
	return s
}

var _ = Describe("RBAC API Test Suite", func() {
	testLogger, _ := testutils.SetupTestLogger()
	rbacRouter := func(s *Server, r *mux.Router) { s.rbacRouter(r.PathPrefix("/auth").Subrouter()) }

	// ===== Permission API Tests =====

	DescribeTableSubtree("GetPermission API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 200 when permission found", apiTestCase{
			name: "should return 200 when permission found", method: http.MethodGet,
			path: "/auth/permission/auth::user::read",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "user::read", "GET", "/users/", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("auth::user::read", 1).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "auth::user::read",
		}),
		Entry("should return 404 when permission not found", apiTestCase{
			name: "should return 404 when permission not found", method: http.MethodGet,
			path: "/auth/permission/nonexistent",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(permissionColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
	)

	DescribeTableSubtree("ListPermissions API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 200 with permissions list", apiTestCase{
			name: "should return 200 with permissions list", method: http.MethodGet,
			path: "/auth/permission/",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "user::read", "GET", "/users/", false)...).
						AddRow(createPermissionRow("auth::user::write", "user::write", "POST", "/users/", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "auth::user::read",
		}),
		Entry("should return 200 with empty list", apiTestCase{
			name: "should return 200 with empty list", method: http.MethodGet,
			path: "/auth/permission/",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WillReturnRows(mockSQL.NewRows(permissionColumns()))
				})
			},
			expectedStatus: http.StatusOK,
		}),
	)

	DescribeTableSubtree("AddPermission API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/auth/permission/", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 201 when permission added successfully", apiTestCase{
			name: "should return 201 when permission added successfully", method: http.MethodPost,
			path: "/auth/permission/",
			body: `{"name":"auth::item::read","service":"auth","action":"item::read","method":"GET","path":"/items/","effect":true}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
						WillReturnRows(mockSQL.NewRows(permissionColumns()).
							AddRow(createPermissionRow("auth::item::read", "item::read", "GET", "/items/", false)...))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusCreated,
		}),
		Entry("should return 409 for duplicate permission", apiTestCase{
			name: "should return 409 for duplicate permission", method: http.MethodPost,
			path: "/auth/permission/",
			body: `{"name":"auth::user::read","service":"auth","action":"user::read","method":"GET","path":"/users/","effect":true}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "rbac_permissions"`).
						WillReturnError(&pgconn.PgError{Code: "23505"})
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusConflict,
		}),
		Entry("should return 400 when path uses auth prefix — admin subpath", apiTestCase{
			name: "should return 400 when path uses auth prefix — admin subpath", method: http.MethodPost,
			path: "/auth/permission/",
			body: `{"name":"custom::perm::read","service":"custom","action":"perm::read","method":"GET","path":"/ezauth/secret","effect":true}`,
			setupServer: func() *Server {
				return setupRBACServerWithConfig(testLogger, ezcfg.ServerConfig{
					AuthPrefix: "/ezauth", StaticPrefix: "/static",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				}, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "reserved system prefix",
		}),
		Entry("should return 400 when path uses auth prefix", apiTestCase{
			name: "should return 400 when path uses auth prefix", method: http.MethodPost,
			path: "/auth/permission/",
			body: `{"name":"custom::perm::read","service":"custom","action":"perm::read","method":"GET","path":"/ezauth/callback","effect":true}`,
			setupServer: func() *Server {
				return setupRBACServerWithConfig(testLogger, ezcfg.ServerConfig{
					AuthPrefix: "/ezauth", StaticPrefix: "/static",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				}, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "reserved system prefix",
		}),
		Entry("should return 400 when path uses static prefix", apiTestCase{
			name: "should return 400 when path uses static prefix", method: http.MethodPost,
			path: "/auth/permission/",
			body: `{"name":"custom::perm::read","service":"custom","action":"perm::read","method":"GET","path":"/static/assets","effect":true}`,
			setupServer: func() *Server {
				return setupRBACServerWithConfig(testLogger, ezcfg.ServerConfig{
					AuthPrefix: "/ezauth", StaticPrefix: "/static",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				}, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "reserved system prefix",
		}),
	)

	DescribeTableSubtree("UpdatePermission API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPut,
			path: "/auth/permission/", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 200 when permission updated successfully", apiTestCase{
			name: "should return 200 when permission updated successfully", method: http.MethodPut,
			path: "/auth/permission/",
			body: `{"name":"auth::user::read","method":"POST","path":"/users/update"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					// GetPermission is called first to check System flag
					rows := mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "user::read", "GET", "/users/", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("auth::user::read", 1).WillReturnRows(rows)
					// Then the actual update (GORM wraps in transaction)
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`UPDATE "rbac_permissions"`).
						WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when permission not found for update", apiTestCase{
			name: "should return 404 when permission not found for update", method: http.MethodPut,
			path: "/auth/permission/",
			body: `{"name":"nonexistent","method":"GET","path":"/test"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(permissionColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 400 when update path uses auth prefix — admin subpath", apiTestCase{
			name: "should return 400 when update path uses auth prefix — admin subpath", method: http.MethodPut,
			path: "/auth/permission/",
			body: `{"name":"auth::user::read","method":"GET","path":"/ezauth/users"}`,
			setupServer: func() *Server {
				return setupRBACServerWithConfig(testLogger, ezcfg.ServerConfig{
					AuthPrefix: "/ezauth", StaticPrefix: "/static",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				}, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "reserved system prefix",
		}),
		Entry("should return 400 when update path uses auth prefix", apiTestCase{
			name: "should return 400 when update path uses auth prefix", method: http.MethodPut,
			path: "/auth/permission/",
			body: `{"name":"auth::user::read","method":"GET","path":"/ezauth/login"}`,
			setupServer: func() *Server {
				return setupRBACServerWithConfig(testLogger, ezcfg.ServerConfig{
					AuthPrefix: "/ezauth", StaticPrefix: "/static",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				}, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "reserved system prefix",
		}),
		Entry("should return 400 when update path uses static prefix", apiTestCase{
			name: "should return 400 when update path uses static prefix", method: http.MethodPut,
			path: "/auth/permission/",
			body: `{"name":"auth::user::read","method":"GET","path":"/static/js/app.js"}`,
			setupServer: func() *Server {
				return setupRBACServerWithConfig(testLogger, ezcfg.ServerConfig{
					AuthPrefix: "/ezauth", StaticPrefix: "/static",
					TrustForwardedHeaders: testutils.BoolPtr(true),
				}, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "reserved system prefix",
		}),
		Entry("should return 403 when updating system permission", apiTestCase{
			name: "should return 403 when updating system permission", method: http.MethodPut,
			path: "/auth/permission/",
			body: `{"name":"auth::system::read","method":"POST","path":"/system/"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::system::read", "system::read", "GET", "/system/", true)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("auth::system::read", 1).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusForbidden, expectedBody: "system resource",
		}),
	)

	DescribeTableSubtree("DeletePermission API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 200 when permission deleted successfully", apiTestCase{
			name: "should return 200 when permission deleted successfully", method: http.MethodDelete,
			path: "/auth/permission/auth::user::read",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					// GetPermission check
					rows := mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "user::read", "GET", "/users/", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("auth::user::read", 1).WillReturnRows(rows)
					// Delete
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`DELETE FROM "rbac_permissions"`).
						WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when permission not found for delete", apiTestCase{
			name: "should return 404 when permission not found for delete", method: http.MethodDelete,
			path: "/auth/permission/nonexistent",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(permissionColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 403 when deleting system permission", apiTestCase{
			name: "should return 403 when deleting system permission", method: http.MethodDelete,
			path: "/auth/permission/auth::system::read",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::system::read", "system::read", "GET", "/system/", true)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("auth::system::read", 1).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusForbidden, expectedBody: "system resource",
		}),
	)

	// ===== Policy API Tests =====

	DescribeTableSubtree("GetPolicy API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 200 when policy found", apiTestCase{
			name: "should return 200 when policy found", method: http.MethodGet,
			path: "/auth/policy/admin-policy",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("admin-policy", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WithArgs("admin-policy", 1).WillReturnRows(rows)
					// Preload Permission (many-to-many through policy_permissions)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
					// Preload Roles (many-to-many through policy_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "admin-policy",
		}),
		Entry("should return 404 when policy not found", apiTestCase{
			name: "should return 404 when policy not found", method: http.MethodGet,
			path: "/auth/policy/nonexistent",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(policyColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
	)

	DescribeTableSubtree("ListPolicies API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 200 with policies list", apiTestCase{
			name: "should return 200 with policies list", method: http.MethodGet,
			path: "/auth/policy/",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("policy-a", false)...).
						AddRow(createPolicyRow("policy-b", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).WillReturnRows(rows)
					// Preload Permission (many-to-many through policy_permissions)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "policy-a",
		}),
		Entry("should return 200 with empty list", apiTestCase{
			name: "should return 200 with empty list", method: http.MethodGet,
			path: "/auth/policy/",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WillReturnRows(mockSQL.NewRows(policyColumns()))
				})
			},
			expectedStatus: http.StatusOK,
		}),
	)

	DescribeTableSubtree("AddPolicy API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/auth/policy/", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 201 when policy added successfully", apiTestCase{
			name: "should return 201 when policy added successfully", method: http.MethodPost,
			path: "/auth/policy/",
			body: `{"name":"new-policy","permission":["auth::user::read"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					// Validate referenced permissions exist
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WithArgs("auth::user::read", 1).
						WillReturnRows(mockSQL.NewRows(permissionColumns()).
							AddRow(createPermissionRow("auth::user::read", "user::read", "GET", "/users/", false)...))
					// Create policy
					mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
						WillReturnRows(mockSQL.NewRows(policyColumns()).
							AddRow(createPolicyRow("new-policy", false)...))
					// GORM inserts into the join table for the association
					mockSQL.ExpectQuery(`INSERT INTO "policy_permissions"`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}).
							AddRow("new-policy", "auth::user::read"))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusCreated,
		}),
		Entry("should return 409 for duplicate policy", apiTestCase{
			name: "should return 409 for duplicate policy", method: http.MethodPost,
			path: "/auth/policy/",
			body: `{"name":"admin-policy"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
						WillReturnError(&pgconn.PgError{Code: "23505"})
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusConflict,
		}),
	)

	DescribeTableSubtree("UpdatePolicy API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPut,
			path: "/auth/policy/test-policy", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 404 when policy not found for update", apiTestCase{
			name: "should return 404 when policy not found for update", method: http.MethodPut,
			path: "/auth/policy/nonexistent",
			body: `{"name":"nonexistent"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(policyColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 403 when updating system policy", apiTestCase{
			name: "should return 403 when updating system policy", method: http.MethodPut,
			path: "/auth/policy/system-policy",
			body: `{"name":"system-policy"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("system-policy", true)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WithArgs("system-policy", 1).WillReturnRows(rows)
					// Preload Permission (many-to-many through policy_permissions)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
					// Preload Roles (many-to-many through policy_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
				})
			},
			expectedStatus: http.StatusForbidden, expectedBody: "system resource",
		}),
	)

	DescribeTableSubtree("DeletePolicy API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 404 when policy not found for delete", apiTestCase{
			name: "should return 404 when policy not found for delete", method: http.MethodDelete,
			path: "/auth/policy/nonexistent",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(policyColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 403 when deleting system policy", apiTestCase{
			name: "should return 403 when deleting system policy", method: http.MethodDelete,
			path: "/auth/policy/system-policy",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(policyColumns()).
						AddRow(createPolicyRow("system-policy", true)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WithArgs("system-policy", 1).WillReturnRows(rows)
					// Preload Permission (many-to-many through policy_permissions)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
					// Preload Roles (many-to-many through policy_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
				})
			},
			expectedStatus: http.StatusForbidden, expectedBody: "system resource",
		}),
	)

	// ===== Role API Tests =====

	DescribeTableSubtree("GetRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 200 when role found", apiTestCase{
			name: "should return 200 when role found", method: http.MethodGet,
			path: "/auth/role/admin",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("admin", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("admin", 1).WillReturnRows(rows)
					// Preload Policies (many-to-many through policy_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
					// Preload Groups (many-to-many through group_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "admin",
		}),
		Entry("should return 404 when role not found", apiTestCase{
			name: "should return 404 when role not found", method: http.MethodGet,
			path: "/auth/role/nonexistent",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(roleColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
	)

	DescribeTableSubtree("ListRoles API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 200 with roles list", apiTestCase{
			name: "should return 200 with roles list", method: http.MethodGet,
			path: "/auth/role/",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("admin", false)...).
						AddRow(createRoleRow("viewer", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "admin",
		}),
		Entry("should return 200 with empty list", apiTestCase{
			name: "should return 200 with empty list", method: http.MethodGet,
			path: "/auth/role/",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WillReturnRows(mockSQL.NewRows(roleColumns()))
				})
			},
			expectedStatus: http.StatusOK,
		}),
	)

	DescribeTableSubtree("AddRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/auth/role/", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 201 when role added successfully", apiTestCase{
			name: "should return 201 when role added successfully", method: http.MethodPost,
			path: "/auth/role/",
			body: `{"name":"new-role","policy":["admin-policy"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					// Validate referenced policies exist
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WithArgs("admin-policy", 1).
						WillReturnRows(mockSQL.NewRows(policyColumns()).
							AddRow(createPolicyRow("admin-policy", false)...))
					// Create role
					mockSQL.ExpectQuery(`INSERT INTO "roles"`).
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("new-role", false)...))
					// GORM upserts the associated policy (Omit("Policy.*") doesn't match field "Policies")
					mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
						WillReturnRows(mockSQL.NewRows(policyColumns()).
							AddRow(createPolicyRow("admin-policy", false)...))
					// GORM inserts into the join table for the association
					mockSQL.ExpectQuery(`INSERT INTO "policy_roles"`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}).
							AddRow("admin-policy", "550e8400-e29b-41d4-a716-446655440000"))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusCreated,
		}),
		Entry("should return 409 for duplicate role", apiTestCase{
			name: "should return 409 for duplicate role", method: http.MethodPost,
			path: "/auth/role/",
			body: `{"name":"admin"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "roles"`).
						WillReturnError(&pgconn.PgError{Code: "23505"})
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusConflict,
		}),
	)

	DescribeTableSubtree("UpdateRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPut,
			path: "/auth/role/admin", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 404 when role not found for update", apiTestCase{
			name: "should return 404 when role not found for update", method: http.MethodPut,
			path: "/auth/role/nonexistent",
			body: `{"name":"nonexistent"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(roleColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 403 when updating system role", apiTestCase{
			name: "should return 403 when updating system role", method: http.MethodPut,
			path: "/auth/role/system-admin",
			body: fmt.Sprintf(`{"name":"%s"}`, "system-admin"),
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("system-admin", true)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("system-admin", 1).WillReturnRows(rows)
					// Preload Policies (many-to-many through policy_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
					// Preload Groups (many-to-many through group_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
				})
			},
			expectedStatus: http.StatusForbidden, expectedBody: "system resource",
		}),
		Entry("should return 200 when role renamed successfully", apiTestCase{
			name: "should return 200 when role renamed successfully", method: http.MethodPut,
			path: "/auth/role/old-role",
			body: `{"name":"new-role"}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					// GetRole system check: main SELECT + 2 preloads
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("old-role", 1).
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("old-role", false)...))
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
					// db.UpdateRole transaction
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`UPDATE "roles"`).
						WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("new-role", 1).
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("new-role", false)...))
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WillReturnRows(mockSQL.NewRows(policyColumns()))
					mockSQL.ExpectExec(`.+`).WillReturnResult(sqlmock.NewResult(0, 0))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 200 when role policies updated successfully", apiTestCase{
			name: "should return 200 when role policies updated successfully", method: http.MethodPut,
			path: "/auth/role/editor",
			body: `{"name":"editor","policy":["read-policy"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					// GetRole system check: main SELECT + 2 preloads
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("editor", 1).
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("editor", false)...))
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
					// db.UpdateRole transaction
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`UPDATE "roles"`).
						WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("editor", 1).
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("editor", false)...))
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows(policyColumns()).
							AddRow(createPolicyRow("read-policy", false)...))
					// GORM upserts the policy record before updating the join table
					mockSQL.ExpectQuery(`INSERT INTO "rbac_policies"`).
						WillReturnRows(mockSQL.NewRows(policyColumns()).
							AddRow(createPolicyRow("read-policy", false)...))
					// GORM inserts into policy_roles join table
					mockSQL.ExpectQuery(`INSERT INTO "policy_roles"`).
						WillReturnRows(mockSQL.NewRows([]string{"role_db_id", "policy_name"}).
							AddRow("550e8400-e29b-41d4-a716-446655440000", "read-policy"))
					// Delete stale policy_roles entries
					mockSQL.ExpectExec(`.+`).WillReturnResult(sqlmock.NewResult(0, 0))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
	)

	DescribeTableSubtree("DeleteRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, rbacRouter, nil) })
		},
		Entry("should return 404 when role not found for delete", apiTestCase{
			name: "should return 404 when role not found for delete", method: http.MethodDelete,
			path: "/auth/role/nonexistent",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(roleColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 403 when deleting system role", apiTestCase{
			name: "should return 403 when deleting system role", method: http.MethodDelete,
			path: "/auth/role/system-admin",
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("system-admin", true)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("system-admin", 1).WillReturnRows(rows)
					// Preload Policies (many-to-many through policy_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
					// Preload Groups (many-to-many through group_roles)
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
				})
			},
			expectedStatus: http.StatusForbidden, expectedBody: "system resource",
		}),
	)

	// ===== isReservedPath Unit Tests =====

	DescribeTable("isReservedPath",
		func(authPrefix, staticPrefix, path string, expected bool) {
			s := &Server{ServeCfg: ezcfg.ServerConfig{
				AuthPrefix:            authPrefix,
				StaticPrefix:          staticPrefix,
				TrustForwardedHeaders: testutils.BoolPtr(true),
			}}
			Expect(s.isReservedPath(path)).To(Equal(expected))
		},
		Entry("matches auth prefix — admin subpath", "/ezauth", "/static", "/ezauth/users", true),
		Entry("matches auth prefix — oauth path", "/ezauth", "/static", "/ezauth/callback", true),
		Entry("matches static prefix", "/ezauth", "/static", "/static/js/app.js", true),
		Entry("exact auth prefix match", "/ezauth", "/static", "/ezauth", true),
		Entry("non-reserved path", "/ezauth", "/static", "/api/v1/items", false),
		Entry("empty path", "/ezauth", "/static", "", false),
		Entry("all prefixes empty", "", "", "/ezauth/test", false),
		Entry("partial match is not reserved", "/ezauth", "/static", "/ezauthest", false),
	)

})

// ---------------------------------------------------------------------------
// ListPermissions – covers pagination error and DB error branches
// ---------------------------------------------------------------------------

var _ = Describe("ListPermissions pagination and DB error branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	rbacRouter := func(s *Server, r *mux.Router) {
		s.rbacRouter(r.PathPrefix("/auth").Subrouter())
	}

	It("returns 400 when limit query param is invalid", func() {
		tc := apiTestCase{
			name: "invalid limit", method: http.MethodGet,
			path: "/auth/permission/?limit=bad",
			setupServer: func() *Server {
				return setupRBACServer(logger, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid pagination parameters",
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 400 when offset query param is negative", func() {
		tc := apiTestCase{
			name: "negative offset", method: http.MethodGet,
			path: "/auth/permission/?offset=-1",
			setupServer: func() *Server {
				return setupRBACServer(logger, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid pagination parameters",
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 500 when rbacController.ListPermissions returns an error", func() {
		tc := apiTestCase{
			name: "db error", method: http.MethodGet,
			path: "/auth/permission/?service=mysvc",
			setupServer: func() *Server {
				return setupRBACServer(logger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
						WillReturnError(errors.New("db down"))
				})
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 200 with service filter applied", func() {
		tc := apiTestCase{
			name: "with service filter", method: http.MethodGet,
			path: "/auth/permission/?service=auth&limit=10&offset=0",
			setupServer: func() *Server {
				return setupRBACServer(logger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(permissionColumns()).
						AddRow(createPermissionRow("auth::user::read", "user::read", "GET", "/users/", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "auth::user::read",
		}
		runAPITest(tc, rbacRouter, logger)
	})
})

// ---------------------------------------------------------------------------
// ListPolicies – covers pagination error and DB error branches
// ---------------------------------------------------------------------------

var _ = Describe("ListPolicies pagination and DB error branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	rbacRouter := func(s *Server, r *mux.Router) {
		s.rbacRouter(r.PathPrefix("/auth").Subrouter())
	}

	It("returns 400 when limit query param is invalid", func() {
		tc := apiTestCase{
			name: "invalid limit", method: http.MethodGet,
			path: "/auth/policy/?limit=abc",
			setupServer: func() *Server {
				return setupRBACServer(logger, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid pagination parameters",
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 400 when page param is negative", func() {
		tc := apiTestCase{
			name: "negative page", method: http.MethodGet,
			path: "/auth/policy/?page=-3",
			setupServer: func() *Server {
				return setupRBACServer(logger, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid pagination parameters",
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 500 when rbacController.ListPolicies returns an error", func() {
		tc := apiTestCase{
			name: "db error", method: http.MethodGet,
			path: "/auth/policy/",
			setupServer: func() *Server {
				return setupRBACServer(logger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
						WillReturnError(errors.New("db down"))
				})
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, rbacRouter, logger)
	})
})

// ---------------------------------------------------------------------------
// ListRoles – covers pagination error and DB error branches
// ---------------------------------------------------------------------------

var _ = Describe("ListRoles pagination and DB error branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	rbacRouter := func(s *Server, r *mux.Router) {
		s.rbacRouter(r.PathPrefix("/auth").Subrouter())
	}

	It("returns 400 when limit query param is non-integer", func() {
		tc := apiTestCase{
			name: "non-integer limit", method: http.MethodGet,
			path: "/auth/role/?limit=xyz",
			setupServer: func() *Server {
				return setupRBACServer(logger, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid pagination parameters",
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 400 when offset param is negative", func() {
		tc := apiTestCase{
			name: "negative offset", method: http.MethodGet,
			path: "/auth/role/?offset=-10",
			setupServer: func() *Server {
				return setupRBACServer(logger, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid pagination parameters",
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 500 when rbacController.ListRoles returns an error", func() {
		tc := apiTestCase{
			name: "db error", method: http.MethodGet,
			path: "/auth/role/",
			setupServer: func() *Server {
				return setupRBACServer(logger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WillReturnError(errors.New("db down"))
				})
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, rbacRouter, logger)
	})

	It("returns 200 with pagination params applied", func() {
		tc := apiTestCase{
			name: "with pagination", method: http.MethodGet,
			path: "/auth/role/?limit=5&page=2",
			setupServer: func() *Server {
				return setupRBACServer(logger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(roleColumns()).
						AddRow(createRoleRow("editor", false)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "editor",
		}
		runAPITest(tc, rbacRouter, logger)
	})
})

// ---------------------------------------------------------------------------
// UpdatePolicy name-resolution branches
// ---------------------------------------------------------------------------

var _ = Describe("UpdatePolicy name resolution branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	It("returns 400 when both URL name and body name are empty", func() {
		s := setupRBACServer(logger, nil)
		req := httptest.NewRequest(http.MethodPut, "/auth/policy/",
			strings.NewReader(`{"name":"","permission":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		// Call handler directly — no mux.Vars, so vars["name"] == "".
		s.UpdatePolicy(rw, req)
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
		Expect(rw.Body.String()).To(ContainSubstring("policy name is required"))
	})

	It("uses body name when URL param is empty", func() {
		s := setupRBACServer(logger, func(mockSQL sqlmock.Sqlmock) {
			// GetPolicy: SELECT + preload permissions + preload roles
			rows := mockSQL.NewRows(policyColumns()).
				AddRow(createPolicyRow("my-policy", false)...)
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WithArgs("my-policy", 1).WillReturnRows(rows)
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "role_db_id"}))
			// db.UpdatePolicy: transaction with UPDATE, SELECT refetch, find perms, DELETE, COMMIT
			mockSQL.ExpectBegin()
			mockSQL.ExpectExec(`UPDATE "rbac_policies"`).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_policies"`).
				WillReturnRows(mockSQL.NewRows(policyColumns()).
					AddRow(createPolicyRow("my-policy", false)...))
			mockSQL.ExpectQuery(`.+`).
				WillReturnRows(mockSQL.NewRows([]string{"policy_name", "permission_name"}))
			mockSQL.ExpectExec(`DELETE FROM "policy_permissions"`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mockSQL.ExpectCommit()
			// invalidateUserPermissionsByPolicy → GetUserIDsByPolicy
			mockSQL.ExpectQuery(`SELECT DISTINCT`).
				WillReturnRows(mockSQL.NewRows([]string{"user_db_id"}))
		})
		req := httptest.NewRequest(http.MethodPut, "/auth/policy/",
			strings.NewReader(`{"name":"my-policy","permission":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		// No mux.Vars → URL name is ""; body name "my-policy" should be used.
		s.UpdatePolicy(rw, req)
		Expect(rw.Code).To(Equal(http.StatusOK))
	})
})

// ---------------------------------------------------------------------------
// UpdateRole name-resolution branches
// ---------------------------------------------------------------------------

var _ = Describe("UpdateRole name resolution branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	It("returns 400 when both URL name and body name are empty", func() {
		s := setupRBACServer(logger, nil)
		req := httptest.NewRequest(http.MethodPut, "/auth/role/",
			strings.NewReader(`{"name":""}`))
		req.Header.Set("Content-Type", "application/json")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		// Call handler directly — no mux.Vars, so vars["name"] == "".
		s.UpdateRole(rw, req)
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
		Expect(rw.Body.String()).To(ContainSubstring("role name is required"))
	})
})
