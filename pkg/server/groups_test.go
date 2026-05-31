package server

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgconn"

	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
)

func groupColumns() []string {
	return []string{"id", "name", "created_at", "updated_at"}
}

func createGroupRow(name string) []driver.Value {
	return []driver.Value{"550e8400-e29b-41d4-a716-446655440001", name, time.Now(), time.Now()}
}

var _ = Describe("Group API Test Suite", func() {
	testLogger, _ := testutils.SetupTestLogger()
	groupRouter := func(s *Server, r *mux.Router) { s.groupRouter(r.PathPrefix("/groups").Subrouter()) }

	// ===== ListGroups =====

	DescribeTableSubtree("ListGroups API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 200 with empty list", apiTestCase{
			name: "should return 200 with empty list", method: http.MethodGet,
			path: "/groups/",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WillReturnRows(mockSQL.NewRows(groupColumns()))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: `"items":[]`,
		}),
		Entry("should return 200 with groups", apiTestCase{
			name: "should return 200 with groups", method: http.MethodGet,
			path: "/groups/",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(groupColumns()).
						AddRow(createGroupRow("admins")...).
						AddRow(createGroupRow("viewers")...)
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "admins",
		}),
		Entry("should return 400 for invalid pagination", apiTestCase{
			name: "should return 400 for invalid pagination", method: http.MethodGet,
			path: "/groups/?page=invalid",
			setupServer: func() *Server {
				return setupUserServer(testLogger, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid pagination parameters",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodGet,
			path:           "/groups/",
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== GetGroup =====

	DescribeTableSubtree("GetGroup API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 200 when group found", apiTestCase{
			name: "should return 200 when group found", method: http.MethodGet,
			path: "/groups/admins",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(groupColumns()).
						AddRow(createGroupRow("admins")...)
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("admins", 1).WillReturnRows(rows)
					// Preload Roles
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}))
					// Preload Users
					mockSQL.ExpectQuery(`.+`).
						WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "admins",
		}),
		Entry("should return 404 when group not found", apiTestCase{
			name: "should return 404 when group not found", method: http.MethodGet,
			path: "/groups/nonexistent",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("nonexistent", 1).WillReturnRows(mockSQL.NewRows(groupColumns()))
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodGet,
			path:           "/groups/admins",
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== AddGroup =====

	DescribeTableSubtree("AddGroup API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/groups/", body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 for missing name", apiTestCase{
			name: "should return 400 for missing name", method: http.MethodPost,
			path: "/groups/", body: `{"name":""}`,
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "group name is required",
		}),
		Entry("should return 201 when group added", apiTestCase{
			name: "should return 201 when group added", method: http.MethodPost,
			path: "/groups/", body: `{"name":"new-group"}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "groups"`).
						WillReturnRows(mockSQL.NewRows(groupColumns()).
							AddRow(createGroupRow("new-group")...))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusCreated,
		}),
		Entry("should return 409 for duplicate group", apiTestCase{
			name: "should return 409 for duplicate group", method: http.MethodPost,
			path: "/groups/", body: `{"name":"admins"}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "groups"`).
						WillReturnError(&pgconn.PgError{Code: "23505"})
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusConflict,
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPost,
			path: "/groups/", body: `{"name":"new-group"}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== UpdateGroup =====

	DescribeTableSubtree("UpdateGroup API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPut,
			path: "/groups/admins", body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 200 when group updated", apiTestCase{
			name: "should return 200 when group updated", method: http.MethodPut,
			path: "/groups/admins", body: `{"name":"super-admins"}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`UPDATE "groups"`).
						WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when group not found", apiTestCase{
			name: "should return 404 when group not found", method: http.MethodPut,
			path: "/groups/nonexistent", body: `{"name":"renamed"}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`UPDATE "groups"`).
						WillReturnResult(sqlmock.NewResult(0, 0))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPut,
			path: "/groups/admins", body: `{"name":"renamed"}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== DeleteGroup =====

	DescribeTableSubtree("DeleteGroup API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 200 when group deleted", apiTestCase{
			name: "should return 200 when group deleted", method: http.MethodDelete,
			path: "/groups/admins",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`DELETE FROM "groups"`).
						WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when group not found", apiTestCase{
			name: "should return 404 when group not found", method: http.MethodDelete,
			path: "/groups/nonexistent",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`DELETE FROM "groups"`).
						WillReturnResult(sqlmock.NewResult(0, 0))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodDelete,
			path:           "/groups/admins",
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== AssignGroupMember =====

	DescribeTableSubtree("AssignGroupMember API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/groups/admins/members/assign", body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 when users is empty", apiTestCase{
			name: "should return 400 when users is empty", method: http.MethodPost,
			path: "/groups/admins/members/assign", body: `{}`,
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "users is required",
		}),
		Entry("should return 200 when user assigned to group", apiTestCase{
			name: "should return 200 when user assigned to group", method: http.MethodPost,
			path: "/groups/admins/members/assign",
			body: `{"users":["550e8400-e29b-41d4-a716-446655440000"]}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("admins", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()).
							AddRow(createGroupRow("admins")...))
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("550e8400-e29b-41d4-a716-446655440000").
						WillReturnRows(mockSQL.NewRows(userColumns()).
							AddRow(createUserRow("testuser", "test@example.com")...))
					mockSQL.ExpectQuery(`INSERT INTO "users"`).
						WillReturnRows(mockSQL.NewRows(userColumns()).
							AddRow(createUserRow("testuser", "test@example.com")...))
					mockSQL.ExpectQuery(`INSERT INTO "user_groups"`).
						WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}).
							AddRow("550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001"))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when group not found", apiTestCase{
			name: "should return 404 when group not found", method: http.MethodPost,
			path: "/groups/nonexistent/members/assign",
			body: `{"users":["550e8400-e29b-41d4-a716-446655440000"]}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("nonexistent", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "group nonexistent not found",
		}),
		Entry("should return 400 when user not found", apiTestCase{
			name: "should return 400 when user not found", method: http.MethodPost,
			path: "/groups/admins/members/assign",
			body: `{"users":["nonexistent-user-id"]}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("admins", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()).
							AddRow(createGroupRow("admins")...))
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("nonexistent-user-id").
						WillReturnRows(mockSQL.NewRows([]string{"id", "username"}))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "user nonexistent-user-id not found",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPost,
			path: "/groups/admins/members/assign", body: `{"users":["id"]}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== AssignGroupRole =====

	DescribeTableSubtree("AssignGroupRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/groups/admins/roles/assign", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 when roles is empty", apiTestCase{
			name: "should return 400 when roles is empty", method: http.MethodPost,
			path: "/groups/admins/roles/assign", body: `{}`,
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "roles is required",
		}),
		Entry("should return 200 when role assigned to group", apiTestCase{
			name: "should return 200 when role assigned to group", method: http.MethodPost,
			path: "/groups/admins/roles/assign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("admins", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()).
							AddRow(createGroupRow("admins")...))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("admin").
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("admin", false)...))
					mockSQL.ExpectExec(`UPDATE "groups"`).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mockSQL.ExpectQuery(`INSERT INTO "roles"`).
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("admin", false)...))
					mockSQL.ExpectQuery(`INSERT INTO "group_roles"`).
						WillReturnRows(mockSQL.NewRows([]string{"group_db_id", "role_db_id"}).
							AddRow("550e8400-e29b-41d4-a716-446655440001", "550e8400-e29b-41d4-a716-446655440000"))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when group not found", apiTestCase{
			name: "should return 404 when group not found", method: http.MethodPost,
			path: "/groups/nonexistent/roles/assign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("nonexistent", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "group nonexistent not found",
		}),
		Entry("should return 400 when role not found", apiTestCase{
			name: "should return 400 when role not found", method: http.MethodPost,
			path: "/groups/admins/roles/assign",
			body: `{"roles":["nonexistent"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("admins", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()).
							AddRow(createGroupRow("admins")...))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("nonexistent").
						WillReturnRows(mockSQL.NewRows(roleColumns()))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "role nonexistent not found",
		}),
		Entry("should return 404 when rbacController is nil", apiTestCase{
			name: "should return 404 when rbacController is nil", method: http.MethodPost,
			path: "/groups/admins/roles/assign", body: `{"roles":["admin"]}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== UnassignGroupRole =====

	DescribeTableSubtree("UnassignGroupRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodDelete,
			path: "/groups/admins/roles/unassign", body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 when roles is empty", apiTestCase{
			name: "should return 400 when roles is empty", method: http.MethodDelete,
			path: "/groups/admins/roles/unassign", body: `{}`,
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "roles is required",
		}),
		Entry("should return 200 when role unassigned from group", apiTestCase{
			name: "should return 200 when role unassigned from group", method: http.MethodDelete,
			path: "/groups/admins/roles/unassign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("admins", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()).
							AddRow(createGroupRow("admins")...))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("admin").
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("admin", false)...))
					mockSQL.ExpectExec(`DELETE FROM "group_roles"`).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when group not found for unassign", apiTestCase{
			name: "should return 404 when group not found for unassign", method: http.MethodDelete,
			path: "/groups/nonexistent/roles/unassign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("nonexistent", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "group nonexistent not found",
		}),
		Entry("should return 404 when rbacController is nil", apiTestCase{
			name: "should return 404 when rbacController is nil", method: http.MethodDelete,
			path: "/groups/admins/roles/unassign", body: `{"roles":["admin"]}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	// ===== UnassignGroupMember =====

	DescribeTableSubtree("UnassignGroupMember API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, groupRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodDelete,
			path: "/groups/admins/members/unassign", body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 when users is empty", apiTestCase{
			name: "should return 400 when users is empty", method: http.MethodDelete,
			path: "/groups/admins/members/unassign", body: `{}`,
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "users is required",
		}),
		Entry("should return 200 when user removed from group", apiTestCase{
			name: "should return 200 when user removed from group", method: http.MethodDelete,
			path: "/groups/admins/members/unassign",
			body: `{"users":["550e8400-e29b-41d4-a716-446655440000"]}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("admins", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()).
							AddRow(createGroupRow("admins")...))
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("550e8400-e29b-41d4-a716-446655440000").
						WillReturnRows(mockSQL.NewRows(userColumns()).
							AddRow(createUserRow("testuser", "test@example.com")...))
					mockSQL.ExpectExec(`DELETE FROM "user_groups"`).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when group not found for unassign", apiTestCase{
			name: "should return 404 when group not found for unassign", method: http.MethodDelete,
			path: "/groups/nonexistent/members/unassign",
			body: `{"users":["550e8400-e29b-41d4-a716-446655440000"]}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "groups"`).
						WithArgs("nonexistent", 1).
						WillReturnRows(mockSQL.NewRows(groupColumns()))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "group nonexistent not found",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodDelete,
			path: "/groups/admins/members/unassign", body: `{"users":["id"]}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger} },
			expectedStatus: http.StatusNotFound,
		}),
	)
})

// ---------------------------------------------------------------------------
// ListGroups DB error branch
// ---------------------------------------------------------------------------

var _ = Describe("ListGroups DB error branch", func() {
	It("returns 500 when DB.ListGroups returns error", func() {
		logger, _ := testutils.SetupTestLogger()
		tc := apiTestCase{
			name: "db error", method: http.MethodGet,
			path: "/",
			setupServer: func() *Server {
				return &Server{
					Logger: logger,
					DB:     &mockDBPAT{listGroupsErr: errors.New("db down")},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, func(s *Server, r *mux.Router) {
			s.groupRouter(r)
		}, logger)
	})
})
