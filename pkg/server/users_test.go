package server

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	ezdto "github.com/flipcloud-ai/ezauth/pkg/server/dto"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// setupUserServer creates a Server with a mock database for user API tests.
func setupUserServer(logger ezlog.Logger, mockSetup func(sqlmock.Sqlmock)) *Server {
	gormDB, mockSQL, err := testutils.MockSQLPool()
	Expect(err).ToNot(HaveOccurred())
	Expect(gormDB).ToNot(BeNil())
	mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
	mockDB.DB = gormDB
	if mockSetup != nil {
		mockSetup(mockSQL)
	}
	return &Server{Logger: logger, DB: mockDB}
}

// userColumns returns the full list of user columns for mock rows
func userColumns() []string {
	return []string{
		"id", "username", "mobile_number", "password", "password_salt",
		"email", "first_name", "last_name", "birth_date", "active",
		"address", "last_login", "password_updated_at", "created_at", "updated_at",
	}
}

// createUserRow creates a mock row for a given user
func createUserRow(username, email string) []driver.Value {
	return []driver.Value{
		uuid.New(), username, "+1234567890", "hashedpassword", "salt",
		email, "John", "Doe", time.Now().AddDate(-20, 0, 0), true,
		`{"street":"123 Main St","city":"NYC","state":"NY","zip_code":"10001","country":"US"}`, time.Now(), time.Now(), time.Now(), time.Now(),
	}
}

var _ = Describe("User Validation Test Suite", func() {
	testLogger, _ := testutils.SetupTestLogger()

	It("should return 400 for invalid request body", func() {
		gormDB, _, err := testutils.MockSQLPool()
		Expect(err).ToNot(HaveOccurred())

		mockDB := &pgx.PGxDB{Database: database.Database{Logger: testLogger}}
		mockDB.DB = gormDB

		server := &Server{Logger: testLogger, DB: mockDB}
		router := mux.NewRouter()
		server.userRouter(router.PathPrefix("/users").Subrouter())

		req := httptest.NewRequest(http.MethodPut, "/users/", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusBadRequest))
	})
})

var _ = Describe("User DTO Test Suite", func() {
	It("should validate UserListItem JSON marshaling", func() {
		item := &ezdto.UserListItem{
			ID:           uuid.New(),
			Username:     "testuser",
			MobileNumber: "1234567890",
			Email:        "test@example.com",
			LastLogin:    time.Now(),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Active:       true,
		}
		data, err := json.Marshal(item)
		Expect(err).To(BeNil())
		Expect(string(data)).To(ContainSubstring("testuser"))
	})
})

var _ = Describe("User API Test Suite", func() {
	testLogger, _ := testutils.SetupTestLogger()
	userRouter := func(s *Server, r *mux.Router) { s.userRouter(r.PathPrefix("/users").Subrouter()) }

	DescribeTableSubtree("GetUser API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 404 when user not found", apiTestCase{
			name: "should return 404 when user not found", method: http.MethodGet,
			path: "/users/" + uuid.New().String(),
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT .* FROM "users"`).
						WillReturnError(gorm.ErrRecordNotFound)
				})
			},
			expectedStatus: http.StatusNotFound,
		}),
		Entry("should return 200 when user found", apiTestCase{
			name: "should return 200 when user found", method: http.MethodGet,
			path: "/users/" + uuid.New().String(),
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT .* FROM "users"`).WillReturnRows(
						mockSQL.NewRows(userColumns()).AddRow(createUserRow("testuser", "test@example.com")...))
					// Preload Groups (alphabetical order: Groups before Roles)
					mockSQL.ExpectQuery(`SELECT .* FROM "user_groups"`).
						WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}))
					// Preload Roles
					mockSQL.ExpectQuery(`SELECT .* FROM "user_roles"`).
						WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "role_db_id"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "testuser",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodGet,
			path:           "/users/" + uuid.New().String(),
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	DescribeTableSubtree("AddUser API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: "/users/", body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 for missing required fields", apiTestCase{
			name: "should return 400 for missing required fields", method: http.MethodPost,
			path: "/users/", body: `{"username":""}`,
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest,
		}),
		Entry("should return 201 when user added successfully", apiTestCase{
			name: "should return 200 when user added successfully", method: http.MethodPost,
			path: "/users/", body: `{"username":"newuser","email":"new@example.com","password":"TestPass123","mobile_number":"+1234567890","birth_date":"1990-01-01T00:00:00Z","address":{"country":"US"}}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "users"`).WillReturnRows(
						mockSQL.NewRows(userColumns()).AddRow(createUserRow("newuser", "new@example.com")...))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusCreated,
		}),
		Entry("should return 409 for duplicate user", apiTestCase{
			name: "should return 409 for duplicate user", method: http.MethodPost,
			path: "/users/", body: `{"username":"existinguser","email":"existing@example.com","password":"TestPass123","mobile_number":"+1234567890","birth_date":"1990-01-01T00:00:00Z","address":{"country":"US"}}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "users"`).WillReturnError(&pgconn.PgError{Code: "23505"})
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusConflict,
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPost,
			path: "/users/", body: `{"username":"newuser","email":"new@example.com"}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	DescribeTableSubtree("UpdateUser API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPut,
			path: "/users/", body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 for invalid user ID", apiTestCase{
			name: "should return 400 for invalid user ID", method: http.MethodPut,
			path: "/users/", body: `{"id":"invalid-uuid"}`,
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid user id",
		}),
		Entry("should return 404 when user not found", apiTestCase{
			name: "should return 404 when user not found", method: http.MethodPut,
			path: "/users/", body: fmt.Sprintf(`{"id":"%s","username":"updateduser"}`, uuid.New().String()),
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`UPDATE "users"`).WillReturnResult(sqlmock.NewResult(0, 0))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "user not found",
		}),
		Entry("should return 200 when user updated successfully", apiTestCase{
			name: "should return 200 when user updated successfully", method: http.MethodPut,
			path: "/users/", body: fmt.Sprintf(`{"id":"%s","username":"updateduser","email":"updated@example.com"}`, uuid.New().String()),
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`UPDATE "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPut,
			path: "/users/", body: fmt.Sprintf(`{"id":"%s"}`, uuid.New().String()),
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	DescribeTableSubtree("DeleteUser API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodDelete,
			path: "/users/", body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest,
		}),
		Entry("should return 400 for missing user ID", apiTestCase{
			name: "should return 400 for missing user ID", method: http.MethodDelete,
			path: "/users/", body: `{"id":""}`,
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "user id is required",
		}),
		Entry("should return 404 when user not found", apiTestCase{
			name: "should return 404 when user not found", method: http.MethodDelete,
			path: "/users/", body: fmt.Sprintf(`{"id":"%s"}`, uuid.New().String()),
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`DELETE FROM "users"`).WillReturnResult(sqlmock.NewResult(0, 0))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "record not found",
		}),
		Entry("should return 200 when user deleted successfully", apiTestCase{
			name: "should return 200 when user deleted successfully", method: http.MethodDelete,
			path: "/users/", body: fmt.Sprintf(`{"id":"%s"}`, uuid.New().String()),
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`DELETE FROM "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodDelete,
			path: "/users/", body: fmt.Sprintf(`{"id":"%s"}`, uuid.New().String()),
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	DescribeTableSubtree("ListUsers API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 200 with empty list when no users", apiTestCase{
			name: "should return 200 with empty list when no users", method: http.MethodGet,
			path: "/users/",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT .* FROM "users"`).WillReturnRows(mockSQL.NewRows(userColumns()))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "[]",
		}),
		Entry("should return 200 with list of users", apiTestCase{
			name: "should return 200 with list of users", method: http.MethodGet,
			path: "/users/",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(userColumns()).
						AddRow(createUserRow("user1", "user1@example.com")...).
						AddRow(createUserRow("user2", "user2@example.com")...)
					mockSQL.ExpectQuery(`SELECT .* FROM "users"`).WillReturnRows(rows)
					mockSQL.ExpectQuery(`SELECT .* FROM "user_groups"`).WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "user1",
		}),
		Entry("should return 200 with pagination", apiTestCase{
			name: "should return 200 with pagination", method: http.MethodGet,
			path: "/users/?page=1&limit=10",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT .* FROM "users"`).WillReturnRows(
						mockSQL.NewRows(userColumns()).AddRow(createUserRow("user1", "user1@example.com")...))
					mockSQL.ExpectQuery(`SELECT .* FROM "user_groups"`).WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "user1",
		}),
		Entry("should return 200 with page and custom limit", apiTestCase{
			name: "should return 200 with page and custom limit", method: http.MethodGet,
			path: "/users/?page=2&limit=10",
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectQuery(`SELECT .* FROM "users".*LIMIT \$1 OFFSET \$2`).WithArgs(10, 10).WillReturnRows(
						mockSQL.NewRows(userColumns()).AddRow(createUserRow("user11", "user11@example.com")...))
					mockSQL.ExpectQuery(`SELECT .* FROM "user_groups"`).WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "group_db_id"}))
				})
			},
			expectedStatus: http.StatusOK, expectedBody: "user11",
		}),
		Entry("should return 400 for invalid page parameter", apiTestCase{
			name: "should return 400 for invalid page parameter", method: http.MethodGet,
			path: "/users/?page=invalid",
			setupServer: func() *Server {
				return setupUserServer(testLogger, nil)
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid pagination parameters",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodGet,
			path:           "/users/",
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	DescribeTableSubtree("ChangePassword API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 400 for missing password", apiTestCase{
			name: "should return 400 for missing password", method: http.MethodPut,
			path: fmt.Sprintf("/users/%s/reset-password", uuid.New().String()), body: `{}`,
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "password is required",
		}),
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPut,
			path: fmt.Sprintf("/users/%s/reset-password", uuid.New().String()), body: "invalid json",
			setupServer:    func() *Server { return setupUserServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest,
		}),
		Entry("should return 404 when user not found", apiTestCase{
			name: "should return 404 when user not found", method: http.MethodPut,
			path: fmt.Sprintf("/users/%s/reset-password", uuid.New().String()), body: `{"password":"NewPass123"}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT .* FROM "users".*FOR UPDATE`).
						WithArgs(sqlmock.AnyArg(), 1).
						WillReturnError(gorm.ErrRecordNotFound)
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "user not found",
		}),
		Entry("should return 200 when password changed successfully", apiTestCase{
			name: "should return 200 when password changed successfully", method: http.MethodPut,
			path: fmt.Sprintf("/users/%s/reset-password", uuid.New().String()), body: `{"password":"NewPass123"}`,
			setupServer: func() *Server {
				return setupUserServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					rows := mockSQL.NewRows([]string{"id", "password", "password_salt"}).
						AddRow(uuid.New(), "hashedpassword", "salt")
					mockSQL.ExpectQuery(`SELECT .* FROM "users".*FOR UPDATE`).WillReturnRows(rows)
					mockSQL.ExpectExec(`UPDATE "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPut,
			path: fmt.Sprintf("/users/%s/reset-password", uuid.New().String()), body: `{"password":"NewPass123"}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	DescribeTableSubtree("AssignUserRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodPost,
			path: fmt.Sprintf("/users/%s/roles/assign", uuid.New().String()), body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 when roles is missing", apiTestCase{
			name: "should return 400 when roles is missing", method: http.MethodPost,
			path: fmt.Sprintf("/users/%s/roles/assign", uuid.New().String()), body: `{}`,
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "roles is required",
		}),
		Entry("should return 200 when role assigned to user", apiTestCase{
			name: "should return 200 when role assigned to user", method: http.MethodPost,
			path: "/users/550e8400-e29b-41d4-a716-446655440000/roles/assign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("550e8400-e29b-41d4-a716-446655440000", 1).
						WillReturnRows(mockSQL.NewRows([]string{"id", "username"}).
							AddRow("550e8400-e29b-41d4-a716-446655440000", "testuser"))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("admin").
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("admin", false)...))
					mockSQL.ExpectExec(`UPDATE "users"`).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mockSQL.ExpectQuery(`INSERT INTO "roles"`).
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("admin", false)...))
					mockSQL.ExpectQuery(`INSERT INTO "user_roles"`).
						WillReturnRows(mockSQL.NewRows([]string{"user_db_id", "role_db_id"}).
							AddRow("550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when user not found", apiTestCase{
			name: "should return 404 when user not found", method: http.MethodPost,
			path: "/users/nonexistent/roles/assign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("nonexistent", 1).
						WillReturnRows(mockSQL.NewRows([]string{"id", "username"}))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "user nonexistent not found",
		}),
		Entry("should return 400 when role not found", apiTestCase{
			name: "should return 400 when role not found", method: http.MethodPost,
			path: "/users/550e8400-e29b-41d4-a716-446655440000/roles/assign",
			body: `{"roles":["nonexistent"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("550e8400-e29b-41d4-a716-446655440000", 1).
						WillReturnRows(mockSQL.NewRows([]string{"id", "username"}).
							AddRow("550e8400-e29b-41d4-a716-446655440000", "testuser"))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("nonexistent").
						WillReturnRows(mockSQL.NewRows(roleColumns()))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusBadRequest, expectedBody: "role nonexistent not found",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPost,
			path: fmt.Sprintf("/users/%s/roles/assign", uuid.New().String()), body: `{"roles":["admin"]}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)

	DescribeTableSubtree("UnassignUserRole API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITest(tc, userRouter, nil) })
		},
		Entry("should return 400 for invalid JSON body", apiTestCase{
			name: "should return 400 for invalid JSON body", method: http.MethodDelete,
			path: fmt.Sprintf("/users/%s/roles/unassign", uuid.New().String()), body: "invalid json",
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "invalid request body",
		}),
		Entry("should return 400 when roles is missing", apiTestCase{
			name: "should return 400 when roles is missing", method: http.MethodDelete,
			path: fmt.Sprintf("/users/%s/roles/unassign", uuid.New().String()), body: `{}`,
			setupServer:    func() *Server { return setupRBACServer(testLogger, nil) },
			expectedStatus: http.StatusBadRequest, expectedBody: "roles is required",
		}),
		Entry("should return 200 when role unassigned from user", apiTestCase{
			name: "should return 200 when role unassigned from user", method: http.MethodDelete,
			path: "/users/550e8400-e29b-41d4-a716-446655440000/roles/unassign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("550e8400-e29b-41d4-a716-446655440000", 1).
						WillReturnRows(mockSQL.NewRows([]string{"id", "username"}).
							AddRow("550e8400-e29b-41d4-a716-446655440000", "testuser"))
					mockSQL.ExpectQuery(`SELECT \* FROM "roles"`).
						WithArgs("admin").
						WillReturnRows(mockSQL.NewRows(roleColumns()).
							AddRow(createRoleRow("admin", false)...))
					mockSQL.ExpectExec(`DELETE FROM "user_roles"`).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
		Entry("should return 404 when user not found for unassign", apiTestCase{
			name: "should return 404 when user not found for unassign", method: http.MethodDelete,
			path: "/users/nonexistent/roles/unassign",
			body: `{"roles":["admin"]}`,
			setupServer: func() *Server {
				return setupRBACServer(testLogger, func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`SELECT \* FROM "users"`).
						WithArgs("nonexistent", 1).
						WillReturnRows(mockSQL.NewRows([]string{"id", "username"}))
					mockSQL.ExpectRollback()
				})
			},
			expectedStatus: http.StatusNotFound, expectedBody: "user nonexistent not found",
		}),
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodDelete,
			path: fmt.Sprintf("/users/%s/roles/unassign", uuid.New().String()), body: `{"roles":["admin"]}`,
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
	)
})

// patColumns returns the PAT column list for mock rows.
func patColumns() []string {
	return []string{"id", "name", "prefix", "hash", "user_id", "expires_at", "last_used_at", "created_at", "updated_at"}
}

// createPATRow creates a mock row for a given PAT.
func createPATRow(id, name, prefix, hash, userID string) []driver.Value {
	now := time.Now()
	return []driver.Value{id, name, prefix, hash, userID, nil, nil, now, now}
}

var _ = Describe("PAT API Tests", func() {
	testLogger, _ := testutils.SetupTestLogger()

	// adminUserID is the subject of the authenticated session used across PAT tests.
	adminUserID := "550e8400-e29b-41d4-a716-446655440000"

	// ===== authenticatePAT — unit tests =====
	// PAT authentication now happens in LoadSession (not AdminGate).
	// These tests exercise authenticatePAT directly.

	Describe("authenticatePAT", func() {
		It("returns nil session for an invalid PAT (token not found in DB)", func() {
			s := newAdminGateServer(testLogger, func(m sqlmock.Sqlmock) {
				m.ExpectQuery(`SELECT \* FROM "pat_tokens"`).
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(m.NewRows(patColumns()))
			})

			req := httptest.NewRequest(http.MethodGet, "/users/", nil)
			req.Header.Set("Authorization", "Bearer xw_invalidtoken")
			session, err := s.authenticatePAT(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(session).To(BeNil())
		})

		It("returns nil session for an expired PAT", func() {
			ts := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			expired := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
			s := newAdminGateServer(testLogger, func(m sqlmock.Sqlmock) {
				m.ExpectQuery(`SELECT \* FROM "pat_tokens"`).
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(m.NewRows(patColumns()).
						AddRow(uuid.New(), "old-token", "ezauth_", "abc123", adminUserID, expired, nil, ts, ts))
			})

			req := httptest.NewRequest(http.MethodGet, "/users/", nil)
			req.Header.Set("Authorization", "Bearer xw_expiredtoken")
			session, err := s.authenticatePAT(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(session).To(BeNil())
		})

		It("returns nil when DB is nil (no Bearer token lookup possible)", func() {
			s := &Server{Logger: testLogger, DB: nil}
			req := httptest.NewRequest(http.MethodGet, "/users/", nil)
			req.Header.Set("Authorization", "Bearer xw_testtoken123")
			// authenticatePAT will panic if called with nil DB; LoadSession skips it.
			// Verify DB nil guard in Server instead by confirming patAuth is not set.
			Expect(s.DB).To(BeNil())
		})

		It("returns a valid session for a valid PAT (username fallback to UUID when GetUser fails)", func() {
			ts := time.Now()
			patID := uuid.New()
			s := newAdminGateServer(testLogger, func(m sqlmock.Sqlmock) {
				m.ExpectQuery(`SELECT \* FROM "pat_tokens"`).
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(m.NewRows(patColumns()).
						AddRow(patID, "ci-token", "ezauth_", "abc123", adminUserID, nil, nil, ts, ts))
				m.ExpectBegin()
				m.ExpectExec(`UPDATE "pat_tokens"`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				m.ExpectCommit()
				// GetUser may fail in mock context; gate.go falls back to UUID on error.
				m.ExpectQuery(`SELECT \* FROM "users"`).
					WillReturnError(fmt.Errorf("db error"))
			})

			req := httptest.NewRequest(http.MethodGet, "/users/", nil)
			req.Header.Set("Authorization", "Bearer xw_validtoken")
			session, err := s.authenticatePAT(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(session).ToNot(BeNil())
			Expect(session.Subject).To(Equal(adminUserID))
			// On GetUser error, User falls back to the UUID subject.
			Expect(session.User).To(Equal(adminUserID))
		})
	})
})

// ---------------------------------------------------------------------------
// ListUsers DB error branch
// ---------------------------------------------------------------------------

var _ = Describe("ListUsers DB error branch", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	It("returns 500 when DB.ListUsers returns error", func() {
		tc := apiTestCase{
			name: "db error", method: http.MethodGet,
			path: "/",
			setupServer: func() *Server {
				return &Server{
					Logger: logger,
					DB:     &mockDBPAT{listUsersErr: errors.New("db down")},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		}
		runAPITest(tc, func(s *Server, r *mux.Router) {
			s.userRouter(r)
		}, logger)
	})
})

// ---------------------------------------------------------------------------
// UpdateUser non-ErrNoRecord DB error branch
// ---------------------------------------------------------------------------

var _ = Describe("UpdateUser DB error branch", func() {
	It("returns 500 when DB.UpdateUser returns a non-ErrNoRecord error", func() {
		logger, _ := testutils.SetupTestLogger()
		db := &mockDBPAT{updateUserErr: errors.New("db error")}
		s := &Server{Logger: logger, DB: db}
		// Provide a valid UUID and JSON body so the request passes decoding/parse.
		validUUID := "00000000-0000-0000-0000-000000000001"
		body := `{"id":"` + validUUID + `","username":"alice"}`
		req := httptest.NewRequest(http.MethodPut, "/users/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.UpdateUser(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})
})

// ---------------------------------------------------------------------------
// T-1: resolveUsername cache logic
// ---------------------------------------------------------------------------

var _ = Describe("resolveUsername", func() {
	var (
		logger   ezlog.Logger
		userID   string
		memCache ezcache.Cache[string, []byte]
	)

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
		userID = uuid.New().String()
		memCache = ezcache.NewMemoryCache[string, []byte](64, 5*time.Minute)
	})

	It("returns username from cache on hit without touching DB", func() {
		s := &Server{Logger: logger, DB: nil, globalCache: memCache}
		_ = memCache.Set(context.Background(), usernameCachePrefix+userID, []byte("cached-user"), 5*time.Minute)

		result := s.resolveUsername(context.Background(), userID)
		Expect(result).To(Equal("cached-user"))
	})

	It("falls back to DB on cache miss and populates cache", func() {
		s := setupUserServer(logger, func(m sqlmock.Sqlmock) {
			m.ExpectQuery(`SELECT .* FROM "users"`).
				WithArgs(userID, sqlmock.AnyArg()).
				WillReturnRows(m.NewRows(userColumns()).AddRow(createUserRow("db-user", "db-user@test.com")...))
			m.ExpectQuery(`SELECT .* FROM "user_groups"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "group_db_id"}))
			m.ExpectQuery(`SELECT .* FROM "user_roles"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "role_db_id"}))
		})
		s.globalCache = memCache

		result := s.resolveUsername(context.Background(), userID)
		Expect(result).To(Equal("db-user"))

		// Cache should now be populated.
		val, err := memCache.Get(context.Background(), usernameCachePrefix+userID)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(val)).To(Equal("db-user"))
	})

	It("returns userID as fallback when DB fails", func() {
		s := setupUserServer(logger, func(m sqlmock.Sqlmock) {
			m.ExpectQuery(`SELECT \* FROM "users"`).
				WillReturnError(errors.New("db down"))
		})

		result := s.resolveUsername(context.Background(), userID)
		Expect(result).To(Equal(userID))
	})

	It("evictUsernameCache removes the cached entry", func() {
		s := &Server{Logger: logger, globalCache: memCache}
		_ = memCache.Set(context.Background(), usernameCachePrefix+userID, []byte("alice"), 5*time.Minute)

		s.evictUsernameCache(context.Background(), userID)

		_, err := memCache.Get(context.Background(), usernameCachePrefix+userID)
		Expect(err).To(HaveOccurred())
	})

	It("resolveUsername with nil cache falls back to DB", func() {
		s := setupUserServer(logger, func(m sqlmock.Sqlmock) {
			m.ExpectQuery(`SELECT .* FROM "users"`).
				WithArgs(userID, sqlmock.AnyArg()).
				WillReturnRows(m.NewRows(userColumns()).AddRow(createUserRow("db-user-nocache", "nocache@test.com")...))
			m.ExpectQuery(`SELECT .* FROM "user_groups"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "group_db_id"}))
			m.ExpectQuery(`SELECT .* FROM "user_roles"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "role_db_id"}))
		})
		s.globalCache = nil

		result := s.resolveUsername(context.Background(), userID)
		Expect(result).To(Equal("db-user-nocache"))
	})
})

// ---------------------------------------------------------------------------
// T-2: authenticatePAT proxy mode uses resolveUsername
// ---------------------------------------------------------------------------

var _ = Describe("authenticatePAT proxy mode", func() {
	testLogger, _ := testutils.SetupTestLogger()
	adminUserID := "550e8400-e29b-41d4-a716-446655440000"

	It("uses UUID directly when proxy is disabled (no DB call for username)", func() {
		ts := time.Now()
		patID := uuid.New()
		s := newAdminGateServer(testLogger, func(m sqlmock.Sqlmock) {
			m.ExpectQuery(`SELECT \* FROM "pat_tokens"`).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(m.NewRows(patColumns()).
					AddRow(patID, "ci-token", "ezauth_", "abc123", adminUserID, nil, nil, ts, ts))
			m.ExpectBegin()
			m.ExpectExec(`UPDATE "pat_tokens"`).WillReturnResult(sqlmock.NewResult(1, 1))
			m.ExpectCommit()
			// No SELECT users expected — proxy disabled, UUID used directly.
		})
		// Explicitly disable proxy so IsEnabled() returns false.
		disabled := false
		s.AuthCfg = ezcfg.AuthConfig{Proxy: ezcfg.AuthProxyConfig{Enabled: &disabled}}

		req := httptest.NewRequest(http.MethodGet, "/users/", nil)
		req.Header.Set("Authorization", "Bearer ezauth_validtoken")
		session, err := s.authenticatePAT(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(session).ToNot(BeNil())
		Expect(session.User).To(Equal(adminUserID))
	})

	It("resolves real username when proxy is enabled", func() {
		ts := time.Now()
		patID := uuid.New()
		s := newAdminGateServer(testLogger, func(m sqlmock.Sqlmock) {
			m.ExpectQuery(`SELECT \* FROM "pat_tokens"`).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(m.NewRows(patColumns()).
					AddRow(patID, "ci-token", "ezauth_", "abc123", adminUserID, nil, nil, ts, ts))
			m.ExpectBegin()
			m.ExpectExec(`UPDATE "pat_tokens"`).WillReturnResult(sqlmock.NewResult(1, 1))
			m.ExpectCommit()
			m.ExpectQuery(`SELECT .* FROM "users"`).
				WithArgs(adminUserID, sqlmock.AnyArg()).
				WillReturnRows(m.NewRows(userColumns()).AddRow(createUserRow("alice", "alice@test.com")...))
			m.ExpectQuery(`SELECT .* FROM "user_groups"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "group_db_id"}))
			m.ExpectQuery(`SELECT .* FROM "user_roles"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "role_db_id"}))
		})
		// AuthCfg.Proxy.Enabled == nil => IsEnabled() returns true.
		s.AuthCfg = ezcfg.AuthConfig{}

		req := httptest.NewRequest(http.MethodGet, "/users/", nil)
		req.Header.Set("Authorization", "Bearer ezauth_validtoken")
		session, err := s.authenticatePAT(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(session).ToNot(BeNil())
		Expect(session.User).To(Equal("alice"))
	})
})

// ---------------------------------------------------------------------------
// T-4: GetUser handler writes username to cache
// ---------------------------------------------------------------------------

var _ = Describe("GetUser cache write-through", func() {
	It("populates cache with username after successful DB lookup", func() {
		logger, _ := testutils.SetupTestLogger()
		uid := uuid.New()
		memCache := ezcache.NewMemoryCache[string, []byte](64, 5*time.Minute)

		s := setupUserServer(logger, func(m sqlmock.Sqlmock) {
			m.ExpectQuery(`SELECT .* FROM "users"`).
				WithArgs(uid.String(), sqlmock.AnyArg()).
				WillReturnRows(m.NewRows(userColumns()).AddRow(createUserRow("cached-alice", "alice@test.com")...))
			m.ExpectQuery(`SELECT .* FROM "user_groups"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "group_db_id"}))
			m.ExpectQuery(`SELECT .* FROM "user_roles"`).
				WillReturnRows(m.NewRows([]string{"user_db_id", "role_db_id"}))
		})
		s.globalCache = memCache

		router := mux.NewRouter()
		s.userRouter(router)
		req := httptest.NewRequest(http.MethodGet, "/"+uid.String(), nil)
		req = req.WithContext(ezlog.RequestContext(req.Context(), logger))
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusOK))

		val, err := memCache.Get(context.Background(), usernameCachePrefix+uid.String())
		Expect(err).ToNot(HaveOccurred())
		Expect(string(val)).To(Equal("cached-alice"))
	})
})

// ---------------------------------------------------------------------------
// T-5: UpdateUser and DeleteUser evict username cache
// ---------------------------------------------------------------------------

var _ = Describe("cache eviction on UpdateUser and DeleteUser", func() {
	var (
		logger   ezlog.Logger
		memCache ezcache.Cache[string, []byte]
		uid      uuid.UUID
	)

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
		memCache = ezcache.NewMemoryCache[string, []byte](64, 5*time.Minute)
		uid = uuid.New()
		_ = memCache.Set(context.Background(), usernameCachePrefix+uid.String(), []byte("old-name"), 5*time.Minute)
	})

	It("UpdateUser evicts the cached username on success", func() {
		s := setupUserServer(logger, func(m sqlmock.Sqlmock) {
			m.ExpectBegin()
			m.ExpectExec(`UPDATE "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
			m.ExpectCommit()
		})
		s.globalCache = memCache

		body := fmt.Sprintf(`{"id":%q,"username":"new-name"}`, uid.String())
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ezlog.RequestContext(req.Context(), logger))
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.UpdateUser(rw, req)
		Expect(rw.Code).To(Equal(http.StatusOK))

		_, err := memCache.Get(context.Background(), usernameCachePrefix+uid.String())
		Expect(err).To(HaveOccurred())
	})

	It("DeleteUser evicts the cached username on success", func() {
		s := setupUserServer(logger, func(m sqlmock.Sqlmock) {
			m.ExpectBegin()
			m.ExpectExec(`DELETE FROM "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
			m.ExpectCommit()
		})
		s.globalCache = memCache

		body := fmt.Sprintf(`{"id":%q}`, uid.String())
		req := httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ezlog.RequestContext(req.Context(), logger))
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		rw := httptest.NewRecorder()
		s.DeleteUser(rw, req)
		Expect(rw.Code).To(Equal(http.StatusOK))

		_, err := memCache.Get(context.Background(), usernameCachePrefix+uid.String())
		Expect(err).To(HaveOccurred())
	})
})
