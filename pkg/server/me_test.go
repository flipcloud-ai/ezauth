package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// setupMeServer creates a Server with a mock database for /me endpoint tests.
func setupMeServer(mockSetup func(sqlmock.Sqlmock)) *Server {
	logger, err := testutils.SetupTestLogger()
	Expect(err).ToNot(HaveOccurred())

	gormDB, mockSQL, err := testutils.MockSQLPool()
	Expect(err).ToNot(HaveOccurred())
	mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
	mockDB.DB = gormDB
	if mockSetup != nil {
		mockSetup(mockSQL)
	}
	return &Server{
		Logger:  logger,
		DB:      mockDB,
		AuthCfg: ezcfg.AuthConfig{OpaqueToken: ezcfg.OpaqueTokenConfig{Prefix: "ezauth_"}},
	}
}

var _ = Describe("Me API Tests", func() {
	testLogger, _ := testutils.SetupTestLogger()

	dbUserID := "550e8400-e29b-41d4-a716-446655440000"

	dbSession := &ezapi.Session{
		Profile: ezapi.Profile{
			Subject: dbUserID,
			User:    "alice",
			IDType:  ezapi.UserIDType,
		},
	}

	oidcSession := &ezapi.Session{
		Profile: ezapi.Profile{
			Subject:           "oidc-sub",
			User:              "bob",
			Email:             "bob@example.com",
			FirstName:         "Bob",
			LastName:          "Smith",
			Groups:            []string{"devs"},
			IDType:            ezapi.OIDCUserIDType,
			PreferredUsername: "bobsmith",
		},
	}

	// meRouter mounts /me handlers directly (no middleware chain) so that
	// runAPITestWithSession can inject the session via ezapi.AddRequestInfo.
	meRouter := func(s *Server, r *mux.Router) {
		r.HandleFunc("/me", s.GetMe).Methods("GET")
		r.HandleFunc("/me/tokens", s.ListMyTokens).Methods("GET")
		r.HandleFunc("/me/tokens", s.CreateMyToken).Methods("POST")
		r.HandleFunc("/me/tokens/{id}", s.DeleteMyToken).Methods("DELETE")
	}

	// ===== GetMe =====

	DescribeTableSubtree("GetMe API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, nil, testLogger) })
		},
		Entry("should return 401 when session is nil", apiTestCase{
			name: "should return 401 when session is nil", method: http.MethodGet, path: "/me",
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusUnauthorized,
		}),
	)

	DescribeTableSubtree("GetMe OIDC user API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, oidcSession, testLogger) })
		},
		Entry("should return 200 for OIDC user without DB call", apiTestCase{
			name: "should return 200 for OIDC user without DB call", method: http.MethodGet, path: "/me",
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusOK,
			expectedBody:   "bob",
		}),
	)

	// GetMe no longer fetches from DB — it reads entirely from the session.
	// DB user sessions return 200 from session data regardless of DB availability.
	DescribeTableSubtree("GetMe DB user API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, dbSession, testLogger) })
		},
		Entry("should return 200 for DB user even when DB is nil — profile comes from session", apiTestCase{
			name: "should return 200 for DB user even when DB is nil — profile comes from session", method: http.MethodGet, path: "/me",
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusOK,
			expectedBody:   "alice",
		}),
		Entry("should return 200 for DB user with DB available — no DB call made", apiTestCase{
			name: "should return 200 for DB user with DB available — no DB call made", method: http.MethodGet, path: "/me",
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusOK,
			expectedBody:   "alice",
		}),
	)

	// ===== ListMyTokens =====

	DescribeTableSubtree("ListMyTokens API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, nil, testLogger) })
		},
		Entry("should return 401 when session is nil", apiTestCase{
			name: "should return 401 when session is nil", method: http.MethodGet, path: "/me/tokens",
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusUnauthorized,
		}),
	)

	DescribeTableSubtree("ListMyTokens with DB session API tests",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, dbSession, testLogger) })
		},
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodGet, path: "/me/tokens",
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
		Entry("should return 200 with token list", apiTestCase{
			name: "should return 200 with token list", method: http.MethodGet, path: "/me/tokens",
			setupServer: func() *Server {
				return setupMeServer(func(mockSQL sqlmock.Sqlmock) {
					rows := mockSQL.NewRows(patColumns()).
						AddRow(createPATRow("770e8400-e29b-41d4-a716-446655440002", "ci-token", "ezauth_", "abc123", dbUserID)...)
					mockSQL.ExpectQuery(`SELECT \* FROM "pat_tokens"`).
						WithArgs(dbUserID).WillReturnRows(rows)
				})
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "ci-token",
		}),
	)

	// ===== CreateMyToken =====

	DescribeTableSubtree("CreateMyToken API tests — no session",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, nil, testLogger) })
		},
		Entry("should return 401 when session is nil", apiTestCase{
			name: "should return 401 when session is nil", method: http.MethodPost, path: "/me/tokens",
			body:           `{"name":"my-token"}`,
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusUnauthorized,
		}),
	)

	DescribeTableSubtree("CreateMyToken API tests — OIDC user",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, oidcSession, testLogger) })
		},
		Entry("should return 400 for OIDC user with DB", apiTestCase{
			name: "should return 400 for OIDC user with DB", method: http.MethodPost, path: "/me/tokens",
			body:           `{"name":"my-token"}`,
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "not supported for OIDC users",
		}),
		Entry("should return 400 for OIDC user without DB", apiTestCase{
			name: "should return 400 for OIDC user without DB", method: http.MethodPost, path: "/me/tokens",
			body: `{"name":"my-token"}`,
			setupServer: func() *Server {
				return &Server{Logger: testLogger, DB: nil, AuthCfg: ezcfg.AuthConfig{OpaqueToken: ezcfg.OpaqueTokenConfig{Prefix: "ezauth_"}}}
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "not supported for OIDC users",
		}),
	)

	DescribeTableSubtree("CreateMyToken API tests — DB user",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, dbSession, testLogger) })
		},
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodPost, path: "/me/tokens",
			body: `{"name":"my-token"}`,
			setupServer: func() *Server {
				return &Server{Logger: testLogger, DB: nil, AuthCfg: ezcfg.AuthConfig{OpaqueToken: ezcfg.OpaqueTokenConfig{Prefix: "ezauth_"}}}
			},
			expectedStatus: http.StatusNotFound,
		}),
		Entry("should return 400 when name is missing", apiTestCase{
			name: "should return 400 when name is missing", method: http.MethodPost, path: "/me/tokens",
			body:           `{}`,
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "token name is required",
		}),
		Entry("should return 400 for name longer than 128 chars", apiTestCase{
			name: "should return 400 for name longer than 128 chars", method: http.MethodPost, path: "/me/tokens",
			// 129 'a' characters — exceeds maxTokenNameLen
			body:           `{"name":"` + strings.Repeat("a", 129) + `"}`,
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "token name must be at most 128 characters",
		}),
		Entry("should return 400 when expires_at is missing", apiTestCase{
			name: "should return 400 when expires_at is missing", method: http.MethodPost, path: "/me/tokens",
			body:           `{"name":"my-token"}`,
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "expires_at is required",
		}),
		Entry("should return 400 for expires_at in the past", apiTestCase{
			name: "should return 400 for expires_at in the past", method: http.MethodPost, path: "/me/tokens",
			body:           `{"name":"my-token","expires_at":"2000-01-01T00:00:00Z"}`,
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "expires_at must be in the future",
		}),
		Entry("should return 400 for expires_at exceeding 365 days", apiTestCase{
			name: "should return 400 for expires_at exceeding 365 days", method: http.MethodPost, path: "/me/tokens",
			body:           `{"name":"my-token","expires_at":"2099-01-01T00:00:00Z"}`,
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "expires_at must be at most 365 days from now",
		}),
		Entry("should return 201 with token on success", apiTestCase{
			name: "should return 201 with token on success", method: http.MethodPost, path: "/me/tokens",
			body: `{"name":"my-token","expires_at":"` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `"}`,
			setupServer: func() *Server {
				return setupMeServer(func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectQuery(`INSERT INTO "pat_tokens"`).
						WillReturnRows(mockSQL.NewRows(patColumns()).
							AddRow(createPATRow("770e8400-e29b-41d4-a716-446655440002", "my-token", "ezauth_", "abc123", dbUserID)...))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusCreated,
			expectedBody:   `"token":`,
		}),
	)

	// ===== DeleteMyToken =====

	DescribeTableSubtree("DeleteMyToken API tests — no session",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, nil, testLogger) })
		},
		Entry("should return 401 when session is nil", apiTestCase{
			name: "should return 401 when session is nil", method: http.MethodDelete,
			path:           "/me/tokens/770e8400-e29b-41d4-a716-446655440002",
			setupServer:    func() *Server { return setupMeServer(nil) },
			expectedStatus: http.StatusUnauthorized,
		}),
	)

	DescribeTableSubtree("DeleteMyToken API tests — DB user",
		func(tc apiTestCase) {
			It(tc.name, func() { runAPITestWithSession(tc, meRouter, dbSession, testLogger) })
		},
		Entry("should return 404 when DB is nil", apiTestCase{
			name: "should return 404 when DB is nil", method: http.MethodDelete,
			path:           "/me/tokens/770e8400-e29b-41d4-a716-446655440002",
			setupServer:    func() *Server { return &Server{Logger: testLogger, DB: nil} },
			expectedStatus: http.StatusNotFound,
		}),
		Entry("should return 404 when token not found", apiTestCase{
			name: "should return 404 when token not found", method: http.MethodDelete,
			path: "/me/tokens/880e8400-e29b-41d4-a716-446655440003",
			setupServer: func() *Server {
				return setupMeServer(func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`DELETE FROM "pat_tokens"`).
						WithArgs("880e8400-e29b-41d4-a716-446655440003", dbUserID).
						WillReturnResult(sqlmock.NewResult(0, 0))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusNotFound,
			expectedBody:   "token not found",
		}),
		Entry("should return 200 when token revoked", apiTestCase{
			name: "should return 200 when token revoked", method: http.MethodDelete,
			path: "/me/tokens/770e8400-e29b-41d4-a716-446655440002",
			setupServer: func() *Server {
				return setupMeServer(func(mockSQL sqlmock.Sqlmock) {
					mockSQL.ExpectBegin()
					mockSQL.ExpectExec(`DELETE FROM "pat_tokens"`).
						WithArgs("770e8400-e29b-41d4-a716-446655440002", dbUserID).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mockSQL.ExpectCommit()
				})
			},
			expectedStatus: http.StatusOK,
		}),
	)
})

// ---------------------------------------------------------------------------
// me.go PAT endpoint error branches
// ---------------------------------------------------------------------------

var _ = Describe("me.go PAT endpoint error branches", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	authedReq := func(method, path string, body string) *http.Request {
		var req *http.Request
		if body != "" {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{
			Session: &ezapi.Session{
				Profile: ezapi.Profile{
					User:    "testuser",
					Subject: "test-subject-uuid",
					IDType:  ezapi.UserIDType,
				},
			},
		})
		return req
	}

	It("ListMyTokens returns 500 when DB.ListPATs returns error", func() {
		s := &Server{
			Logger: logger,
			DB:     &mockDBPAT{listPATsErr: errors.New("db down")},
		}
		req := authedReq(http.MethodGet, "/me/tokens", "")
		rw := httptest.NewRecorder()
		s.ListMyTokens(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})

	It("CreateMyToken returns 400 for invalid JSON body", func() {
		s := &Server{
			Logger: logger,
			DB:     &mockDBPAT{},
			AuthCfg: ezcfg.AuthConfig{
				JWT: ezcfg.JWTConfig{},
			},
		}
		req := authedReq(http.MethodPost, "/me/tokens", "not-valid-json")
		rw := httptest.NewRecorder()
		s.CreateMyToken(rw, req)
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
	})

	It("CreateMyToken returns 500 when DB.CreatePAT returns error", func() {
		store, err := sessions.NewSessionStore(&ezcfg.Session{
			Cookie: ezcfg.CookieStoreOptions{
				Name:   "_xw",
				Secret: ezcfg.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		s := &Server{
			Logger:       logger,
			sessionStore: store,
			DB:           &mockDBPAT{createPATErr: errors.New("db write failed")},
			AuthCfg: ezcfg.AuthConfig{
				JWT: ezcfg.JWTConfig{},
			},
		}
		// Use an expiry 1 hour from now to pass validation.
		body := `{"name":"mytoken","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
		req := authedReq(http.MethodPost, "/me/tokens", body)
		rw := httptest.NewRecorder()
		s.CreateMyToken(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})

	It("DeleteMyToken returns 400 when token ID is empty", func() {
		s := &Server{
			Logger: logger,
			DB:     &mockDBPAT{},
		}
		req := authedReq(http.MethodDelete, "/me/tokens/", "")
		// No mux vars → vars["id"] == ""
		rw := httptest.NewRecorder()
		s.DeleteMyToken(rw, req)
		Expect(rw.Code).To(Equal(http.StatusBadRequest))
		Expect(rw.Body.String()).To(ContainSubstring("token id is required"))
	})

	It("DeleteMyToken returns 500 when DB.DeletePAT returns generic error", func() {
		s := &Server{
			Logger: logger,
			DB:     &mockDBPAT{deletePATErr: errors.New("db error")},
		}
		req := authedReq(http.MethodDelete, "/me/tokens/some-id", "")
		req = mux.SetURLVars(req, map[string]string{"id": "some-id"})
		rw := httptest.NewRecorder()
		s.DeleteMyToken(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})
})
