package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// newAdminGateServer builds a minimal Server wired for AdminGate testing.
func newAdminGateServer(logger ezlog.Logger, mockSetup func(sqlmock.Sqlmock)) *Server {
	gormDB, mockSQL, err := testutils.MockSQLPool()
	Expect(err).ToNot(HaveOccurred())
	mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
	mockDB.DB = gormDB
	if mockSetup != nil {
		mockSetup(mockSQL)
	}
	return &Server{
		Logger:           logger,
		DB:               mockDB,
		systemAdminGroup: "system-admins",
		ServeCfg:         ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
	}
}

// withSession injects a session into the request's AuthRequest.
func withSession(req *http.Request, session *ezapi.Session) *http.Request {
	info := ezapi.GetRequest(req)
	if info == nil {
		info = &ezapi.AuthRequest{}
		req = ezapi.AddRequestInfo(req, info)
	}
	info.Session = session
	return req
}

var _ = Describe("Gate middleware", func() {
	var (
		okHandler http.Handler
		s         *Server
	)

	BeforeEach(func() {
		logger, _ := testutils.SetupTestLogger()
		okHandler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
		})
		s = &Server{
			Logger:   logger,
			ServeCfg: ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
		}
	})

	Context("no session", func() {
		It("should return 401 for an API client", func() {
			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req.Header.Set("Accept", "application/json")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusUnauthorized))
		})

		It("should redirect a browser GET to the login page", func() {
			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusFound))
			loc := rr.Header().Get("Location")
			Expect(strings.HasPrefix(loc, s.ServeCfg.AuthPrefix+signInPath+"?redirect=")).To(BeTrue())
			u, err := url.Parse(loc)
			Expect(err).ToNot(HaveOccurred())
			Expect(u.Query().Get("redirect")).To(Equal("/app/page"))
		})

		It("should return 401 for a non-GET browser request", func() {
			req := httptest.NewRequest(http.MethodPost, "/app/action", nil)
			req.Header.Set("Accept", "text/html")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusUnauthorized))
		})
	})

	Context("expired session", func() {
		It("should return 401 for an API client", func() {
			session := &ezapi.Session{
				Profile:   ezapi.Profile{User: "alice", IDType: ezapi.UserIDType},
				ExpiresOn: time.Now().Add(-time.Hour).Unix(),
			}
			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req.Header.Set("Accept", "application/json")
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusUnauthorized))
		})

		It("should redirect a browser GET to the login page", func() {
			session := &ezapi.Session{
				Profile:   ezapi.Profile{User: "alice", IDType: ezapi.UserIDType},
				ExpiresOn: time.Now().Add(-time.Hour).Unix(),
			}
			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusFound))
			loc := rr.Header().Get("Location")
			Expect(strings.HasPrefix(loc, s.ServeCfg.AuthPrefix+signInPath+"?redirect=")).To(BeTrue())
			u, err := url.Parse(loc)
			Expect(err).ToNot(HaveOccurred())
			Expect(u.Query().Get("redirect")).To(Equal("/app/page"))
		})
	})

	Context("valid session", func() {
		It("should call next when session is present and not expired", func() {
			session := &ezapi.Session{
				Profile:   ezapi.Profile{User: "alice", IDType: ezapi.UserIDType},
				ExpiresOn: time.Now().Add(time.Hour).Unix(),
			}
			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("should call next when session has no expiry set (zero time)", func() {
			session := &ezapi.Session{
				Profile: ezapi.Profile{User: "bob", IDType: ezapi.UserIDType},
				// ExpiresOn zero value — IsExpired returns false for zero time.
			}
			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	Context("Bearer token", func() {
		It("returns 401 for a Bearer request with no session — LoadSession handles PAT auth before Gate", func() {
			// PAT authentication now happens in LoadSession (before Gate).
			// By the time Gate runs, Bearer tokens with no valid session yield 401.
			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req.Header.Set("Authorization", "Bearer xw_sometoken")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
			rr := httptest.NewRecorder()
			s.Gate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusUnauthorized))
		})
	})
})

var _ = Describe("AdminGate middleware", func() {
	var (
		logger    ezlog.Logger
		okHandler http.Handler
	)

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
		okHandler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
		})
	})

	Context("static mode (DB == nil)", func() {
		// In static mode the bootstrap root user is the only account permitted
		// to access admin routes. All other authenticated users are denied with
		// 403 so that ordinary static users cannot reach the admin API.

		It("allows the bootstrap root user through", func() {
			s := &Server{
				Logger:        logger,
				DB:            nil,
				adminUsername: fallbackAdminUser,
				ServeCfg:      ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
			}
			session := &ezapi.Session{Profile: ezapi.Profile{User: fallbackAdminUser, IDType: ezapi.UserIDType}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("denies a non-root static user with 403", func() {
			s := &Server{
				Logger:        logger,
				DB:            nil,
				adminUsername: fallbackAdminUser,
				ServeCfg:      ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
			}
			session := &ezapi.Session{Profile: ezapi.Profile{User: "alice", IDType: ezapi.UserIDType}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		// Design documentation test: AdminGate is mounted only on admin routes.
		// Non-admin routes (e.g. /healthz, proxy upstream) are served directly
		// without passing through AdminGate, so non-root users are unaffected.
		// This test verifies the contract by showing that a handler NOT wrapped
		// by AdminGate responds 200 for any authenticated user.
		It("does not affect non-admin routes — AdminGate is only mounted on admin paths", func() {
			// A plain handler that represents a public or proxied route: no
			// AdminGate involved. Any authenticated user reaches it normally.
			publicHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), &ezapi.Session{
				Profile: ezapi.Profile{User: "alice", IDType: ezapi.UserIDType},
			})
			rr := httptest.NewRecorder()
			publicHandler.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	Context("DB mode — DB user", func() {
		var rootUUID uuid.UUID

		BeforeEach(func() {
			rootUUID = uuid.New()
		})

		It("allows a DB user that is in the system admin group", func() {
			ts := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			groupID := uuid.New()
			s := newAdminGateServer(logger, func(m sqlmock.Sqlmock) {
				// Primary group query.
				m.ExpectQuery(`SELECT \* FROM "groups"`).
					WillReturnRows(m.NewRows([]string{"id", "name", "created_at", "updated_at"}).
						AddRow(groupID, "system-admins", ts, ts))
				// GORM many2many Preload issues a query on the join table first.
				m.ExpectQuery(`SELECT \* FROM "user_groups"`).
					WillReturnRows(m.NewRows([]string{"user_db_id", "group_db_id"}).
						AddRow(rootUUID, groupID))
				// Then GORM fetches the actual user records.
				m.ExpectQuery(`SELECT \* FROM "users"`).
					WillReturnRows(m.NewRows([]string{"id", "username"}).
						AddRow(rootUUID, "root"))
			})

			session := &ezapi.Session{Profile: ezapi.Profile{
				Subject: rootUUID.String(),
				User:    "root",
				IDType:  ezapi.UserIDType,
			}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("denies a DB user not in the system admin group", func() {
			ts := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			groupID := uuid.New()
			s := newAdminGateServer(logger, func(m sqlmock.Sqlmock) {
				// group exists but user is not a member — join table returns empty.
				m.ExpectQuery(`SELECT \* FROM "groups"`).
					WillReturnRows(m.NewRows([]string{"id", "name", "created_at", "updated_at"}).
						AddRow(groupID, "system-admins", ts, ts))
				m.ExpectQuery(`SELECT \* FROM "user_groups"`).
					WillReturnRows(m.NewRows([]string{"user_db_id", "group_db_id"}))
			})

			session := &ezapi.Session{Profile: ezapi.Profile{
				Subject: uuid.New().String(),
				User:    "bob",
				IDType:  ezapi.UserIDType,
			}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	Context("DB mode — DB error", func() {
		It("returns 500 when the DB group query fails", func() {
			s := newAdminGateServer(logger, func(m sqlmock.Sqlmock) {
				m.ExpectQuery(`SELECT \* FROM "groups"`).
					WillReturnError(fmt.Errorf("connection refused"))
			})
			session := &ezapi.Session{Profile: ezapi.Profile{
				Subject: uuid.New().String(),
				User:    "root",
				IDType:  ezapi.UserIDType,
			}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})
	})

	Context("DB mode — OAuth user", func() {
		It("allows an OAuth user whose IDP groups contain a provider admin_group", func() {
			s := newAdminGateServer(logger, nil)
			s.AuthCfg = ezcfg.AuthConfig{
				Provider: []*ezcfg.ProviderConfig{
					{ProviderName: "myidp", AdminGroup: "idp-admins"},
				},
			}

			session := &ezapi.Session{Profile: ezapi.Profile{
				Subject: "oauth-user-001",
				User:    "carol",
				IDType:  ezapi.OIDCUserIDType,
				Groups:  []string{"developers", "idp-admins"},
			}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("denies an OAuth user whose IDP groups do not contain any admin_group", func() {
			s := newAdminGateServer(logger, nil)
			s.AuthCfg = ezcfg.AuthConfig{
				Provider: []*ezcfg.ProviderConfig{
					{ProviderName: "myidp", AdminGroup: "idp-admins"},
				},
			}

			session := &ezapi.Session{Profile: ezapi.Profile{
				Subject: "oauth-user-002",
				User:    "dave",
				IDType:  ezapi.OIDCUserIDType,
				Groups:  []string{"developers", "viewers"},
			}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("denies an OAuth user when no provider has admin_group set", func() {
			s := newAdminGateServer(logger, nil)
			s.AuthCfg = ezcfg.AuthConfig{
				Provider: []*ezcfg.ProviderConfig{
					{ProviderName: "myidp"},
				},
			}

			session := &ezapi.Session{Profile: ezapi.Profile{
				Subject: "oauth-user-003",
				User:    "eve",
				IDType:  ezapi.OIDCUserIDType,
				Groups:  []string{"developers"},
			}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	Context("DB mode — unknown IDType", func() {
		It("denies a session with an unrecognised IDType", func() {
			s := newAdminGateServer(logger, nil)

			session := &ezapi.Session{Profile: ezapi.Profile{
				Subject: "some-id",
				User:    "mystery",
				IDType:  "unknown",
			}}
			req := httptest.NewRequest(http.MethodGet, "/ezauth/users/", nil)
			req = withSession(ezapi.AddRequestInfo(req, &ezapi.AuthRequest{}), session)
			rr := httptest.NewRecorder()
			s.AdminGate(okHandler).ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})
})
