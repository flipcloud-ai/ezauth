package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	eztmpl "github.com/flipcloud-ai/ezauth/pkg/server/templates"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// apiTestCase is a unified test case struct for API endpoint tests.
type apiTestCase struct {
	name           string
	method         string
	path           string
	body           string
	setupServer    func() *Server
	setupMock      func()
	expectedStatus int
	expectedBody   string
}

// runAPITest executes an API test case against the given router setup.
// If logger is non-nil, it is injected into the request context via ezlog.RequestContext.
func runAPITest(tc apiTestCase, setupRouter func(*Server, *mux.Router), logger ezlog.Logger) {
	if tc.setupMock != nil {
		tc.setupMock()
	}
	s := tc.setupServer()
	router := mux.NewRouter()
	setupRouter(s, router)

	var req *http.Request
	if tc.method == "POST" || tc.method == "PUT" || tc.method == "DELETE" {
		req, _ = http.NewRequestWithContext(context.Background(), tc.method, tc.path, bytes.NewBufferString(tc.body))
	} else {
		req, _ = http.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	if logger != nil {
		req = req.WithContext(ezlog.RequestContext(req.Context(), logger))
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	Expect(rr.Code).To(Equal(tc.expectedStatus))
	if tc.expectedBody != "" {
		Expect(rr.Body.String()).To(ContainSubstring(tc.expectedBody))
	}
}

// runAPITestWithSession executes an API test case with a pre-injected session.
func runAPITestWithSession(tc apiTestCase, setupRouter func(*Server, *mux.Router), session *ezapi.Session, logger ezlog.Logger) {
	if tc.setupMock != nil {
		tc.setupMock()
	}
	s := tc.setupServer()
	router := mux.NewRouter()
	setupRouter(s, router)

	var req *http.Request
	if tc.body != "" {
		req, _ = http.NewRequestWithContext(context.Background(), tc.method, tc.path, bytes.NewBufferString(tc.body))
	} else {
		req, _ = http.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	if logger != nil {
		req = req.WithContext(ezlog.RequestContext(req.Context(), logger))
	}

	reqInfo := &ezapi.AuthRequest{Session: session}
	req = ezapi.AddRequestInfo(req, reqInfo)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	Expect(rr.Code).To(Equal(tc.expectedStatus))
	if tc.expectedBody != "" {
		Expect(rr.Body.String()).To(ContainSubstring(tc.expectedBody))
	}
}

// ---------------------------------------------------------------------------
// pagination – covers negative and out-of-range param branches
// ---------------------------------------------------------------------------

var _ = Describe("pagination", func() {
	makeReq := func(query string) *http.Request {
		req, _ := http.NewRequest("GET", "/users/?"+query, nil)
		return req
	}

	DescribeTable("valid combinations",
		func(query string, wantLimit, wantOffset int) {
			limit, offset, err := pagination(makeReq(query))
			Expect(err).ToNot(HaveOccurred())
			Expect(limit).To(Equal(wantLimit))
			Expect(offset).To(Equal(wantOffset))
		},
		// defaults
		Entry("empty query uses defaults", "", 30, 0),
		// explicit limit
		Entry("limit=10", "limit=10", 10, 0),
		// limit capped at 100
		Entry("limit=999 is capped to 100", "limit=999", 100, 0),
		// explicit offset
		Entry("offset=5", "offset=5", 30, 5),
		// page-based
		Entry("page=1 means offset=0", "page=1&limit=10", 10, 0),
		Entry("page=2 means offset=10", "page=2&limit=10", 10, 10),
		Entry("page=3 means offset=20", "page=3&limit=10", 10, 20),
		// page=0 is treated as no page (offset stays 0)
		Entry("page=0 leaves offset=0", "page=0&limit=5", 5, 0),
	)

	DescribeTable("invalid inputs return error",
		func(query string) {
			_, _, err := pagination(makeReq(query))
			Expect(err).To(HaveOccurred())
		},
		Entry("non-integer limit", "limit=abc"),
		Entry("negative limit", "limit=-1"),
		Entry("non-integer offset", "offset=xyz"),
		Entry("negative offset", "offset=-5"),
		Entry("non-integer page", "page=bad"),
		Entry("negative page", "page=-2"),
	)
})

// ---------------------------------------------------------------------------
// requestLogger – covers the nil-request fallback branch
// ---------------------------------------------------------------------------

var _ = Describe("requestLogger", func() {
	It("returns base logger when request is nil", func() {
		logger, _ := testutils.SetupTestLogger()
		s := &Server{Logger: logger}
		l := s.requestLogger(nil)
		Expect(l).To(Equal(logger))
	})

	It("returns context logger when request has a logger in context", func() {
		logger, _ := testutils.SetupTestLogger()
		s := &Server{Logger: logger}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(ezlog.RequestContext(req.Context(), logger))
		l := s.requestLogger(req)
		Expect(l).NotTo(BeNil())
	})
})

// ---------------------------------------------------------------------------
// respondError – covers JSON vs HTML routing branches
// ---------------------------------------------------------------------------

var _ = Describe("respondError", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	It("writes JSON when JSONResponse is true", func() {
		rend, _, _ := eztmpl.New("", "")
		s := &Server{
			Logger:   logger,
			renderer: rend,
			ServeCfg: ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
			AuthCfg: ezcfg.AuthConfig{
				Proxy: ezcfg.AuthProxyConfig{JSONResponse: true},
			},
		}
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		s.respondError(rw, req, http.StatusForbidden, "Forbidden")
		Expect(rw.Header().Get("Content-Type")).To(Equal("application/json"))
		Expect(rw.Code).To(Equal(http.StatusForbidden))
	})

	It("renders HTML when JSONResponse is false and client wants HTML", func() {
		rend, _, _ := eztmpl.New("", "")
		store, err := sessions.NewSessionStore(&ezcfg.Session{
			Cookie: ezcfg.CookieStoreOptions{
				Name:   "_ez_proxy",
				Secret: ezcfg.NewResolvedSecretRef([]byte("test-secret-key32byteslong111!!!")),
			},
		})
		Expect(err).ToNot(HaveOccurred())
		s := &Server{
			Logger:       logger,
			renderer:     rend,
			ServeCfg:     ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
			sessionStore: store,
			AuthCfg:      ezcfg.AuthConfig{},
		}
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{})
		s.respondError(rw, req, http.StatusForbidden, "Forbidden")
		Expect(rw.Header().Get("Content-Type")).To(ContainSubstring("text/html"))
	})
})

// ---------------------------------------------------------------------------
// mockableDB wraps a DatabaseInterface and lets tests inject errors for
// UserLogin without touching the sqlmock internals.
// ---------------------------------------------------------------------------

type mockableDB struct {
	ezdb.DatabaseInterface
	userLoginErr error
}

func (m *mockableDB) UserLogin(_ context.Context, _, _ string) (*ezapi.Profile, error) {
	if m.userLoginErr != nil {
		return nil, m.userLoginErr
	}
	return &ezapi.Profile{User: "test", Subject: "test"}, nil
}

// ---------------------------------------------------------------------------
// mockDBListProviders injects ListProviders errors or results without sqlmock.
// ---------------------------------------------------------------------------

type mockDBListProviders struct {
	ezdb.DatabaseInterface
	result []*models.ProviderDB
	err    error
}

func (m *mockDBListProviders) ListProviders(_ context.Context, _, _ int) ([]*models.ProviderDB, error) {
	return m.result, m.err
}

// ---------------------------------------------------------------------------
// mockDBDeleteProvider injects DeleteProvider errors without sqlmock.
// ---------------------------------------------------------------------------

type mockDBDeleteProvider struct {
	ezdb.DatabaseInterface
	err error
}

func (m *mockDBDeleteProvider) DeleteProvider(_ context.Context, _ string) error {
	return m.err
}

// ---------------------------------------------------------------------------
// mockDBPAT provides controllable error injection for PAT and user operations.
// ---------------------------------------------------------------------------

type mockDBPAT struct {
	ezdb.DatabaseInterface
	listPATsErr       error
	createPATErr      error
	deletePATErr      error
	listUsersErr      error
	updateUserErr     error
	listGroupsErr     error
	addProviderErr    error
	updateProviderErr error
}

func (m *mockDBPAT) ListPATs(_ context.Context, _ string) ([]*models.PATDB, error) {
	return nil, m.listPATsErr
}

func (m *mockDBPAT) CreatePAT(_ context.Context, _ *models.PATDB) error {
	return m.createPATErr
}

func (m *mockDBPAT) DeletePAT(_ context.Context, _, _ string) error {
	return m.deletePATErr
}

func (m *mockDBPAT) ListUsers(_ context.Context, _, _ int) ([]*models.UserDB, error) {
	return nil, m.listUsersErr
}

func (m *mockDBPAT) UpdateUser(_ context.Context, _ *models.UserDB) error {
	return m.updateUserErr
}

func (m *mockDBPAT) ListGroups(_ context.Context, _, _ int) ([]*models.GroupDB, error) {
	return nil, m.listGroupsErr
}

func (m *mockDBPAT) AddProvider(_ context.Context, _ *models.ProviderDB) error {
	return m.addProviderErr
}

func (m *mockDBPAT) UpdateProvider(_ context.Context, _ *models.ProviderDB) error {
	return m.updateProviderErr
}
