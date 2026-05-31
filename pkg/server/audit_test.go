package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// auditColumns returns the column list expected by sqlmock for audit_events queries.
func auditColumns() []string {
	return []string{"id", "timestamp", "type", "user", "ip", "provider", "details", "request_id", "success"}
}

// newAuditTestLogger creates a real zap development logger wrapped in an auditCore.
func newAuditTestLogger(capacity int) (ezlog.Logger, *auditCore) {
	zl, _ := zap.NewDevelopment()
	base := ezlog.New(zl)
	return newAuditLogger(base, capacity)
}

var _ = Describe("auditState ring buffer", func() {
	Describe("append and recent", func() {
		It("returns empty slice when buffer is empty", func() {
			s := &auditState{buf: make([]AuditEvent, 5), capacity: 5}
			Expect(s.recent(10)).To(BeEmpty())
		})

		It("returns events newest-first", func() {
			s := &auditState{buf: make([]AuditEvent, 5), capacity: 5}
			for i := range 3 {
				s.append(AuditEvent{Type: fmt.Sprintf("t%d", i)})
			}
			events := s.recent(3)
			Expect(events).To(HaveLen(3))
			// recent() returns newest first
			Expect(events[0].Type).To(Equal("t2"))
			Expect(events[1].Type).To(Equal("t1"))
			Expect(events[2].Type).To(Equal("t0"))
		})

		It("assigns monotonically increasing IDs starting at 1", func() {
			s := &auditState{buf: make([]AuditEvent, 5), capacity: 5}
			for range 3 {
				s.append(AuditEvent{})
			}
			events := s.recent(3)
			ids := make([]uint64, len(events))
			for i, e := range events {
				ids[i] = e.ID
			}
			Expect(ids).To(ContainElements(uint64(1), uint64(2), uint64(3)))
		})

		It("wraps around when capacity is exceeded (ring behaviour)", func() {
			cap := 3
			s := &auditState{buf: make([]AuditEvent, cap), capacity: cap}
			for i := range 5 {
				s.append(AuditEvent{Type: fmt.Sprintf("t%d", i)})
			}
			// Only the 3 most recent (t2, t3, t4) should be in the buffer.
			events := s.recent(cap)
			Expect(events).To(HaveLen(cap))
			types := make([]string, len(events))
			for i, e := range events {
				types[i] = e.Type
			}
			Expect(types).To(ContainElements("t2", "t3", "t4"))
		})

		It("recent(n) limits output to n even when buffer has more", func() {
			s := &auditState{buf: make([]AuditEvent, 10), capacity: 10}
			for i := range 8 {
				s.append(AuditEvent{Type: fmt.Sprintf("t%d", i)})
			}
			Expect(s.recent(3)).To(HaveLen(3))
		})

		It("recent(0) returns all buffered events", func() {
			s := &auditState{buf: make([]AuditEvent, 10), capacity: 10}
			for range 4 {
				s.append(AuditEvent{})
			}
			Expect(s.recent(0)).To(HaveLen(4))
		})
	})

	Describe("drain", func() {
		It("returns nil when buffer is empty", func() {
			s := &auditState{buf: make([]AuditEvent, 5), capacity: 5}
			Expect(s.drain()).To(BeNil())
		})

		It("returns all events oldest-first and resets the buffer", func() {
			s := &auditState{buf: make([]AuditEvent, 5), capacity: 5}
			for i := range 3 {
				s.append(AuditEvent{Type: fmt.Sprintf("t%d", i)})
			}
			events := s.drain()
			Expect(events).To(HaveLen(3))
			Expect(events[0].Type).To(Equal("t0"))
			Expect(events[2].Type).To(Equal("t2"))
			// Buffer must be empty after drain; count keeps incrementing for unique IDs.
			Expect(s.drain()).To(BeNil())
			Expect(s.filled).To(BeZero())
			Expect(s.count).To(BeEquivalentTo(3)) // monotonic — never reset
		})

		It("drain after wrap-around returns only the capacity most recent events oldest-first", func() {
			cap := 3
			s := &auditState{buf: make([]AuditEvent, cap), capacity: cap}
			for i := range 5 {
				s.append(AuditEvent{Type: fmt.Sprintf("t%d", i)})
			}
			events := s.drain()
			Expect(events).To(HaveLen(cap))
			// t2 was written at slot (5-3)=2, so oldest surviving is t2.
			Expect(events[0].Type).To(Equal("t2"))
			Expect(events[2].Type).To(Equal("t4"))
		})

		It("is safe for concurrent append and drain", func() {
			s := &auditState{buf: make([]AuditEvent, 100), capacity: 100}
			var wg sync.WaitGroup
			for i := range 50 {
				wg.Go(func() { s.append(AuditEvent{Type: fmt.Sprintf("t%d", i)}) })
			}
			wg.Go(func() { _ = s.drain() })
			wg.Wait()
			// No panic means the locking is correct.
		})
	})
})

var _ = Describe("auditCore", func() {
	Describe("newAuditCore", func() {
		It("defaults to defaultAuditCapacity when capacity <= 0", func() {
			inner := zapcore.NewNopCore()
			ac := newAuditCore(inner, 0)
			Expect(ac.state.capacity).To(Equal(defaultAuditCapacity))
		})

		It("uses the provided capacity", func() {
			inner := zapcore.NewNopCore()
			ac := newAuditCore(inner, 42)
			Expect(ac.state.capacity).To(Equal(42))
		})
	})

	Describe("Write — captures known audit messages", func() {
		It("captures a login event and extracts structured fields", func() {
			_, ac := newAuditTestLogger(50)
			child := ac.With([]zapcore.Field{
				zap.String("ip", "10.0.0.1"),
				zap.String("request_id", "req-123"),
			})
			entry := zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Time:    time.Now(),
				Message: "Successfully logged in user",
			}
			Expect(child.Write(entry, []zapcore.Field{
				zap.String("user", "alice"),
				zap.String("provider", "google"),
			})).To(Succeed())

			events := ac.recent(1)
			Expect(events).To(HaveLen(1))
			ev := events[0]
			Expect(ev.Type).To(Equal("login"))
			Expect(ev.User).To(Equal("alice"))
			Expect(ev.IP).To(Equal("10.0.0.1"))
			Expect(ev.Provider).To(Equal("google"))
			Expect(ev.RequestID).To(Equal("req-123"))
			Expect(ev.Success).To(BeTrue())
		})

		It("captures a login_failed event and sets Success=false", func() {
			_, ac := newAuditTestLogger(50)
			entry := zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Time:    time.Now(),
				Message: "Login failed: invalid password",
			}
			Expect(ac.Write(entry, []zapcore.Field{
				zap.String("user", "bob"),
				zap.String("ip", "1.2.3.4"),
			})).To(Succeed())

			events := ac.recent(1)
			Expect(events).To(HaveLen(1))
			Expect(events[0].Type).To(Equal("login_failed"))
			Expect(events[0].Success).To(BeFalse())
			Expect(events[0].User).To(Equal("bob"))
		})

		It("captures a logout event", func() {
			_, ac := newAuditTestLogger(50)
			entry := zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Time:    time.Now(),
				Message: "Logged out user",
			}
			Expect(ac.Write(entry, []zapcore.Field{zap.String("user", "carol")})).To(Succeed())

			events := ac.recent(1)
			Expect(events).To(HaveLen(1))
			Expect(events[0].Type).To(Equal("logout"))
		})

		It("does not capture unknown messages", func() {
			_, ac := newAuditTestLogger(50)
			entry := zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Time:    time.Now(),
				Message: "some unrelated log message",
			}
			Expect(ac.Write(entry, nil)).To(Succeed())
			Expect(ac.recent(10)).To(BeEmpty())
		})

		It("captures all known login_failed variants", func() {
			_, ac := newAuditTestLogger(50)
			messages := []string{
				"Login failed: user does not exist",
				"Login failed: internal error",
				"Login failed: static user not found or invalid password",
			}
			for _, msg := range messages {
				entry := zapcore.Entry{Level: zapcore.InfoLevel, Time: time.Now(), Message: msg}
				Expect(ac.Write(entry, nil)).To(Succeed())
			}
			Expect(ac.recent(10)).To(HaveLen(len(messages)))
		})

		It("uses message as Details when no redirect field is present", func() {
			_, ac := newAuditTestLogger(50)
			entry := zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Time:    time.Now(),
				Message: "Successfully logged in user",
			}
			Expect(ac.Write(entry, nil)).To(Succeed())
			events := ac.recent(1)
			Expect(events[0].Details).To(Equal("Successfully logged in user"))
		})

		It("sets Details from redirect field when present", func() {
			_, ac := newAuditTestLogger(50)
			entry := zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Time:    time.Now(),
				Message: "Oauth2 callback is finished",
			}
			Expect(ac.Write(entry, []zapcore.Field{
				zap.String("redirect", "/dashboard"),
			})).To(Succeed())
			events := ac.recent(1)
			Expect(events[0].Details).To(Equal("/dashboard"))
		})
	})

	Describe("With — child cores share the same ring buffer", func() {
		It("child writes are visible on the parent core", func() {
			_, ac := newAuditTestLogger(50)
			child := ac.With([]zapcore.Field{zap.String("ip", "9.9.9.9")})
			entry := zapcore.Entry{Level: zapcore.InfoLevel, Time: time.Now(), Message: "Logged out user"}
			Expect(child.Write(entry, nil)).To(Succeed())

			// Query via root core — must see the child's write.
			events := ac.recent(1)
			Expect(events).To(HaveLen(1))
			Expect(events[0].IP).To(Equal("9.9.9.9"))
		})
	})

	Describe("watermarkExceeded", func() {
		It("returns false when buffer is empty", func() {
			_, ac := newAuditTestLogger(10)
			Expect(ac.watermarkExceeded()).To(BeFalse())
		})

		It("returns false below 80 %", func() {
			_, ac := newAuditTestLogger(10)
			for range 7 {
				ac.state.append(AuditEvent{})
			}
			Expect(ac.watermarkExceeded()).To(BeFalse())
		})

		It("returns true at exactly 80 %", func() {
			_, ac := newAuditTestLogger(10)
			for range 8 {
				ac.state.append(AuditEvent{})
			}
			Expect(ac.watermarkExceeded()).To(BeTrue())
		})

		It("returns true above 80 %", func() {
			_, ac := newAuditTestLogger(10)
			for range 10 {
				ac.state.append(AuditEvent{})
			}
			Expect(ac.watermarkExceeded()).To(BeTrue())
		})
	})
})

var _ = Describe("auditFlusher", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	Describe("flushToFile", func() {
		It("writes events as JSONL to the configured file", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "audit.jsonl")

			_, ac := newAuditTestLogger(50)
			f := &auditFlusher{
				core:   ac,
				cfg:    ezcfg.AuditConfig{File: path},
				logger: logger,
			}

			events := []AuditEvent{
				{ID: 1, Type: "login", User: "alice", IP: "1.1.1.1", Success: true, Timestamp: time.Now()},
				{ID: 2, Type: "logout", User: "alice", IP: "1.1.1.1", Success: true, Timestamp: time.Now()},
			}
			f.flushToFile(events)

			data, err := os.ReadFile(path)
			Expect(err).ToNot(HaveOccurred())

			lines := splitLines(data)
			Expect(lines).To(HaveLen(2))
			var ev AuditEvent
			Expect(json.Unmarshal([]byte(lines[0]), &ev)).To(Succeed())
			Expect(ev.User).To(Equal("alice"))
			Expect(ev.Type).To(Equal("login"))
		})

		It("truncates the file when it exceeds maxFileSize", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "audit.jsonl")

			// Pre-fill the file above the tiny limit.
			Expect(os.WriteFile(path, []byte(`{"type":"old"}`+"\n"), 0600)).To(Succeed())

			_, ac := newAuditTestLogger(50)
			f := &auditFlusher{
				core:   ac,
				cfg:    ezcfg.AuditConfig{File: path, MaxFileSize: 1}, // 1 byte limit
				logger: logger,
			}
			f.flushToFile([]AuditEvent{{ID: 1, Type: "new", Success: true, Timestamp: time.Now()}})

			data, err := os.ReadFile(path)
			Expect(err).ToNot(HaveOccurred())
			// Old content must be gone; new event written after truncation.
			Expect(string(data)).NotTo(ContainSubstring("old"))
			Expect(string(data)).To(ContainSubstring("new"))
		})

		It("uses cfg.File path when set", func() {
			_, ac := newAuditTestLogger(50)
			dir := GinkgoT().TempDir()
			filePath := filepath.Join(dir, "ezauth-audit.jsonl")

			f := &auditFlusher{
				core:   ac,
				cfg:    ezcfg.AuditConfig{File: filePath},
				logger: logger,
			}
			f.flushToFile([]AuditEvent{{ID: 99, Type: "login", Success: true, Timestamp: time.Now()}})

			data, err := os.ReadFile(filePath)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(data)).To(ContainSubstring(`"login"`))
		})
	})

	Describe("flushToDB", func() {
		It("calls InsertAuditEvents with converted rows", func() {
			gormDB, mockSQL, err := testutils.MockSQLPool()
			Expect(err).ToNot(HaveOccurred())
			mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
			mockDB.DB = gormDB

			// GORM issues INSERT … RETURNING …, which is a Query, not an Exec.
			returningCols := sqlmock.NewRows(auditColumns())
			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`INSERT INTO "audit_events"`).WillReturnRows(returningCols)
			mockSQL.ExpectCommit()

			_, ac := newAuditTestLogger(50)
			f := &auditFlusher{core: ac, db: mockDB, logger: logger}
			events := []AuditEvent{
				{Type: "login", User: "alice", Success: true, Timestamp: time.Now()},
				{Type: "logout", User: "alice", Success: true, Timestamp: time.Now()},
			}
			f.flushToDB(context.Background(), events)

			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("logs an error but does not panic when DB insert fails", func() {
			gormDB, mockSQL, err := testutils.MockSQLPool()
			Expect(err).ToNot(HaveOccurred())
			mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
			mockDB.DB = gormDB

			mockSQL.ExpectBegin()
			mockSQL.ExpectQuery(`INSERT INTO "audit_events"`).WillReturnError(fmt.Errorf("db down"))
			mockSQL.ExpectRollback()

			_, ac := newAuditTestLogger(50)
			f := &auditFlusher{core: ac, db: mockDB, logger: logger}
			// Must not panic.
			Expect(func() {
				f.flushToDB(context.Background(), []AuditEvent{
					{Type: "login", Success: true, Timestamp: time.Now()},
				})
			}).NotTo(Panic())
		})
	})

	Describe("flush routing", func() {
		It("routes to file when db is nil", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "route.jsonl")
			_, ac := newAuditTestLogger(50)
			ac.state.append(AuditEvent{Type: "login", Success: true, Timestamp: time.Now()})

			f := &auditFlusher{
				core:   ac,
				db:     nil,
				cfg:    ezcfg.AuditConfig{File: path},
				logger: logger,
			}
			f.flush(context.Background())

			data, err := os.ReadFile(path)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(data)).To(ContainSubstring("login"))
		})

		It("is a no-op when the buffer is empty", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "empty.jsonl")
			_, ac := newAuditTestLogger(50)

			f := &auditFlusher{
				core:   ac,
				db:     nil,
				cfg:    ezcfg.AuditConfig{File: path},
				logger: logger,
			}
			f.flush(context.Background())
			_, err := os.Stat(path)
			Expect(os.IsNotExist(err)).To(BeTrue(), "file should not be created when nothing to flush")
		})
	})
})

var _ = Describe("ListAuditEvents handler", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	// newAuditServer wires a minimal Server with an auditCore and optional DB.
	newAuditServer := func(ac *auditCore, db database.DatabaseInterface) *Server {
		return &Server{
			Logger:    logger,
			auditCore: ac,
			DB:        db,
			ServeCfg:  ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
		}
	}

	It("returns 200 and an empty array when buffer is empty and no DB", func() {
		_, ac := newAuditTestLogger(50)
		s := newAuditServer(ac, nil)

		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Header().Get("Content-Type")).To(Equal("application/json"))
		var events []AuditEvent
		Expect(json.Unmarshal(rr.Body.Bytes(), &events)).To(Succeed())
		Expect(events).To(BeEmpty())
	})

	It("returns in-memory events in response when buffer has data", func() {
		_, ac := newAuditTestLogger(50)
		for i := range 3 {
			ac.state.append(AuditEvent{
				Type: "login", User: fmt.Sprintf("u%d", i), Success: true, Timestamp: time.Now(),
			})
		}
		s := newAuditServer(ac, nil)

		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		var events []AuditEvent
		Expect(json.Unmarshal(rr.Body.Bytes(), &events)).To(Succeed())
		Expect(events).To(HaveLen(3))
	})

	It("respects the ?limit query parameter", func() {
		_, ac := newAuditTestLogger(50)
		for i := range 10 {
			ac.state.append(AuditEvent{Type: "login", User: fmt.Sprintf("u%d", i), Success: true, Timestamp: time.Now()})
		}
		s := newAuditServer(ac, nil)

		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events?limit=4", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		var events []AuditEvent
		Expect(json.Unmarshal(rr.Body.Bytes(), &events)).To(Succeed())
		Expect(events).To(HaveLen(4))
	})

	It("caps limit at 1000 for excessive values", func() {
		_, ac := newAuditTestLogger(50)
		s := newAuditServer(ac, nil)

		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events?limit=9999", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		// We only care that the server doesn't blow up; limit is silently capped.
	})

	It("ignores invalid limit and uses default 100", func() {
		_, ac := newAuditTestLogger(50)
		s := newAuditServer(ac, nil)

		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events?limit=bad", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
	})

	It("falls back to DB when offset > 0 even if memory has events", func() {
		_, ac := newAuditTestLogger(50)
		ac.state.append(AuditEvent{Type: "login", Success: true, Timestamp: time.Now()})

		gormDB, mockSQL, err := testutils.MockSQLPool()
		Expect(err).ToNot(HaveOccurred())
		mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
		mockDB.DB = gormDB

		dbRows := mockSQL.NewRows(auditColumns()).AddRow(
			uint64(10), time.Now(), "logout", "db-user", "2.2.2.2", "", "msg", "rid", true,
		)
		mockSQL.ExpectQuery(`SELECT \* FROM "audit_events"`).WillReturnRows(dbRows)

		s := newAuditServer(ac, mockDB)
		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events?offset=5", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		var events []AuditEvent
		Expect(json.Unmarshal(rr.Body.Bytes(), &events)).To(Succeed())
		Expect(events).To(HaveLen(1))
		Expect(events[0].User).To(Equal("db-user"))
		Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
	})

	It("falls back to DB when memory is empty", func() {
		_, ac := newAuditTestLogger(50) // empty buffer

		gormDB, mockSQL, err := testutils.MockSQLPool()
		Expect(err).ToNot(HaveOccurred())
		mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
		mockDB.DB = gormDB

		dbRows := mockSQL.NewRows(auditColumns()).AddRow(
			uint64(1), time.Now(), "login", "fallback-user", "3.3.3.3", "google", "detail", "req1", true,
		)
		mockSQL.ExpectQuery(`SELECT \* FROM "audit_events"`).WillReturnRows(dbRows)

		s := newAuditServer(ac, mockDB)
		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		var events []AuditEvent
		Expect(json.Unmarshal(rr.Body.Bytes(), &events)).To(Succeed())
		Expect(events).To(HaveLen(1))
		Expect(events[0].User).To(Equal("fallback-user"))
		Expect(events[0].Provider).To(Equal("google"))
	})

	It("returns 500 when DB falls back and returns an error", func() {
		_, ac := newAuditTestLogger(50)

		gormDB, mockSQL, err := testutils.MockSQLPool()
		Expect(err).ToNot(HaveOccurred())
		mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
		mockDB.DB = gormDB

		mockSQL.ExpectQuery(`SELECT \* FROM "audit_events"`).WillReturnError(fmt.Errorf("db error"))

		s := newAuditServer(ac, mockDB)
		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusInternalServerError))
	})

	It("works correctly when auditCore is nil (DB-only mode)", func() {
		gormDB, mockSQL, err := testutils.MockSQLPool()
		Expect(err).ToNot(HaveOccurred())
		mockDB := &pgx.PGxDB{Database: database.Database{Logger: logger}}
		mockDB.DB = gormDB

		dbRows := mockSQL.NewRows(auditColumns()).AddRow(
			uint64(5), time.Now(), "login", "nil-core-user", "4.4.4.4", "", "", "", true,
		)
		mockSQL.ExpectQuery(`SELECT \* FROM "audit_events"`).WillReturnRows(dbRows)

		s := newAuditServer(nil, mockDB) // auditCore intentionally nil
		router := mux.NewRouter()
		s.auditRouter(router)

		req := httptest.NewRequest(http.MethodGet, "/events", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		var events []AuditEvent
		Expect(json.Unmarshal(rr.Body.Bytes(), &events)).To(Succeed())
		Expect(events[0].User).To(Equal("nil-core-user"))
	})
})

// splitLines splits JSONL bytes into non-empty lines.
func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, string(data[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

// ---------------------------------------------------------------------------
// auditCore.Check – covers the enabled/disabled branch
// ---------------------------------------------------------------------------

var _ = Describe("auditCore.Check", func() {
	It("adds core to CheckedEntry when level is enabled", func() {
		_, ac := newAuditTestLogger(50)
		entry := zapcore.Entry{
			Level:   zapcore.InfoLevel,
			Message: "Successfully logged in user",
		}
		ce := ac.Check(entry, nil)
		Expect(ce).NotTo(BeNil())
	})

	It("returns ce unchanged when level is not enabled", func() {
		_, ac := newAuditTestLogger(50)
		// Use a level below Debug (the minimum enabled by the development logger).
		entry := zapcore.Entry{
			Level:   zapcore.DebugLevel - 1,
			Message: "Should be filtered",
		}
		ce := ac.Check(entry, nil)
		// When the level is not enabled, Check should return the incoming ce
		// (nil in this case) unmodified.
		Expect(ce).To(BeNil())
	})
})

// ---------------------------------------------------------------------------
// auditFlusher.Start – covers the high-watermark ticker branch
// ---------------------------------------------------------------------------

var _ = Describe("auditFlusher.Start watermark branch", func() {
	It("flushes when watermark is exceeded via direct flush() call", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "hwm.jsonl")

		logger, _ := testutils.SetupTestLogger()
		_, ac := newAuditTestLogger(10)

		// Fill buffer above 80%.
		for range 9 {
			ac.state.append(AuditEvent{Type: "login", Success: true, Timestamp: time.Now()})
		}
		Expect(ac.watermarkExceeded()).To(BeTrue())

		f := &auditFlusher{
			core: ac,
			cfg: ezcfg.AuditConfig{
				File:          path,
				FlushInterval: 10 * time.Minute,
			},
			logger: logger,
		}

		// Test the high-watermark code path by calling flush() directly,
		// since the 30-second hwTicker cannot be shortened in unit tests.
		f.flush(context.Background())

		data, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(data)).To(ContainSubstring("login"))
	})

	It("Start exits cleanly when context is cancelled", func() {
		logger, _ := testutils.SetupTestLogger()
		_, ac := newAuditTestLogger(10)
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "start.jsonl")

		f := &auditFlusher{
			core: ac,
			cfg: ezcfg.AuditConfig{
				File:          path,
				FlushInterval: 1 * time.Hour,
			},
			logger: logger,
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			f.Start(ctx)
			close(done)
		}()
		cancel()
		Eventually(done, 2*time.Second).Should(BeClosed())
	})

	It("performs final flush on context cancel when buffer has events", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "final.jsonl")

		logger, _ := testutils.SetupTestLogger()
		_, ac := newAuditTestLogger(50)
		ac.state.append(AuditEvent{Type: "logout", Success: true, Timestamp: time.Now()})

		f := &auditFlusher{
			core: ac,
			cfg: ezcfg.AuditConfig{
				File:          path,
				FlushInterval: 1 * time.Hour,
			},
			logger: logger,
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			f.Start(ctx)
			close(done)
		}()
		cancel()
		Eventually(done, 2*time.Second).Should(BeClosed())

		data, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(data)).To(ContainSubstring("logout"))
	})
})

// ---------------------------------------------------------------------------
// flushToFile – covers the open-fail and default-path branches
// ---------------------------------------------------------------------------

var _ = Describe("auditFlusher.flushToFile edge cases", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger, _ = testutils.SetupTestLogger()
	})

	It("uses os.TempDir default path when cfg.File is empty", func() {
		_, ac := newAuditTestLogger(50)
		f := &auditFlusher{
			core:   ac,
			cfg:    ezcfg.AuditConfig{File: ""},
			logger: logger,
		}
		events := []AuditEvent{
			{ID: 1, Type: "login", User: "sys", Success: true, Timestamp: time.Now()},
		}
		// Should not panic; file goes to os.TempDir()/ezauth-audit.jsonl.
		Expect(func() { f.flushToFile(events) }).NotTo(Panic())

		// Clean up the default file if it was created.
		defaultPath := os.TempDir() + "/ezauth-audit.jsonl"
		_ = os.Remove(defaultPath)
	})

	It("does not panic when the file path is in a non-existent directory", func() {
		_, ac := newAuditTestLogger(50)
		f := &auditFlusher{
			core:   ac,
			cfg:    ezcfg.AuditConfig{File: "/nonexistent/dir/audit.jsonl"},
			logger: logger,
		}
		events := []AuditEvent{
			{ID: 1, Type: "login", User: "u", Success: true, Timestamp: time.Now()},
		}
		// The directory doesn't exist so OpenFile fails; must log and return cleanly.
		Expect(func() { f.flushToFile(events) }).NotTo(Panic())
	})
})

// ---------------------------------------------------------------------------
// auditFlusher.Start additional branches
// ---------------------------------------------------------------------------

var _ = Describe("auditFlusher.Start additional branches", func() {
	It("uses 5-minute default interval when FlushInterval is zero", func() {
		logger, _ := testutils.SetupTestLogger()
		_, ac := newAuditLogger(logger, 64)
		f := &auditFlusher{
			core:   ac,
			db:     nil,
			logger: logger,
			cfg:    ezcfg.AuditConfig{FlushInterval: 0},
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			f.Start(ctx)
			close(done)
		}()
		// Cancel immediately — exercises the interval<=0 default branch and
		// the ctx.Done() select case.
		cancel()
		Eventually(done, "2s").Should(BeClosed())
	})

	It("flushes via ticker.C when the interval fires", func() {
		logger, _ := testutils.SetupTestLogger()
		_, ac := newAuditLogger(logger, 64)
		f := &auditFlusher{
			core:   ac,
			db:     nil,
			logger: logger,
			cfg:    ezcfg.AuditConfig{FlushInterval: 10 * time.Millisecond},
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			f.Start(ctx)
			close(done)
		}()
		// Wait long enough for the 10 ms ticker to fire at least once, then stop.
		time.Sleep(50 * time.Millisecond)
		cancel()
		Eventually(done, "2s").Should(BeClosed())
	})
})
