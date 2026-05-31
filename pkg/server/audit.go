package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"

	ezlog "github.com/flipcloud-ai/ezauth/log"
)

const (
	defaultAuditCapacity = 500
	auditPath            = "/audit"
)

// auditMessages maps known log messages to their audit event type.
// Entries here are captured into the in-memory ring buffer.
var auditMessages = map[string]string{
	"Successfully logged in user":                             "login",
	"Successfully authenticated user in auth-only mode":       "login",
	"Oauth2 callback is finished":                             "login",
	"Oauth2 callback finished in auth-only mode":              "login",
	"Login failed: user does not exist":                       "login_failed",
	"Login failed: invalid password":                          "login_failed",
	"Login failed: internal error":                            "login_failed",
	"Login failed: static user not found or invalid password": "login_failed",
	"Logged out user":                                         "logout",
}

// AuditEvent is a single entry in the in-memory audit ring buffer.
type AuditEvent struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	User      string    `json:"user"`
	IP        string    `json:"ip"`
	Provider  string    `json:"provider,omitempty"`
	Details   string    `json:"details,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Success   bool      `json:"success"`
}

// auditState is the shared ring buffer accessed by all auditCore instances
// (root and every With() child). Using a pointer ensures that writes from
// child cores (created by RequestLogger middleware) are visible when
// recent() is queried on the root core stored in Server.
type auditState struct {
	mu       sync.RWMutex
	buf      []AuditEvent
	head     int
	count    uint64 // monotonically increasing; never reset, used as event ID
	filled   uint64 // events written since last drain; reset to 0 on drain
	capacity int
}

func (s *auditState) append(ev AuditEvent) {
	s.mu.Lock()
	s.count++
	s.filled++
	ev.ID = s.count
	s.buf[s.head] = ev
	s.head = (s.head + 1) % s.capacity
	s.mu.Unlock()
}

func (s *auditState) recent(n int) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	filled := s.capacity
	if uint64(s.capacity) > s.filled { //nolint:gosec // capacity is a positive int set at construction time
		filled = int(s.filled) //nolint:gosec // filled < capacity (int), so conversion is safe
	}
	if n <= 0 || n > filled {
		n = filled
	}
	out := make([]AuditEvent, 0, n)
	pos := (s.head - 1 + s.capacity) % s.capacity
	for i := 0; i < n; i++ {
		out = append(out, s.buf[pos])
		pos = (pos - 1 + s.capacity) % s.capacity
	}
	return out
}

// drain atomically removes all currently buffered events and returns them
// oldest-first. Called by the flush goroutine.
func (s *auditState) drain() []AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	filled := s.capacity
	if uint64(s.capacity) > s.filled { //nolint:gosec // capacity is a positive int set at construction time
		filled = int(s.filled) //nolint:gosec // filled < capacity (int), so conversion is safe
	}
	if filled == 0 {
		return nil
	}
	out := make([]AuditEvent, filled)
	// head points to the next write slot; oldest entry is at (head - filled).
	start := (s.head - filled + s.capacity) % s.capacity
	for i := 0; i < filled; i++ {
		out[i] = s.buf[(start+i)%s.capacity]
	}
	// Reset only the ring-buffer position; count is never reset so event IDs
	// remain monotonically increasing across flushes.
	s.head = 0
	s.filled = 0
	return out
}

// auditCore wraps a zapcore.Core and captures log entries whose message
// matches a known audit event type. All other entries pass through unchanged.
// Context fields accumulated via With() (e.g. user, ip injected by middleware)
// are available when Write() fires.
type auditCore struct {
	zapcore.Core
	ctx   []zapcore.Field // fields accumulated by With() calls
	state *auditState     // shared across root and all With() children
}

func newAuditCore(inner zapcore.Core, capacity int) *auditCore {
	if capacity <= 0 {
		capacity = defaultAuditCapacity
	}
	return &auditCore{
		Core:  inner,
		state: &auditState{buf: make([]AuditEvent, capacity), capacity: capacity},
	}
}

// With accumulates context fields (e.g. ip, user from request logger) and
// returns a child core sharing the same ring buffer.
func (c *auditCore) With(fields []zapcore.Field) zapcore.Core {
	return &auditCore{
		Core:  c.Core.With(fields),
		ctx:   append(append([]zapcore.Field(nil), c.ctx...), fields...),
		state: c.state, // shared — writes from any child update the same buffer
	}
}

func (c *auditCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

// Write delegates to the inner core for normal logging, then — if the message
// matches a known audit event — extracts structured fields and appends an AuditEvent.
func (c *auditCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if err := c.Core.Write(entry, fields); err != nil {
		return fmt.Errorf("audit core write: %w", err)
	}

	evType, known := auditMessages[entry.Message]
	if !known {
		return nil
	}

	// Merge context fields (ip, request_id, …) + call-site fields (user, …).
	all := append(append([]zapcore.Field(nil), c.ctx...), fields...)
	ev := AuditEvent{
		Timestamp: entry.Time,
		Type:      evType,
		Success:   evType != "login_failed",
	}
	for _, f := range all {
		switch f.Key {
		case "user":
			ev.User = f.String
		case "ip":
			ev.IP = f.String
		case "provider":
			ev.Provider = f.String
		case "redirect":
			ev.Details = f.String
		case "request_id":
			ev.RequestID = f.String
		}
	}
	if ev.Details == "" {
		ev.Details = entry.Message
	}
	c.state.append(ev)
	return nil
}

// recent returns up to n events in reverse-chronological order (newest first).
func (c *auditCore) recent(n int) []AuditEvent { return c.state.recent(n) }

// drain removes and returns all buffered events oldest-first.
func (c *auditCore) drain() []AuditEvent { return c.state.drain() }

// watermarkExceeded reports whether the buffer is at or above 80 % capacity.
func (c *auditCore) watermarkExceeded() bool {
	c.state.mu.RLock()
	count := c.state.count
	cap := c.state.capacity
	c.state.mu.RUnlock()
	filled := uint64(cap) //nolint:gosec // capacity is a positive int set at construction time
	if count < filled {
		filled = count
	}
	return int(filled)*10 >= cap*8 //nolint:gosec // filled <= cap (int), so conversion is safe
}

// newAuditLogger wraps the given Logger's core with an auditCore so that
// matching log entries are captured in-memory. The returned Logger replaces
// s.Logger; the auditCore is stored on Server for the API handler.
func newAuditLogger(logger ezlog.Logger, capacity int) (ezlog.Logger, *auditCore) {
	inner := logger.Zap().Core()
	ac := newAuditCore(inner, capacity)
	wrapped := logger.Zap().WithOptions(zap.WrapCore(func(_ zapcore.Core) zapcore.Core {
		return ac
	}))
	return ezlog.New(wrapped), ac
}

// auditFlusher periodically drains the ring buffer and writes events to DB or file.
type auditFlusher struct {
	core   *auditCore
	db     ezdb.DatabaseInterface
	cfg    ezcfg.AuditConfig
	logger ezlog.Logger
}

// Start launches the flush loop. It blocks until ctx is cancelled, then
// performs a final flush before returning.
func (f *auditFlusher) Start(ctx context.Context) {
	interval := f.cfg.FlushInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// High-watermark check every 30 s so the buffer never stays above 80 %
	// between regular ticks when traffic is high.
	hwTicker := time.NewTicker(30 * time.Second)
	defer hwTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			f.flush(context.WithoutCancel(ctx))
			return
		case <-ticker.C:
			f.flush(ctx)
		case <-hwTicker.C:
			if f.core.watermarkExceeded() {
				f.flush(ctx)
			}
		}
	}
}

func (f *auditFlusher) flush(ctx context.Context) {
	events := f.core.drain()
	if len(events) == 0 {
		return
	}
	if f.db != nil {
		f.flushToDB(ctx, events)
	} else {
		f.flushToFile(events)
	}
}

func (f *auditFlusher) flushToDB(ctx context.Context, events []AuditEvent) {
	rows := make([]*models.AuditEventDB, len(events))
	for i, e := range events {
		rows[i] = &models.AuditEventDB{
			Timestamp: e.Timestamp,
			Type:      e.Type,
			User:      e.User,
			IP:        e.IP,
			Provider:  e.Provider,
			Details:   e.Details,
			RequestID: e.RequestID,
			Success:   e.Success,
		}
	}
	if err := f.db.InsertAuditEvents(ctx, rows); err != nil {
		f.logger.Error("audit flush to db failed", ezlog.Err(err))
	}
}

func (f *auditFlusher) flushToFile(events []AuditEvent) {
	path := f.cfg.File
	if path == "" {
		path = os.TempDir() + "/ezauth-audit.jsonl"
	}

	maxSize := f.cfg.MaxFileSize
	if maxSize <= 0 {
		maxSize = 100 << 20 // 100 MiB
	}
	// Warn and truncate when the file would exceed the configured limit.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= maxSize {
		f.logger.Warn("audit log file reached size limit; truncating",
			ezlog.Str("file", path),
			ezlog.Float64("limit_mib", float64(maxSize)/(1<<20)))
		if err := os.Truncate(path, 0); err != nil {
			f.logger.Error("failed to truncate audit log file", ezlog.Str("file", path), ezlog.Err(err))
			return
		}
	}

	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) //nolint:gosec // path comes from administrator config
	if err != nil {
		f.logger.Error("failed to open audit log file", ezlog.Str("file", path), ezlog.Err(err))
		return
	}
	defer func() {
		if closeErr := fh.Close(); closeErr != nil {
			f.logger.Error("failed to close audit log file", ezlog.Str("file", path), ezlog.Err(closeErr))
		}
	}()

	w := bufio.NewWriter(fh)
	enc := json.NewEncoder(w)
	for _, e := range events {
		if encErr := enc.Encode(e); encErr != nil {
			f.logger.Error("failed to write audit event to file", ezlog.Err(encErr))
		}
	}
	if flushErr := w.Flush(); flushErr != nil {
		f.logger.Error("failed to flush audit log file", ezlog.Str("file", path), ezlog.Err(flushErr))
	}
}

// ListAuditEvents handles GET /ezauth/portal/audit-events?limit=N&offset=N
// Returns in-memory events; falls back to DB when offset > 0 or memory is empty.
func (s *Server) ListAuditEvents(rw http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	const maxLimit = 1000
	if limit > maxLimit {
		limit = maxLimit
	}

	var events []AuditEvent

	if offset == 0 && s.auditCore != nil {
		events = s.auditCore.recent(limit)
	}

	// Fall back to DB when in-memory has no results or client is paginating.
	if len(events) == 0 && s.DB != nil {
		dbEvents, err := s.DB.ListAuditEventsDB(r.Context(), limit, offset)
		if err != nil {
			s.writeJSONError(rw, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		events = make([]AuditEvent, len(dbEvents))
		for i, e := range dbEvents {
			events[i] = AuditEvent{
				ID:        e.ID,
				Timestamp: e.Timestamp,
				Type:      e.Type,
				User:      e.User,
				IP:        e.IP,
				Provider:  e.Provider,
				Details:   e.Details,
				RequestID: e.RequestID,
				Success:   e.Success,
			}
		}
	}

	if events == nil {
		events = []AuditEvent{}
	}

	b, err := json.Marshal(events)
	if err != nil {
		s.writeJSONError(rw, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(b)
}

func (s *Server) auditRouter(r *mux.Router) {
	r.Path("/events").Methods("GET").HandlerFunc(s.ListAuditEvents).Name("admin::audit::list")
}
