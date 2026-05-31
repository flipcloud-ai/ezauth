package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	ezmetrics "github.com/flipcloud-ai/ezauth/pkg/metrics"
)

// Gate is the session-presence middleware that guards every route behind the
// session chain. It rejects requests with no session or an expired session
// before they reach any handler that assumes a valid session exists.
// PAT Bearer tokens are resolved by LoadSession before Gate runs, so by the
// time Gate is called the session is already populated regardless of auth method.
func (s *Server) Gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session := ezapi.GetRequest(req).Session
		if session == nil {
			ezmetrics.AuthzDenyTotal.WithLabelValues("gate", "no_session").Inc()
			s.respondUnauthorized(rw, req)
			return
		}
		if session.IsExpired() {
			ezmetrics.AuthzDenyTotal.WithLabelValues("gate", "session_expired").Inc()
			s.requestLogger(req).Debug("session expired", ezlog.Time("expires_on", time.Unix(session.ExpiresOn, 0)))
			s.respondUnauthorized(rw, req)
			return
		}
		ezmetrics.AuthzAllowTotal.WithLabelValues("gate").Inc()
		next.ServeHTTP(rw, req)
	})
}

// AdminGate is the admin-route authorisation middleware. It is independent of
// the RBAC controller and applies whenever a request reaches an admin route,
// regardless of whether rbac.enabled is true.
//
// By the time AdminGate runs, LoadSession has already resolved the session from
// either a cookie or a PAT Bearer token. AdminGate only needs to check whether
// the authenticated identity has admin privileges.
//
// DB mode  – the session must belong to either a DB user that is a member of
// the system admin group, or an OAuth user whose IDP groups contain any
// provider's configured admin_group.
//
// Static mode (no DB) – only the admin user loaded from the bootstrap secret
// (or the fallback "root" if no secret file exists) may access admin routes.
// Any other authenticated user is denied with 403.
func (s *Server) AdminGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Gate guarantees session is non-nil and unexpired before reaching here.
		session := ezapi.GetRequest(req).Session

		if s.DB == nil {
			// Static mode: only the configured admin user may access admin routes.
			if session.User != s.adminUsername {
				ezmetrics.AuthzDenyTotal.WithLabelValues("admin_gate", "not_admin").Inc()
				s.respondError(rw, req, http.StatusForbidden, http.StatusText(http.StatusForbidden))
				return
			}
			ezmetrics.AuthzAllowTotal.WithLabelValues("admin_gate").Inc()
			next.ServeHTTP(rw, req)
			return
		}

		// DB mode: enforce group-based admin access.
		allowed, err := s.isAdminSession(req.Context(), session)
		if err != nil {
			s.requestLogger(req).Error("admin gate: error checking admin access",
				ezlog.Str("user", session.User),
				ezlog.Str("id_type", session.IDType),
				ezlog.Err(err))
			s.respondError(rw, req, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		if !allowed {
			s.requestLogger(req).Warn("admin gate: access denied",
				ezlog.Str("user", session.User),
				ezlog.Str("id_type", session.IDType))
			ezmetrics.AuthzDenyTotal.WithLabelValues("admin_gate", "not_admin").Inc()
			s.respondError(rw, req, http.StatusForbidden, http.StatusText(http.StatusForbidden))
			return
		}

		ezmetrics.AuthzAllowTotal.WithLabelValues("admin_gate").Inc()
		next.ServeHTTP(rw, req)
	})
}

// authenticatePAT looks up the Bearer PAT token from the request, validates it,
// and returns a synthetic session carrying the token owner's identity.
// Returns nil when the token is invalid, expired, or not found.
func (s *Server) authenticatePAT(req *http.Request) (*ezapi.Session, error) {
	authHeader := req.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, nil
	}

	hash := sha256Hash(token)
	pat, err := s.DB.GetPATByHash(req.Context(), hash)
	if err != nil {
		if errors.Is(err, database.ErrNoRecord) {
			return nil, nil
		}
		return nil, err
	}

	if pat.ExpiresAt != nil && pat.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}

	// Update last_used_at asynchronously so auth latency is not affected.
	// context.WithoutCancel detaches from the request lifetime while preserving trace/values.
	detached := context.WithoutCancel(req.Context())
	go func() {
		ctx, cancel := context.WithTimeout(detached, 5*time.Second)
		defer cancel()
		if err := s.DB.UpdatePATLastUsed(ctx, pat.ID.String()); err != nil {
			s.Logger.Warn("failed to update PAT last_used_at",
				ezlog.Str("pat_id", pat.ID.String()),
				ezlog.Err(err))
		}
	}()

	expiresOn := time.Now().Add(24 * time.Hour) // PAT without explicit expiry: 24h window
	if pat.ExpiresAt != nil {
		expiresOn = *pat.ExpiresAt
	}

	// Populate the username so /me returns a human-readable identity, not a UUID.
	// Only resolve the username in proxy mode where identity headers require it.
	username := pat.UserID.String()
	if s.AuthCfg.Proxy.IsEnabled() {
		username = s.resolveUsername(req.Context(), pat.UserID.String())
	}

	return &ezapi.Session{
		Profile: ezapi.Profile{
			Subject: pat.UserID.String(),
			User:    username,
			IDType:  ezapi.UserIDType,
		},
		ExpiresOn: expiresOn.Unix(),
	}, nil
}

// sha256Hash returns the hex-encoded SHA-256 digest of s.
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// isAdminSession returns true when the session carries admin privileges.
func (s *Server) isAdminSession(ctx context.Context, session *ezapi.Session) (bool, error) {
	switch session.IDType {
	case ezapi.UserIDType:
		return s.isInSystemAdminGroup(ctx, session.Subject)
	case ezapi.OIDCUserIDType:
		return s.isOAuthAdmin(ctx, session), nil //nolint:contextcheck // ctx not required for in-memory check
	default:
		return false, nil
	}
}

// isInSystemAdminGroup checks whether the DB user identified by subject (UUID)
// belongs to the system admin group.
func (s *Server) isInSystemAdminGroup(ctx context.Context, subject string) (bool, error) {
	groupName := s.systemAdminGroup

	// Fetch the group with only the user whose ID matches the subject.
	var group models.GroupDB
	err := s.DB.Manager().WithContext(ctx).
		Preload("Users", "id = ?", subject).
		Where("name = ?", groupName).
		First(&group).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Group not yet created (e.g. bootstrap not yet run) → not an admin.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("fetching system admin group %q: %w", groupName, err)
	}
	return len(group.Users) > 0, nil
}

// isOAuthAdmin checks whether any of the session's IDP groups matches a
// provider's configured admin_group. The admin group set is rebuilt by the
// provider registry after every sync — O(1) lookup per group.
func (s *Server) isOAuthAdmin(_ context.Context, session *ezapi.Session) bool {
	r := s.ensureRegistry()
	m := *r.adminGroups.Load()
	for _, g := range session.Groups {
		if m[g] {
			return true
		}
	}
	return false
}
