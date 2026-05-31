package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	middleware "github.com/flipcloud-ai/ezauth/pkg/middleware"
	"github.com/flipcloud-ai/ezauth/pkg/server/dto"
)

// GetMe returns the profile of the currently authenticated user.
//
// @Summary      Get current user profile
// @Description  Returns the profile of the currently authenticated user from the session.
// @Tags         Self-Service
// @Produce      json
// @Success      200 {object} dto.UserResponse "User profile"
// @Failure      401 {object} dto.ErrorResponse "Unauthorized"
// @Router       /ezauth/me [get]
func (s *Server) GetMe(rw http.ResponseWriter, r *http.Request) {
	session := ezapi.GetRequest(r).Session
	if session == nil || session.Subject == "" {
		s.respondUnauthorized(rw, r)
		return
	}

	username := session.User
	if username == "" {
		username = session.PreferredUsername
	}
	if username == "" {
		username = session.Subject
	}

	resp := dto.UserResponse{
		Username:  username,
		Email:     session.Email,
		FirstName: session.FirstName,
		LastName:  session.LastName,
		IDType:    session.IDType,
	}
	s.writeJSONResponse(rw, http.StatusOK, "user profile", resp)
}

// ListMyTokens returns all personal access tokens for the current user.
//
// @Summary      List my personal access tokens
// @Description  Returns metadata for all PATs belonging to the currently authenticated user. Token values are never returned.
// @Tags         Self-Service
// @Produce      json
// @Success      200 {array}  dto.PATListItem "Token list"
// @Failure      401 {object} dto.ErrorResponse "Unauthorized"
// @Failure      404 {object} dto.ErrorResponse "Database not available"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/me/tokens [get]
func (s *Server) ListMyTokens(rw http.ResponseWriter, r *http.Request) {
	session := ezapi.GetRequest(r).Session
	if session == nil || session.Subject == "" {
		s.respondUnauthorized(rw, r)
		return
	}

	if s.DB == nil {
		s.writeJSONError(rw, http.StatusNotFound, http.StatusText(http.StatusNotFound))
		return
	}

	pats, err := s.DB.ListPATs(r.Context(), session.Subject)
	if err != nil {
		s.writeGeneralError(rw, err)
		return
	}

	items := make([]dto.PATListItem, len(pats))
	for i, p := range pats {
		items[i] = dto.PATListItem{
			ID:         p.ID,
			Name:       p.Name,
			CreatedAt:  p.CreatedAt,
			ExpiresAt:  p.ExpiresAt,
			LastUsedAt: p.LastUsedAt,
		}
	}

	s.writeJSONResponse(rw, http.StatusOK, "tokens retrieved", items)
}

// CreateMyToken creates a new personal access token for the current user.
//
// @Summary      Create a personal access token
// @Description  Generates a new opaque token for the currently authenticated user. OIDC users cannot create PATs. The plaintext token is returned once and never stored.
// @Tags         Self-Service
// @Accept       json
// @Produce      json
// @Param        body body dto.CreatePATRequest true "Token creation request"
// @Success      201 {object} dto.CreatePATResponse "Token created"
// @Failure      400 {object} dto.ErrorResponse "Invalid request or OIDC user"
// @Failure      401 {object} dto.ErrorResponse "Unauthorized"
// @Failure      404 {object} dto.ErrorResponse "Database not available"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/me/tokens [post]
func (s *Server) CreateMyToken(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	session := ezapi.GetRequest(r).Session
	if session == nil || session.Subject == "" {
		s.respondUnauthorized(rw, r)
		return
	}

	if session.IDType == ezapi.OIDCUserIDType {
		s.writeJSONError(rw, http.StatusBadRequest, "PAT creation is not supported for OIDC users")
		return
	}

	if s.DB == nil {
		s.writeJSONError(rw, http.StatusNotFound, http.StatusText(http.StatusNotFound))
		return
	}

	var req dto.CreatePATRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "token name is required")
		return
	}
	if len(req.Name) > maxTokenNameLen {
		s.writeJSONError(rw, http.StatusBadRequest, "token name must be at most 128 characters")
		return
	}

	if req.ExpiresAt == nil {
		s.writeJSONError(rw, http.StatusBadRequest, "expires_at is required")
		return
	}
	now := time.Now()
	if req.ExpiresAt.Before(now) {
		s.writeJSONError(rw, http.StatusBadRequest, "expires_at must be in the future")
		return
	}
	if req.ExpiresAt.After(now.Add(maxExpiresIn)) {
		s.writeJSONError(rw, http.StatusBadRequest, "expires_at must be at most 365 days from now")
		return
	}
	expiresAt := req.ExpiresAt

	token, prefix, err := s.generatePAT()
	if err != nil {
		logger.Error("failed to generate PAT", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}

	userID, err := uuid.Parse(session.Subject)
	if err != nil {
		logger.Error("invalid user ID in session", ezlog.Str("subject", session.Subject), ezlog.Err(err))
		s.writeJSONError(rw, http.StatusInternalServerError, "internal error")
		return
	}

	pat := &models.PATDB{
		Name:      req.Name,
		Prefix:    prefix,
		Hash:      sha256Hash(token),
		UserID:    userID,
		ExpiresAt: expiresAt,
	}

	if err := s.DB.CreatePAT(r.Context(), pat); err != nil {
		logger.Error("failed to create PAT", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	resp := dto.CreatePATResponse{
		ID:        pat.ID,
		Name:      pat.Name,
		Token:     token,
		ExpiresAt: pat.ExpiresAt,
		CreatedAt: pat.CreatedAt,
	}

	s.writeJSONResponse(rw, http.StatusCreated, "token created", resp)
}

// DeleteMyToken revokes a personal access token belonging to the current user.
//
// @Summary      Revoke a personal access token
// @Description  Permanently deletes the specified token. The operation is irreversible.
// @Tags         Self-Service
// @Param        id path string true "Token UUID"
// @Success      200 "Token revoked"
// @Failure      400 {object} dto.ErrorResponse "Missing token ID"
// @Failure      401 {object} dto.ErrorResponse "Unauthorized"
// @Failure      404 {object} dto.ErrorResponse "Token or database not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/me/tokens/{id} [delete]
func (s *Server) DeleteMyToken(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	session := ezapi.GetRequest(r).Session
	if session == nil || session.Subject == "" {
		s.respondUnauthorized(rw, r)
		return
	}

	if s.DB == nil {
		s.writeJSONError(rw, http.StatusNotFound, http.StatusText(http.StatusNotFound))
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "token id is required")
		return
	}

	err := s.DB.DeletePAT(r.Context(), id, session.Subject)
	if err != nil {
		if errors.Is(err, database.ErrNoRecord) {
			s.writeJSONError(rw, http.StatusNotFound, "token not found")
			return
		}
		logger.Error("failed to delete token", ezlog.Str("id", id), ezlog.Err(err))
		s.writeJSONError(rw, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "token revoked", nil)
}

// meSelfRouter registers the self-service /me routes on r using the provided chain.
// Routes have no Name() to avoid RouteWalk RBAC pollution.
func (s *Server) meSelfRouter(r *mux.Router, authPrefix string, chain middleware.Chain) {
	r.Path(authPrefix + "/me").Handler(chain.ThenFunc(s.GetMe)).Methods("GET")
	r.Path(authPrefix + "/me/tokens").Handler(chain.ThenFunc(s.ListMyTokens)).Methods("GET")
	r.Path(authPrefix + "/me/tokens").Handler(chain.ThenFunc(s.CreateMyToken)).Methods("POST")
	r.Path(authPrefix + "/me/tokens/{id}").Handler(chain.ThenFunc(s.DeleteMyToken)).Methods("DELETE")
}
