package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	"github.com/flipcloud-ai/ezauth/pkg/server/dto"
)

const (
	userPath = "/users"

	maxTokenNameLen = 128
	maxExpiresIn    = 365 * 24 * time.Hour

	usernameCachePrefix = "user::"
	usernameCacheTTL    = 5 * time.Minute

	// b61 is a 61-character alphabet for token generation (A-Z, a-z, 0-9 without
	// the last digit to keep it coprime with typical random ranges).
	b61 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678"

	randomCharCount = 40
)

func (s *Server) userRouter(r *mux.Router) {
	r.HandleFunc("/", s.ListUsers).Methods("GET").Name("auth::user::list")
	r.HandleFunc("/", s.AddUser).Methods("POST").Name("auth::user::create")
	r.HandleFunc("/{uid}", s.GetUser).Methods("GET").Name("auth::user::get")
	r.HandleFunc("/", s.UpdateUser).Methods("PUT").Name("auth::user::update")
	r.HandleFunc("/", s.DeleteUser).Methods("DELETE").Name("auth::user::delete")
	r.HandleFunc("/{uid}/reset-password", s.ChangePassword).Methods("PUT").Name("auth::user::reset_password")
	r.HandleFunc("/{uid}/roles/assign", s.AssignUserRole).Methods("POST").Name("auth::user::assign-role")
	r.HandleFunc("/{uid}/roles/unassign", s.UnassignUserRole).Methods("DELETE").Name("auth::user::unassign-role")
}

// generatePAT produces a new opaque token with the configured prefix and 40
// characters of crypto-random base61 (alphanumeric) entropy. It returns the
// full token and the prefix so callers do not need to re-read the config.
func (s *Server) generatePAT() (token, prefix string, err error) {
	prefix = s.AuthCfg.OpaqueToken.Prefix
	if prefix == "" {
		prefix = "ezauth_"
	}
	var sb strings.Builder
	sb.Grow(len(prefix) + randomCharCount)
	sb.WriteString(prefix)

	max := big.NewInt(int64(len(b61)))
	for range randomCharCount {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", "", fmt.Errorf("generate random char: %w", err)
		}
		sb.WriteByte(b61[n.Int64()])
	}
	return sb.String(), prefix, nil
}

// resolveUsername returns the username for userID, consulting the cache first.
// Falls back to a DB lookup on cache miss. Returns userID unchanged on any error.
func (s *Server) resolveUsername(ctx context.Context, userID string) string {
	key := usernameCachePrefix + userID
	if s.globalCache != nil {
		if val, err := s.globalCache.Get(ctx, key); err == nil {
			return string(val)
		}
	}
	u, err := s.DB.GetUser(ctx, userID)
	if err != nil {
		return userID
	}
	if s.globalCache != nil {
		_ = s.globalCache.Set(ctx, key, []byte(u.Username), usernameCacheTTL)
	}
	return u.Username
}

// evictUsernameCache removes the cached username for userID, if any.
func (s *Server) evictUsernameCache(ctx context.Context, userID string) {
	if s.globalCache != nil {
		_ = s.globalCache.Del(ctx, usernameCachePrefix+userID)
	}
}

func pagination(r *http.Request) (limit, offset int, err error) {
	var v int
	offset = 0
	limit = 30
	if q := r.URL.Query().Get("limit"); q != "" {
		v, err = strconv.Atoi(q)
		if err != nil {
			return
		} else if v < 0 {
			err = fmt.Errorf("invalid limit parameter, must be a non-negative integer")
			return
		}
		limit = v
	}
	const maxLimit = 100
	if limit > maxLimit {
		limit = maxLimit
	}
	if q := r.URL.Query().Get("offset"); q != "" {
		v, err = strconv.Atoi(q)
		if err != nil {
			return
		} else if v < 0 {
			err = fmt.Errorf("invalid offset parameter, must be a non-negative integer")
			return
		}
		offset = v
	}
	if q := r.URL.Query().Get("page"); q != "" {
		v, err = strconv.Atoi(q)
		if err != nil {
			return
		} else if v < 0 {
			err = fmt.Errorf("invalid page parameter, must be a non-negative integer")
			return
		}
		if v > 0 {
			offset = (v - 1) * limit
		}
	}
	return
}

// GetUser returns the user with the given ID.
//
// @Summary      Get a user by ID
// @Description  Returns the full profile for a single user, including roles and groups.
// @Tags         User Management
// @Produce      json
// @Param        uid path string true "User UUID"
// @Success      200 {object} dto.UserResponse "User profile"
// @Failure      404 {object} dto.ErrorResponse "User not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/{uid} [get]
func (s *Server) GetUser(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	vars := mux.Vars(r)
	uid := vars["uid"]

	logger.Debug("getting user from database", ezlog.Str("uid", uid))
	u, err := s.DB.GetUser(r.Context(), uid)
	if err != nil {
		s.writeGeneralError(rw, err)
		return
	}
	if s.globalCache != nil {
		_ = s.globalCache.Set(r.Context(), usernameCachePrefix+uid, []byte(u.Username), usernameCacheTTL)
	}

	roles := make([]string, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = r.RoleName
	}
	groups := make([]string, len(u.Groups))
	for i, g := range u.Groups {
		groups[i] = g.GroupName
	}

	response := dto.UserResponse{
		ID:           u.ID,
		Username:     u.Username,
		MobileNumber: u.MobileNumber,
		Email:        u.Email,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
		BirthDate:    u.BirthDate,
		Active:       u.Active,
		Address:      u.Address,
		Roles:        roles,
		Groups:       groups,
		LastLogin:    u.LastLogin,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}

	s.writeJSONResponse(rw, http.StatusOK, "user retrieved", response)
}

// UpdateUser updates an existing user's details.
//
// @Summary      Update a user
// @Description  Updates profile fields for an existing user. The body must include the user ID.
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        body body dto.UpdateUserRequest true "Updated user fields"
// @Success      200 "User updated"
// @Failure      400 {object} dto.ErrorResponse "Invalid request body or user ID"
// @Failure      404 {object} dto.ErrorResponse "User not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/ [put]
func (s *Server) UpdateUser(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req dto.UpdateUserRequest
	err := decoder.Decode(&req)
	if err != nil {
		logger.Error("error in parsing form data", ezlog.Err(err))
		code := http.StatusBadRequest
		s.writeJSONError(rw, code, "invalid request body, please check the format and try again.")
		return
	}

	id, err := uuid.Parse(req.ID)
	if err != nil {
		s.writeJSONError(rw, http.StatusBadRequest, "invalid user id")
		return
	}

	u := models.UserDB{
		ID:           id,
		Username:     req.Username,
		Email:        req.Email,
		MobileNumber: req.MobileNumber,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Address:      req.Address,
		// BirthDate intentionally omitted — not editable via this endpoint
	}

	logger.Info("updating user in database.")
	err = s.DB.UpdateUser(r.Context(), &u)
	if err != nil {
		switch err {
		case database.ErrNoRecord:
			s.writeJSONError(rw, http.StatusNotFound, "user not found")
			return
		}
		code := http.StatusInternalServerError
		s.writeJSONError(rw, code, fmt.Sprintf("%s, please contact admin.", http.StatusText(code)))
		return
	}
	s.evictUsernameCache(r.Context(), u.ID.String())
	logger.Info("user updated successfully.")
	s.writeJSONResponse(rw, http.StatusOK, "user updated", nil)
}

// DeleteUser removes the user with the given ID.
//
// @Summary      Delete a user
// @Description  Permanently removes a user from the database. The body must include the user ID.
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        body body dto.DeleteUserRequest true "User ID to delete"
// @Success      200 "User deleted"
// @Failure      400 {object} dto.ErrorResponse "Missing user ID"
// @Failure      404 {object} dto.ErrorResponse "User not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/ [delete]
func (s *Server) DeleteUser(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req dto.DeleteUserRequest
	err := decoder.Decode(&req)
	if err != nil {
		logger.Error("error in parsing form data for user deletion", ezlog.Err(err))
		code := http.StatusBadRequest
		s.writeJSONError(rw, code, fmt.Sprintf("%s, please contact admin.", http.StatusText(code)))
		return
	}
	if req.ID == "" {
		logger.Error("missing user id in delete user request")
		code := http.StatusBadRequest
		s.writeJSONError(rw, code, "user id is required.")
		return
	}

	logger.Info("deleting user from database.")
	err = s.DB.DeleteUser(r.Context(), req.ID)
	if err != nil {
		s.writeGeneralError(rw, err)
		return
	}
	s.evictUsernameCache(r.Context(), req.ID)
	logger.Info("user deleted successfully.")
	s.writeJSONResponse(rw, http.StatusOK, "user deleted", nil)
}

// AddUser creates a new user account.
//
// @Summary      Create a user
// @Description  Creates a new user with the specified profile fields and password.
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        body body dto.CreateUserRequest true "User details"
// @Success      200 "User created"
// @Failure      400 {object} dto.ErrorResponse "Invalid request body"
// @Failure      409 {object} dto.ErrorResponse "Duplicate username/email"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/ [post]
func (s *Server) AddUser(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req dto.CreateUserRequest
	err := decoder.Decode(&req)
	if err != nil {
		logger.Error("error in parsing form data for new user", ezlog.Err(err))
		code := http.StatusBadRequest
		s.writeJSONError(rw, code, "invalid request body, please check the format and try again.")
		return
	}

	u := models.UserDB{
		Username:     req.Username,
		Email:        req.Email,
		MobileNumber: req.MobileNumber,
		Password:     req.Password,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		BirthDate:    req.BirthDate,
		Address:      req.Address,
	}

	err = s.DB.AddUser(r.Context(), &u)
	if err != nil {
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusCreated, "user created", map[string]any{"id": u.ID, "username": u.Username})
}

// ListUsers returns a paginated list of all users.
//
// @Summary      List users
// @Description  Returns a paginated list of all users.
// @Tags         User Management
// @Produce      json
// @Param        limit query int false "Page size (default 30)"
// @Param        offset query int false "Offset (default 0)"
// @Param        page query int false "Page number (1-based, alternative to offset)"
// @Success      200 {array} dto.UserListItem "List of users"
// @Failure      400 {object} dto.ErrorResponse "Invalid pagination params"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/ [get]
func (s *Server) ListUsers(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	limit, offset, err := pagination(r)
	if err != nil {
		s.Logger.Error("error in parsing pagination parameters", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid pagination parameters, please check the format and try again.")
		return
	}

	logger.Debug("listing users", ezlog.Int("limit", limit), ezlog.Int("offset", offset))
	users, err := s.DB.ListUsers(r.Context(), limit, offset)
	if err != nil {
		logger.Error("error in listing users", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	// Convert models.UserDB to dto.UserListItem
	userList := make([]*dto.UserListItem, len(users))
	for i, u := range users {
		groups := make([]string, len(u.Groups))
		for j, g := range u.Groups {
			groups[j] = g.GroupName
		}
		userList[i] = &dto.UserListItem{
			ID:           u.ID,
			Username:     u.Username,
			FirstName:    u.FirstName,
			LastName:     u.LastName,
			MobileNumber: u.MobileNumber,
			Email:        u.Email,
			Country:      u.Address.Country,
			Groups:       groups,
			LastLogin:    u.LastLogin,
			CreatedAt:    u.CreatedAt,
			UpdatedAt:    u.UpdatedAt,
			Active:       u.Active,
		}
	}

	s.writeJSONResponse(rw, http.StatusOK, "users retrieved", userList)
}

// ChangePassword resets the password for the given user.
//
// @Summary      Reset a user's password
// @Description  Sets a new password for the specified user. Requires admin privileges.
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        uid path string true "User UUID"
// @Param        body body dto.ResetPasswordRequest true "New password"
// @Success      200 "Password changed"
// @Failure      400 {object} dto.ErrorResponse "Missing user ID or password"
// @Failure      404 {object} dto.ErrorResponse "User not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/{uid}/reset-password [put]
func (s *Server) ChangePassword(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	uid := vars["uid"]
	if uid == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "user id is required")
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req dto.ResetPasswordRequest
	err := decoder.Decode(&req)
	if err != nil {
		logger.Error("error in parsing password request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Password == "" {
		logger.Error("password is required")
		s.writeJSONError(rw, http.StatusBadRequest, "password is required")
		return
	}

	logger.Info("changing password for user.")
	err = s.DB.ResetPassword(r.Context(), uid, req.Password)
	if err != nil {
		if errors.Is(err, database.ErrNoRecord) {
			s.writeJSONError(rw, http.StatusNotFound, "user not found")
			return
		}
		s.writeGeneralError(rw, err)
		return
	}
	logger.Info("password changed successfully for user.")
	s.writeJSONResponse(rw, http.StatusOK, "password changed", nil)
}

// AssignUserRole assigns roles to a user.
//
// @Summary      Assign roles to a user
// @Description  Grants the specified roles to a user. Roles are referenced by name.
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        uid path string true "User UUID"
// @Param        body body dto.UserRoleRequest true "Roles to assign"
// @Success      200 "Roles assigned"
// @Failure      400 {object} dto.ErrorResponse "Missing parameters"
// @Failure      404 {object} dto.ErrorResponse "User or role not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/{uid}/roles/assign [post]
func (s *Server) AssignUserRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.rbacController == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	uid := vars["uid"]
	if uid == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "user id is required")
		return
	}

	var req dto.UserRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding role assign request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Roles) == 0 {
		s.writeJSONError(rw, http.StatusBadRequest, "roles is required")
		return
	}

	if err := s.rbacController.AddRoleToUser(r.Context(), uid, req.Roles); err != nil {
		logger.Error("error assigning roles to user", ezlog.Str("uid", uid), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "roles assigned", nil)
}

// UnassignUserRole removes roles from a user.
//
// @Summary      Unassign roles from a user
// @Description  Revokes the specified roles from a user.
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        uid path string true "User UUID"
// @Param        body body dto.UserRoleRequest true "Roles to unassign"
// @Success      200 "Roles unassigned"
// @Failure      400 {object} dto.ErrorResponse "Missing parameters"
// @Failure      404 {object} dto.ErrorResponse "User or role not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/users/{uid}/roles/unassign [delete]
func (s *Server) UnassignUserRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.rbacController == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	uid := vars["uid"]
	if uid == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "user id is required")
		return
	}

	var req dto.UserRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding role unassign request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Roles) == 0 {
		s.writeJSONError(rw, http.StatusBadRequest, "roles is required")
		return
	}

	if err := s.rbacController.RemoveRoleFromUser(r.Context(), uid, req.Roles); err != nil {
		logger.Error("error unassigning roles from user", ezlog.Str("uid", uid), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "roles unassigned", nil)
}
