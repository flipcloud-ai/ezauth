package server

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	"github.com/flipcloud-ai/ezauth/pkg/server/dto"
)

const (
	groupPath = "/groups"
)

func (s *Server) groupRouter(r *mux.Router) {
	r.HandleFunc("/", s.ListGroups).Methods("GET").Name("auth::group::list")
	r.HandleFunc("/{name}", s.GetGroup).Methods("GET").Name("auth::group::get")
	r.HandleFunc("/", s.AddGroup).Methods("POST").Name("auth::group::create")
	r.HandleFunc("/{name}", s.UpdateGroup).Methods("PUT").Name("auth::group::update")
	r.HandleFunc("/{name}", s.DeleteGroup).Methods("DELETE").Name("auth::group::delete")
	r.HandleFunc("/{name}/members/assign", s.AssignGroupMember).Methods("POST").Name("auth::group::assign-member")
	r.HandleFunc("/{name}/members/unassign", s.UnassignGroupMember).Methods("DELETE").Name("auth::group::unassign-member")
	r.HandleFunc("/{name}/roles/assign", s.AssignGroupRole).Methods("POST").Name("auth::group::assign-role")
	r.HandleFunc("/{name}/roles/unassign", s.UnassignGroupRole).Methods("DELETE").Name("auth::group::unassign-role")
}

// ListGroups returns a paginated list of all groups.
//
// @Summary      List groups
// @Description  Returns a paginated list of all groups.
// @Tags         Group Management
// @Produce      json
// @Param        limit query int false "Page size (default 30)"
// @Param        offset query int false "Offset (default 0)"
// @Param        page query int false "Page number (1-based)"
// @Success      200 {object} dto.GroupListResponse "Group list"
// @Failure      400 {object} dto.ErrorResponse "Invalid pagination params"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/ [get]
func (s *Server) ListGroups(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	limit, offset, err := pagination(r)
	if err != nil {
		logger.Error("error in parsing pagination parameters", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid pagination parameters, please check the format and try again.")
		return
	}

	groups, err := s.DB.ListGroups(r.Context(), limit, offset)
	if err != nil {
		logger.Error("error listing groups", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	items := make([]*dto.GroupListItem, len(groups))
	for i, g := range groups {
		items[i] = &dto.GroupListItem{
			ID:   g.ID,
			Name: g.GroupName,
		}
	}
	response := dto.GroupListResponse{
		Items:  items,
		Offset: offset,
		Limit:  limit,
		Total:  len(items),
	}
	s.writeJSONResponse(rw, http.StatusOK, "groups retrieved", response)
}

// GetGroup returns the group with the given name.
//
// @Summary      Get a group by name
// @Description  Returns group details including member users and assigned roles.
// @Tags         Group Management
// @Produce      json
// @Param        name path string true "Group name"
// @Success      200 {object} dto.GroupResponse "Group details"
// @Failure      404 {object} dto.ErrorResponse "Group not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/{name} [get]
func (s *Server) GetGroup(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	group, err := s.DB.GetGroup(r.Context(), name)
	if err != nil {
		logger.Error("error getting group", ezlog.Str("group", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	roles := make([]string, len(group.Roles))
	for i, role := range group.Roles {
		roles[i] = role.RoleName
	}
	users := make([]dto.GroupUserItem, len(group.Users))
	for i, u := range group.Users {
		users[i] = dto.GroupUserItem{
			ID:       u.ID,
			Username: u.Username,
		}
	}

	response := dto.GroupResponse{
		ID:        group.ID,
		Name:      group.GroupName,
		Roles:     roles,
		Users:     users,
		CreatedAt: group.CreatedAt,
	}
	s.writeJSONResponse(rw, http.StatusOK, "group retrieved", response)
}

// AddGroup creates a new group.
//
// @Summary      Create a group
// @Description  Creates a new group with the specified name.
// @Tags         Group Management
// @Accept       json
// @Produce      json
// @Param        body body dto.CreateGroupRequest true "Group name"
// @Success      200 "Group created"
// @Failure      400 {object} dto.ErrorResponse "Invalid request body"
// @Failure      409 {object} dto.ErrorResponse "Duplicate group name"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/ [post]
func (s *Server) AddGroup(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	var req dto.CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding group request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "group name is required")
		return
	}

	g := &models.GroupDB{
		GroupName: req.Name,
	}
	err := s.DB.AddGroup(r.Context(), g)
	if err != nil {
		logger.Error("error adding group", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusCreated, "group created", map[string]any{"name": g.GroupName})
}

// UpdateGroup updates an existing group by name.
//
// @Summary      Update a group
// @Description  Renames an existing group.
// @Tags         Group Management
// @Accept       json
// @Produce      json
// @Param        name path string true "Current group name"
// @Param        body body dto.UpdateGroupRequest true "New group name"
// @Success      200 "Group updated"
// @Failure      400 {object} dto.ErrorResponse "Invalid request body"
// @Failure      404 {object} dto.ErrorResponse "Group not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/{name} [put]
func (s *Server) UpdateGroup(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	var req dto.UpdateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding group update request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		req.Name = name
	}

	err := s.DB.UpdateGroup(r.Context(), name, &models.GroupDB{
		GroupName: req.Name,
	})
	if err != nil {
		logger.Error("error updating group", ezlog.Str("group", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "group updated", nil)
}

// DeleteGroup removes the group with the given name.
//
// @Summary      Delete a group
// @Description  Permanently removes a group from the database.
// @Tags         Group Management
// @Produce      json
// @Param        name path string true "Group name to delete"
// @Success      200 "Group deleted"
// @Failure      404 {object} dto.ErrorResponse "Group not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/{name} [delete]
func (s *Server) DeleteGroup(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	err := s.DB.DeleteGroup(r.Context(), name)
	if err != nil {
		logger.Error("error deleting group", ezlog.Str("group", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "group deleted", nil)
}

// AssignGroupMember adds users to a group.
//
// @Summary      Add members to a group
// @Description  Assigns one or more users to a group.
// @Tags         Group Management
// @Accept       json
// @Produce      json
// @Param        name path string true "Group name"
// @Param        body body dto.GroupMemberRequest true "User IDs to add"
// @Success      200 "Members added"
// @Failure      400 {object} dto.ErrorResponse "Missing parameters"
// @Failure      404 {object} dto.ErrorResponse "Group or user not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/{name}/members/assign [post]
func (s *Server) AssignGroupMember(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	var req dto.GroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding group member request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Users) == 0 {
		s.writeJSONError(rw, http.StatusBadRequest, "users is required")
		return
	}

	if err := s.DB.AddUserToGroup(r.Context(), name, req.Users); err != nil {
		logger.Error("error adding users to group", ezlog.Str("group", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "members added", nil)
}

// UnassignGroupMember removes users from a group.
//
// @Summary      Remove members from a group
// @Description  Removes one or more users from a group.
// @Tags         Group Management
// @Accept       json
// @Produce      json
// @Param        name path string true "Group name"
// @Param        body body dto.GroupMemberRequest true "User IDs to remove"
// @Success      200 "Members removed"
// @Failure      400 {object} dto.ErrorResponse "Missing parameters"
// @Failure      404 {object} dto.ErrorResponse "Group or user not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/{name}/members/unassign [delete]
func (s *Server) UnassignGroupMember(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	var req dto.GroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding group member request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Users) == 0 {
		s.writeJSONError(rw, http.StatusBadRequest, "users is required")
		return
	}

	if err := s.DB.RemoveUserFromGroup(r.Context(), name, req.Users); err != nil {
		logger.Error("error removing users from group", ezlog.Str("group", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "members removed", nil)
}

// AssignGroupRole assigns roles to a group.
//
// @Summary      Assign roles to a group
// @Description  Grants roles to a group. All group members inherit these roles.
// @Tags         Group Management
// @Accept       json
// @Produce      json
// @Param        name path string true "Group name"
// @Param        body body dto.GroupRoleRequest true "Roles to assign"
// @Success      200 "Roles assigned"
// @Failure      400 {object} dto.ErrorResponse "Missing parameters"
// @Failure      404 {object} dto.ErrorResponse "Group or role not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/{name}/roles/assign [post]
func (s *Server) AssignGroupRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.rbacController == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	var req dto.GroupRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding group role assign request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Roles) == 0 {
		s.writeJSONError(rw, http.StatusBadRequest, "roles is required")
		return
	}

	if err := s.rbacController.AddRoleToGroup(r.Context(), name, req.Roles); err != nil {
		logger.Error("error assigning roles to group", ezlog.Str("group", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "roles assigned", nil)
}

// UnassignGroupRole removes roles from a group.
//
// @Summary      Unassign roles from a group
// @Description  Revokes roles from a group.
// @Tags         Group Management
// @Accept       json
// @Produce      json
// @Param        name path string true "Group name"
// @Param        body body dto.GroupRoleRequest true "Roles to unassign"
// @Success      200 "Roles unassigned"
// @Failure      400 {object} dto.ErrorResponse "Missing parameters"
// @Failure      404 {object} dto.ErrorResponse "Group or role not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/groups/{name}/roles/unassign [delete]
func (s *Server) UnassignGroupRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.rbacController == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	var req dto.GroupRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding group role unassign request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Roles) == 0 {
		s.writeJSONError(rw, http.StatusBadRequest, "roles is required")
		return
	}

	if err := s.rbacController.RemoveRoleFromGroup(r.Context(), name, req.Roles); err != nil {
		logger.Error("error unassigning roles from group", ezlog.Str("group", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusOK, "roles unassigned", nil)
}
