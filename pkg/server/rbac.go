package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	ezdto "github.com/flipcloud-ai/ezauth/pkg/server/dto"
)

const (
	authPath = "/auth"
)

// RBAC API routes are mounted under {AuthPrefix}/auth:
// {AuthPrefix}/auth/permission/{action}
// {AuthPrefix}/auth/policy/{name}
// {AuthPrefix}/auth/role/{name}

func (s *Server) rbacRouter(r *mux.Router) {
	// Permission routes
	r.HandleFunc("/permission/", s.ListPermissions).Methods("GET").Name("auth::permission::list")
	r.HandleFunc("/permission/{name}", s.GetPermission).Methods("GET").Name("auth::permission::get")
	r.HandleFunc("/permission/", s.AddPermission).Methods("POST").Name("auth::permission::create")
	r.HandleFunc("/permission/", s.UpdatePermission).Methods("PUT").Name("auth::permission::update")
	r.HandleFunc("/permission/{name}", s.DeletePermission).Methods("DELETE").Name("auth::permission::delete")

	// Policy routes
	r.HandleFunc("/policy/", s.ListPolicies).Methods("GET").Name("auth::policy::list")
	r.HandleFunc("/policy/{name}", s.GetPolicy).Methods("GET").Name("auth::policy::get")
	r.HandleFunc("/policy/", s.AddPolicy).Methods("POST").Name("auth::policy::create")
	r.HandleFunc("/policy/{name}", s.UpdatePolicy).Methods("PUT").Name("auth::policy::update")
	r.HandleFunc("/policy/{name}", s.DeletePolicy).Methods("DELETE").Name("auth::policy::delete")

	// Role routes
	r.HandleFunc("/role/", s.ListRoles).Methods("GET").Name("auth::role::list")
	r.HandleFunc("/role/{name}", s.GetRole).Methods("GET").Name("auth::role::get")
	r.HandleFunc("/role/", s.AddRole).Methods("POST").Name("auth::role::create")
	r.HandleFunc("/role/{name}", s.UpdateRole).Methods("PUT").Name("auth::role::update")
	r.HandleFunc("/role/{name}", s.DeleteRole).Methods("DELETE").Name("auth::role::delete")
}

func (s *Server) isReservedPath(path string) bool {
	reserved := []string{s.ServeCfg.AuthPrefix, s.ServeCfg.StaticPrefix}
	for _, prefix := range reserved {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			if len(path) == len(prefix) || path[len(prefix)] == '/' {
				return true
			}
		}
	}
	return false
}

// Permission handlers

// ListPermissions handles GET {AuthPrefix}/auth/permission.
func (s *Server) ListPermissions(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	service := r.URL.Query().Get("service")
	limit, offset, err := pagination(r)
	if err != nil {
		s.Logger.Error("error in parsing pagination parameters", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid pagination parameters, please check the format and try again.")
		return
	}

	permissions, err := s.rbacController.ListPermissions(r.Context(), service, limit, offset)
	if err != nil {
		logger.Error("error listing permissions", ezlog.Err(err))
		code := http.StatusInternalServerError
		s.writeJSONError(rw, code, http.StatusText(code))
		return
	}

	rsp := make(map[string][]*ezdto.PermissionResponse)
	total := 0
	for svc, perms := range permissions {
		logger.Debug("listing permission", ezlog.Str("service", svc), ezlog.Any("permissions", perms))
		rsp[svc] = make([]*ezdto.PermissionResponse, len(perms))
		for i, p := range perms {
			rsp[svc][i] = &ezdto.PermissionResponse{
				Effect:  p.Effect,
				Action:  p.Action,
				Path:    p.Path,
				Method:  p.Method,
				Service: p.Service,
				Name:    p.Name,
				System:  p.System,
			}
			total++
		}
	}
	response := ezdto.PermissionListResponse{
		Items: rsp,
		Total: total,
	}
	if service != "" {
		response.Offset = offset
		response.Limit = limit
	}
	s.writeJSONResponse(rw, http.StatusOK, "permissions retrieved", response)
}

// GetPermission handles GET {AuthPrefix}/auth/permission/{name}.
func (s *Server) GetPermission(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	permissionName := vars["name"]

	permission, err := s.rbacController.GetPermission(r.Context(), permissionName)
	if err != nil {
		logger.Error("error getting permission", ezlog.Str("permission", permissionName), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "permission retrieved", permission)
}

// AddPermission handles POST {AuthPrefix}/auth/permission.
func (s *Server) AddPermission(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	var req ezdto.PermissionRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding permission request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.isReservedPath(req.Path) {
		s.writeJSONError(rw, http.StatusBadRequest, "permission path must not use a reserved system prefix")
		return
	}

	err := s.rbacController.AddPermission(r.Context(), &models.Permission{
		Name:    req.Name,
		System:  false,
		Service: req.Service,
		Effect:  req.Effect,
		Action:  req.Action,
		Method:  req.Method,
		Path:    req.Path,
	})
	if err != nil {
		logger.Error("error adding permission", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusCreated, "permission created", map[string]any{"name": req.Name})
}

// UpdatePermission handles PUT {AuthPrefix}/auth/permission/{name}.
func (s *Server) UpdatePermission(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	var req ezdto.PermissionRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding permission request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.isReservedPath(req.Path) {
		s.writeJSONError(rw, http.StatusBadRequest, "permission path must not use a reserved system prefix")
		return
	}

	err := s.rbacController.UpdatePermission(r.Context(), &models.Permission{
		Name:   req.Name,
		Method: req.Method,
		Path:   req.Path,
	})
	if err != nil {
		logger.Error("error updating permission", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "permission updated", nil)
}

// DeletePermission handles DELETE {AuthPrefix}/auth/permission/{name}.
func (s *Server) DeletePermission(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	permissionName := vars["name"]

	err := s.rbacController.DeletePermission(r.Context(), permissionName)
	if err != nil {
		logger.Error("error deleting permission", ezlog.Str("permission", permissionName), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "permission deleted", nil)
}

// Policy handlers

// ListPolicies handles GET {AuthPrefix}/auth/policy.
func (s *Server) ListPolicies(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)

	limit, offset, err := pagination(r)
	if err != nil {
		s.Logger.Error("error in parsing pagination parameters", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid pagination parameters, please check the format and try again.")
		return
	}

	policies, err := s.rbacController.ListPolicies(r.Context(), limit, offset)
	if err != nil {
		logger.Error("error listing policies", ezlog.Err(err))
		code := http.StatusInternalServerError
		s.writeJSONError(rw, code, http.StatusText(code))
		return
	}

	rsp := make([]*ezdto.PolicyResponse, len(policies))
	for i, p := range policies {
		permissions := make([]string, len(p.Permission))
		for j, perm := range p.Permission {
			permissions[j] = perm.Name
		}
		rsp[i] = &ezdto.PolicyResponse{
			Name:       p.Name,
			Permission: permissions,
			CreatedAt:  p.CreatedAt,
			UpdatedAt:  p.UpdatedAt,
		}
	}
	response := ezdto.PolicyListResponse{
		Items:  rsp,
		Total:  len(policies),
		Offset: offset,
		Limit:  limit,
	}

	s.writeJSONResponse(rw, http.StatusOK, "policies retrieved", response)
}

// GetPolicy handles GET {AuthPrefix}/auth/policy/{name}.
func (s *Server) GetPolicy(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	name := vars["name"]

	policy, err := s.rbacController.GetPolicy(r.Context(), name)
	if err != nil {
		logger.Error("error getting policy", ezlog.Str("policy", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	response := ezdto.PolicyResponse{
		Name:       policy.Name,
		CreatedAt:  policy.CreatedAt,
		UpdatedAt:  policy.UpdatedAt,
		Permission: make([]string, len(policy.Permission)),
		Roles:      make([]string, len(policy.Roles)),
	}
	for i, perm := range policy.Permission {
		response.Permission[i] = perm.Name
	}
	for i, role := range policy.Roles {
		response.Roles[i] = role.RoleName
	}
	s.writeJSONResponse(rw, http.StatusOK, "policy retrieved", response)
}

// AddPolicy handles POST {AuthPrefix}/auth/policy.
func (s *Server) AddPolicy(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	var req ezdto.PolicyRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding policy request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}

	permissions := make([]*models.Permission, len(req.Permission))
	for i, name := range req.Permission {
		permissions[i] = &models.Permission{Name: name}
	}

	err := s.rbacController.AddPolicy(r.Context(), &models.Policy{
		Name:       req.Name,
		Permission: permissions,
	})
	if err != nil {
		logger.Error("error adding policy", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	s.writeJSONResponse(rw, http.StatusCreated, "policy created", map[string]any{"name": req.Name})
}

// UpdatePolicy handles PUT {AuthPrefix}/auth/policy/{name}.
func (s *Server) UpdatePolicy(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	var req ezdto.PolicyRequest

	vars := mux.Vars(r)
	name := vars["name"]

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding policy request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}

	if name == "" && req.Name == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "policy name is required")
		return
	} else if req.Name == "" {
		req.Name = name
	} else if name == "" {
		name = req.Name
	}

	permissions := make([]*models.Permission, len(req.Permission))
	for i, name := range req.Permission {
		permissions[i] = &models.Permission{Name: name}
	}

	err := s.rbacController.UpdatePolicy(r.Context(), name, &models.Policy{
		Name:       req.Name,
		Permission: permissions,
	})
	if err != nil {
		logger.Error("error updating policy", ezlog.Str("policy", req.Name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "policy updated", nil)
}

// DeletePolicy handles DELETE {AuthPrefix}/auth/policy/{name}.
func (s *Server) DeletePolicy(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	name := vars["name"]

	err := s.rbacController.DeletePolicy(r.Context(), name)
	if err != nil {
		logger.Error("error deleting policy", ezlog.Str("policy", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "policy deleted", nil)
}

// Role handlers

// ListRoles handles GET {AuthPrefix}/auth/role.
func (s *Server) ListRoles(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)

	limit, offset, err := pagination(r)
	if err != nil {
		s.Logger.Error("error in parsing pagination parameters", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid pagination parameters, please check the format and try again.")
		return
	}

	roles, err := s.rbacController.ListRoles(r.Context(), limit, offset)
	if err != nil {
		logger.Error("error listing roles", ezlog.Err(err))
		code := http.StatusInternalServerError
		s.writeJSONError(rw, code, http.StatusText(code))
		return
	}

	response := ezdto.RoleListResponse{
		Roles:  make([]string, len(roles)),
		Offset: offset,
		Limit:  limit,
		Total:  len(roles),
	}
	for i, r := range roles {
		response.Roles[i] = r.RoleName
	}
	s.writeJSONResponse(rw, http.StatusOK, "roles retrieved", response)
}

// GetRole handles GET {AuthPrefix}/auth/role/{name}.
func (s *Server) GetRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	name := vars["name"]

	role, err := s.rbacController.GetRole(r.Context(), name)
	if err != nil {
		logger.Error("error getting role", ezlog.Str("role", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	perms, err := s.rbacController.GetRolePermissions(r.Context(), name)
	if err != nil {
		logger.Error("error getting role permissions", ezlog.Str("role", name), ezlog.Err(err))
		perms = nil
	}

	var roleUsers []string
	if s.DB != nil {
		var roleUsersErr error
		roleUsers, roleUsersErr = s.DB.GetRoleUsers(r.Context(), name)
		if roleUsersErr != nil {
			logger.Warn("failed to fetch role users", ezlog.Str("role", name), ezlog.Err(roleUsersErr))
		}
	}

	response := ezdto.RoleResponse{
		Name:        role.RoleName,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
		Policy:      make([]string, len(role.Policies)),
		Groups:      make([]string, len(role.Groups)),
		Permissions: make([]string, len(perms)),
		Users:       roleUsers,
	}
	if response.Users == nil {
		response.Users = []string{}
	}
	for i, p := range role.Policies {
		response.Policy[i] = p.Name
	}
	for i, group := range role.Groups {
		response.Groups[i] = group.GroupName
	}
	for i, p := range perms {
		response.Permissions[i] = p.Name
	}
	s.writeJSONResponse(rw, http.StatusOK, "role retrieved", response)
}

// AddRole handles POST {AuthPrefix}/auth/role.
func (s *Server) AddRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	var req ezdto.RoleRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding role request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}

	policy := make([]*models.Policy, len(req.Policy))
	for i, name := range req.Policy {
		policy[i] = &models.Policy{Name: name}
	}

	err := s.rbacController.AddRole(r.Context(), &models.RoleDB{
		RoleName: req.Name,
		Policies: policy,
	})
	if err != nil {
		logger.Error("error adding role", ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusCreated, "role created", map[string]any{"name": req.Name})
}

// UpdateRole handles PUT {AuthPrefix}/auth/role/{name}.
func (s *Server) UpdateRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	name := vars["name"]
	var req ezdto.RoleRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding role request", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}

	if name == "" && req.Name == "" {
		s.writeJSONError(rw, http.StatusBadRequest, "role name is required")
		return
	} else if req.Name == "" {
		req.Name = name
	} else if name == "" {
		name = req.Name
	}

	policies := make([]*models.Policy, len(req.Policy))
	for i, p := range req.Policy {
		policies[i] = &models.Policy{Name: p}
	}

	err := s.rbacController.UpdateRole(r.Context(), name, &models.RoleDB{
		RoleName: req.Name,
		Policies: policies,
	})
	if err != nil {
		logger.Error("error updating role", ezlog.Str("role", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "role updated", nil)
}

// DeleteRole handles DELETE {AuthPrefix}/auth/role/{name}.
func (s *Server) DeleteRole(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	name := vars["name"]

	err := s.rbacController.DeleteRole(r.Context(), name)
	if err != nil {
		logger.Error("error deleting role", ezlog.Str("role", name), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}

	s.writeJSONResponse(rw, http.StatusOK, "role deleted", nil)
}
