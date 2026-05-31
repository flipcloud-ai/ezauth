package dto

import (
	"time"
)

// Permission DTOs

// PermissionRequest is the request body for creating or updating a permission.
type PermissionRequest struct {
	Effect  bool   `json:"effect"`
	Service string `json:"service"`
	Action  string `json:"action"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Name    string `json:"name"`
}

// PermissionResponse is the response body for a single permission.
type PermissionResponse struct {
	Effect    bool      `json:"effect"`
	Service   string    `json:"service"`
	Action    string    `json:"action"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	System    bool      `json:"system"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PermissionListResponse is the paginated response for a list of permissions.
type PermissionListResponse struct {
	Items  map[string][]*PermissionResponse `json:"items"`
	Offset int                              `json:"offset"`
	Limit  int                              `json:"limit"`
	Total  int                              `json:"total"`
}

// Policy DTOs

// PolicyRequest is the request body for creating or updating a policy.
type PolicyRequest struct {
	Name       string   `json:"name"`
	Permission []string `json:"permission,omitempty"`
	Resource   []string `json:"resource,omitempty"`
}

// PolicyResponse is the response body for a single policy.
type PolicyResponse struct {
	Name       string    `json:"name"`
	Permission []string  `json:"permission"`
	Roles      []string  `json:"roles"`
	Resource   []string  `json:"resource"`
	System     bool      `json:"system"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PolicyListResponse is the paginated response for a list of policies.
type PolicyListResponse struct {
	Items  []*PolicyResponse `json:"items"`
	Offset int               `json:"offset"`
	Limit  int               `json:"limit"`
	Total  int               `json:"total"`
}

// Role DTOs

// RoleRequest is the request body for creating or updating a role.
type RoleRequest struct {
	Name   string   `json:"name"`
	Policy []string `json:"policy"`
}

// RoleResponse is the response body for a single role.
type RoleResponse struct {
	Name        string    `json:"name"`
	Policy      []string  `json:"policy"`
	Permissions []string  `json:"permissions"`
	Groups      []string  `json:"groups"`
	Users       []string  `json:"users"`
	System      bool      `json:"system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleListResponse is the paginated response for a list of roles.
type RoleListResponse struct {
	Roles  []string `json:"roles"`
	Offset int      `json:"offset"`
	Limit  int      `json:"limit"`
	Total  int      `json:"total"`
}
