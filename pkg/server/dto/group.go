package dto

import (
	"time"

	"github.com/google/uuid"
)

// CreateGroupRequest is the request body for creating a new group.
// @Description Request body for creating a group. The name field is required.
type CreateGroupRequest struct {
	Name string `json:"name"`
}

// UpdateGroupRequest is the request body for renaming a group.
// @Description Request body for updating a group. The name field is the new group name.
type UpdateGroupRequest struct {
	Name string `json:"name"`
}

// GroupMemberRequest is the request body for adding or removing group members.
// @Description Request body for managing group membership. The users field is a list of user UUIDs.
type GroupMemberRequest struct {
	Users []string `json:"users"`
}

// GroupRoleRequest is the request body for assigning or unassigning roles to a group.
// @Description Request body for granting or revoking group roles. The roles field is a list of role names.
type GroupRoleRequest struct {
	Roles []string `json:"roles"`
}

// GroupListItem is a lightweight group entry returned in list responses.
// @Description Summary row for a group in list views. Includes id and name.
type GroupListItem struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// GroupResponse is the full group details returned by GetGroup.
// @Description Full group details including member users, assigned roles, and creation timestamp.
type GroupResponse struct {
	ID        uuid.UUID       `json:"id"`
	Name      string          `json:"name"`
	Roles     []string        `json:"roles"`
	Users     []GroupUserItem `json:"users"`
	CreatedAt time.Time       `json:"created_at"`
}

// GroupUserItem is a lightweight user reference within a group response.
// @Description Minimal user reference returned inside group details. Contains id and username.
type GroupUserItem struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
}

// GroupListResponse is the paginated response for listing groups.
// @Description Paginated list of groups with offset, limit, and total count metadata.
type GroupListResponse struct {
	Items  []*GroupListItem `json:"items"`
	Offset int              `json:"offset"`
	Limit  int              `json:"limit"`
	Total  int              `json:"total"`
}
