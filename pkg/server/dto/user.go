package dto

import (
	"time"

	"github.com/google/uuid"

	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// CreateUserRequest is the request body for creating a new user account.
// @Description Request body for creating a user. Username and password are required; all other fields are optional (email is strongly recommended).
type CreateUserRequest struct {
	Username     string           `json:"username"`
	Email        string           `json:"email"`
	MobileNumber string           `json:"mobile_number"`
	Password     string           `json:"password"`
	FirstName    string           `json:"first_name"`
	LastName     string           `json:"last_name"`
	BirthDate    time.Time        `json:"birth_date"`
	Address      models.AddressDB `json:"address"`
}

// UpdateUserRequest is the request body for updating an existing user.
// @Description Request body for updating a user. The id field is required; all other fields are optional and only provided fields are updated.
type UpdateUserRequest struct {
	ID           string           `json:"id"`
	Username     string           `json:"username"`
	Email        string           `json:"email"`
	MobileNumber string           `json:"mobile_number"`
	FirstName    string           `json:"first_name"`
	LastName     string           `json:"last_name"`
	Address      models.AddressDB `json:"address"`
}

// DeleteUserRequest is the request body for deleting a user.
// @Description Request body for deleting a user. The id field is required.
type DeleteUserRequest struct {
	ID string `json:"id"`
}

// ResetPasswordRequest is the request body for resetting a user's password.
// @Description Request body for changing a user's password. The password field is required.
type ResetPasswordRequest struct {
	Password string `json:"password"`
}

// UserRoleRequest is the request body for assigning or unassigning roles.
// @Description Request body for granting or revoking roles. The roles field is a list of role names.
type UserRoleRequest struct {
	Roles []string `json:"roles"`
}

// UserListItem is a lightweight user entry returned in list responses.
// @Description Summary row for a user in list views. Includes the most relevant fields for browsing users.
type UserListItem struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	MobileNumber string    `json:"mobile_number"`
	Email        string    `json:"email"`
	Country      string    `json:"country"`
	Groups       []string  `json:"groups"`
	LastLogin    time.Time `json:"last_login"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Active       bool      `json:"active"`
}

// UserResponse is the full user profile returned by GetUser and GetMe.
// @Description Full user profile including roles, groups, and address details.
type UserResponse struct {
	ID           uuid.UUID        `json:"id"`
	Username     string           `json:"username"`
	MobileNumber string           `json:"mobile_number"`
	Email        string           `json:"email"`
	FirstName    string           `json:"first_name"`
	LastName     string           `json:"last_name"`
	BirthDate    time.Time        `json:"birth_date"`
	Active       bool             `json:"active"`
	Address      models.AddressDB `json:"address"`
	Roles        []string         `json:"roles"`
	Groups       []string         `json:"groups"`
	IDType       string           `json:"id_type,omitempty"`
	LastLogin    time.Time        `json:"last_login"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}
