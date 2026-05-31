package dto

import (
	"time"

	"github.com/google/uuid"
)

// CreatePATRequest is the request body for creating a new PAT.
// @Description Token creation request. expires_at is required and must be within 365 days from now.
type CreatePATRequest struct {
	Name      string     `json:"name"                        example:"ci-pipeline"`
	ExpiresAt *time.Time `json:"expires_at"                  example:"2026-12-31T23:59:59Z" swaggertype:"string" format:"date-time"`
}

// CreatePATResponse is returned after successful PAT creation.
// The Token field contains the full plaintext token and is only shown once.
type CreatePATResponse struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// PATListItem is returned in token list responses.
// The plaintext token is never included.
type PATListItem struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}
