package models

import (
	"time"

	"github.com/google/uuid"
)

// PATDB represents a Personal Access Token stored in the database.
// Only the SHA-256 hash of the token is stored; the plaintext token is
// returned once at creation time and never persisted.
type PATDB struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;not null;default:gen_random_uuid()" json:"id"`
	Name       string     `gorm:"type:varchar(128);not null" json:"name"`
	Prefix     string     `gorm:"type:varchar(16);not null" json:"prefix"`
	Hash       string     `gorm:"type:varchar(64);uniqueIndex;not null" json:"-"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"user_id"`
	ExpiresAt  *time.Time `gorm:"column:expires_at" json:"expires_at,omitempty"`
	LastUsedAt *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `gorm:"column:created_at;autoCreateTime;not null" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;autoUpdateTime;not null" json:"updated_at"`
}

// TableName returns the database table name for PATDB.
func (PATDB) TableName() string {
	return "pat_tokens"
}
