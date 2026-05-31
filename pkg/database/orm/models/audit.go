package models

import (
	"time"
)

// AuditEventDB is the ORM model for persisted audit events.
type AuditEventDB struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Timestamp time.Time `gorm:"column:timestamp;not null;index" json:"timestamp"`
	Type      string    `gorm:"column:type;type:varchar(32);not null;index" json:"type"`
	User      string    `gorm:"column:user;type:varchar(256);not null;default:''" json:"user"`
	IP        string    `gorm:"column:ip;type:varchar(64);not null;default:''" json:"ip"`
	Provider  string    `gorm:"column:provider;type:varchar(64);default:null" json:"provider,omitempty"`
	Details   string    `gorm:"column:details;type:text;default:null" json:"details,omitempty"`
	RequestID string    `gorm:"column:request_id;type:varchar(64);default:null" json:"request_id,omitempty"`
	Success   bool      `gorm:"column:success;not null;default:true" json:"success"`
}

// TableName returns the database table name for AuditEventDB.
func (AuditEventDB) TableName() string {
	return "audit_events"
}
