package models

import (
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/flipcloud-ai/ezauth/pkg/utils"
)

// actionRe validates the Resource::Action format for permission entries.
// Subgroup indices: 1 = Resource, 2 = Action.
var actionRe = regexp.MustCompile(`^(?P<Resource>[A-Za-z][A-Za-z0-9_-]{0,16}|\*)::(?P<Action>[A-Za-z][A-Za-z0-9_-]{0,16}|\*)$`)

// RoleDB represents the ORM model for an RBAC role.
type RoleDB struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;uniqueIndex;not null;default:gen_random_uuid()" json:"id"`
	RoleName string    `gorm:"type:varchar(128);uniqueIndex;not null;default:null;column:name" json:"name"`
	System   bool      `gorm:"type:boolean;default:false" json:"system"`

	Groups   []*GroupDB `gorm:"many2many:group_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"groups"`
	Policies []*Policy  `gorm:"many2many:policy_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"policies"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;default:now();not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime;default:now();not null" json:"updated_at"`
}

// TableName returns the database table name for RoleDB.
func (RoleDB) TableName() string {
	return "roles"
}

// BeforeSave validates the RoleDB fields before persisting to the database.
func (r *RoleDB) BeforeSave(tx *gorm.DB) error {
	if !utils.IsValidName(r.RoleName, 32) {
		return fmt.Errorf("validation error: invalid role name format")
	}
	return nil
}

// Policy represents the ORM model for an RBAC policy, a named set of permissions.
type Policy struct {
	Name       string         `gorm:"type:varchar(128);primaryKey;uniqueIndex;not null;default:null" json:"name"`
	Permission []*Permission  `gorm:"many2many:policy_permissions;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"permissions"`
	Roles      []*RoleDB      `gorm:"many2many:policy_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"roles"`
	Resource   pq.StringArray `gorm:"type:text[]" json:"resource"`
	System     bool           `gorm:"type:boolean;default:false" json:"system"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;default:now();not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime;default:now();not null" json:"updated_at"`
}

// TableName returns the database table name for Policy.
func (Policy) TableName() string {
	return "rbac_policies"
}

// BeforeSave validates the Policy fields before persisting to the database.
func (p *Policy) BeforeSave(tx *gorm.DB) error {
	if !utils.IsValidName(p.Name, 32) {
		return fmt.Errorf("validation error: invalid policy name %s", p.Name)
	}
	return nil
}

// Permission represents the ORM model for an RBAC permission entry.
type Permission struct {
	Name    string    `gorm:"type:varchar(128);primaryKey;uniqueIndex;not null;default:null" json:"name"`
	Effect  bool      `gorm:"type:boolean" json:"effect"`
	Service string    `gorm:"type:varchar(32)" json:"service"`
	Method  string    `gorm:"type:varchar(16)" json:"method"`
	Path    string    `gorm:"type:varchar(256)" json:"path"`
	Action  string    `gorm:"type:varchar(64);not null;default:null" json:"action"`
	Policy  []*Policy `gorm:"many2many:policy_permissions;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"policies"`
	System  bool      `gorm:"type:boolean;default:false" json:"system"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;default:now();not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime;default:now();not null" json:"updated_at"`
}

// TableName returns the database table name for Permission.
func (Permission) TableName() string {
	return "rbac_permissions"
}

// BeforeSave validates the Permission fields before persisting to the database.
func (p *Permission) BeforeSave(tx *gorm.DB) error {
	if p.Action == "" {
		return fmt.Errorf("validation error: action cannot be empty")
	}
	// actionRe has 2 capturing groups; a full match produces 3 elements.
	if matches := actionRe.FindStringSubmatch(p.Action); len(matches) < 3 {
		return fmt.Errorf("validation error: invalid action format")
	}
	if !utils.IsValidName(p.Service) && p.Service != "*" {
		return fmt.Errorf("validation error: invalid service format")
	}
	if !utils.IsValidPermissionName(p.Name, 32) {
		return fmt.Errorf("validation error: invalid permission name format")
	}
	if !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE", "ALL"}, p.Method) {
		return fmt.Errorf("validation error: invalid HTTP method")
	}
	if !utils.IsValidPath(p.Path) {
		return fmt.Errorf("validation error: invalid path format")
	}
	return nil
}
