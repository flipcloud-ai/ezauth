package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/flipcloud-ai/ezauth/pkg/utils"
)

// GroupDB represents the ORM model for a user group.
type GroupDB struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;not null;default:gen_random_uuid()" json:"id"`
	GroupName string    `gorm:"column:name;type:varchar(64);uniqueIndex;not null;default:null" json:"name"`
	Roles     []*RoleDB `gorm:"many2many:group_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"roles"`
	Users     []*UserDB `gorm:"many2many:user_groups;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"users"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;default:now();not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime;default:now();not null" json:"updated_at"`
}

// TableName returns the database table name for GroupDB.
func (GroupDB) TableName() string {
	return "groups"
}

// BeforeCreate validates GroupDB fields before persisting to the database.
func (g *GroupDB) BeforeCreate(tx *gorm.DB) error {
	if !utils.IsValidName(g.GroupName, 32) {
		return fmt.Errorf("validation error: invalid group name format")
	}
	return nil
}

// AddressDB is the embedded address struct for UserDB.
type AddressDB struct {
	Street  string `gorm:"type:varchar(100);default:null" json:"street"`
	City    string `gorm:"type:varchar(50);default:null" json:"city"`
	State   string `gorm:"type:varchar(50);default:null" json:"state"`
	ZipCode string `gorm:"type:varchar(20);default:null" json:"zip_code"`
	Country string `gorm:"type:varchar(50);not null;default:null" json:"country"`
}

// UserDB represents the ORM model for a user account.
type UserDB struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey;not null;default:gen_random_uuid()" json:"id"`
	Username     string    `gorm:"type:varchar(32);uniqueIndex;not null;default:null" json:"username"`
	MobileNumber string    `gorm:"type:varchar(24);uniqueIndex;default:null" json:"mobile_number"`
	Password     string    `gorm:"not null;size:256;default:null" json:"-"`
	PasswordSalt string    `gorm:"not null;type:varchar(24);default:null" json:"-"`
	Email        string    `gorm:"type:varchar(96);uniqueIndex;default:null" json:"email"`
	FirstName    string    `gorm:"type:varchar(16);default:null" json:"first_name"`
	LastName     string    `gorm:"type:varchar(16);default:null" json:"last_name"`
	BirthDate    time.Time `gorm:"type:date;not null;default:null" json:"birth_date"`
	Active       bool      `gorm:"not null;default:true" json:"active"`

	Address AddressDB `gorm:"embedded" json:"address"`

	Roles  []*RoleDB `gorm:"many2many:user_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"roles"`
	Groups []GroupDB `gorm:"many2many:user_groups;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"groups"`

	LastLogin         time.Time `gorm:"column:last_login;default:now()" json:"last_login"`
	PasswordUpdatedAt time.Time `gorm:"column:password_updated_at;default:now();not null" json:"password_updated_at"`
	CreatedAt         time.Time `gorm:"column:created_at;autoCreateTime;default:now();not null" json:"created_at"`
	UpdatedAt         time.Time `gorm:"column:updated_at;autoUpdateTime;default:now();not null" json:"updated_at"`
}

// TableName returns the database table name for UserDB.
func (UserDB) TableName() string {
	return "users"
}

// BeforeCreate validates UserDB fields before persisting to the database.
func (u *UserDB) BeforeCreate(tx *gorm.DB) error {
	hasUsername := u.Username != ""
	hasEmail := u.Email != ""
	hasMobile := u.MobileNumber != ""
	now := time.Now()

	if u.BirthDate.IsZero() || u.BirthDate.After(now.AddDate(-1, 0, 0)) || u.BirthDate.Before(now.AddDate(-150, 0, 0)) {
		return fmt.Errorf("validation error: birth date is invalid")
	}

	if !hasUsername {
		u.Username = fmt.Sprintf("User_%s", uuid.New().String()[:8])
	} else {
		if !utils.IsValidUsername(u.Username) {
			return fmt.Errorf("validation error: invalid username format")
		}
	}

	// Require at least one of email or mobile number
	if !hasEmail && !hasMobile {
		return fmt.Errorf("validation error: either email or mobile number is required")
	}

	// Validate email if provided
	if hasEmail && !utils.IsValidEmail(u.Email) {
		return fmt.Errorf("validation error: invalid email format")
	}

	// Validate mobile number if provided
	if hasMobile && !utils.IsValidPhoneNumber(u.MobileNumber) {
		return fmt.Errorf("validation error: invalid mobile number format")
	}

	// Validate country (required by DB constraint)
	if u.Address.Country == "" {
		return fmt.Errorf("validation error: country is required")
	}

	return nil
}
