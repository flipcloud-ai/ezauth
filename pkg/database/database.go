package database

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/flipcloud-ai/ezauth/log"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// ProviderInterface defines CRUD operations for OAuth provider configurations.
type ProviderInterface interface {
	ScanProviders(ctx context.Context, size int) ([]*ezcfg.ProviderConfig, error)
	ListProviders(ctx context.Context, limit, offset int) ([]*models.ProviderDB, error)
	GetProvider(ctx context.Context, name string) (*ezcfg.ProviderConfig, error)
	AddProvider(ctx context.Context, p *models.ProviderDB) error
	UpdateProvider(ctx context.Context, p *models.ProviderDB) error
	DeleteProvider(ctx context.Context, name string) error
}

// UserInterface defines CRUD and authentication operations for users.
type UserInterface interface {
	GetUser(ctx context.Context, id string) (*models.UserDB, error)
	AddUser(ctx context.Context, u *models.UserDB) error
	UpdateUser(ctx context.Context, u *models.UserDB) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*models.UserDB, error)
	ResetPassword(ctx context.Context, id string, newPassword string) error
	UserLogin(ctx context.Context, usernameOrEmail string, password string) (*ezapi.Profile, error)
}

// RBACInterface defines CRUD operations for RBAC resources and permission resolution.
type RBACInterface interface {
	// Permissions CRUD
	ListPermissions(ctx context.Context, service string, limit, offset int) (map[string][]*models.Permission, error)
	GetPermission(ctx context.Context, name string) (*models.Permission, error)
	AddPermission(ctx context.Context, p *models.Permission) error
	UpdatePermission(ctx context.Context, p *models.Permission) error
	DeletePermission(ctx context.Context, name string) error

	// Policies CRUD
	ListPolicies(ctx context.Context, limit, offset int) ([]*models.Policy, error)
	GetPolicy(ctx context.Context, name string) (*models.Policy, error)
	AddPolicy(ctx context.Context, p *models.Policy) error
	UpdatePolicy(ctx context.Context, name string, p *models.Policy) error
	DeletePolicy(ctx context.Context, name string) error

	// Roles CRUD
	ListRoles(ctx context.Context, limit, offset int) ([]*models.RoleDB, error)
	GetRole(ctx context.Context, name string) (*models.RoleDB, error)
	AddRole(ctx context.Context, r *models.RoleDB) error
	UpdateRole(ctx context.Context, name string, r *models.RoleDB) error
	DeleteRole(ctx context.Context, name string) error

	// Role associations
	AddRoleToUser(ctx context.Context, userID string, roleNames []string) error
	RemoveRoleFromUser(ctx context.Context, userID string, roleNames []string) error
	AddRoleToGroup(ctx context.Context, groupName string, roleNames []string) error
	RemoveRoleFromGroup(ctx context.Context, groupName string, roleNames []string) error

	// Permission resolution
	GetUserPermissions(ctx context.Context, userID string) ([]*models.Permission, error)
	GetGroupPermissions(ctx context.Context, groupName string) ([]*models.Permission, error)
	GetRolePermissions(ctx context.Context, roleName string) ([]*models.Permission, error)
	GetUserIDsByRole(ctx context.Context, roleName string) ([]string, error)
	GetRoleUsers(ctx context.Context, roleName string) ([]string, error)
	GetUserIDsByPolicy(ctx context.Context, policyName string) ([]string, error)
}

// GroupInterface defines CRUD and membership operations for groups.
type GroupInterface interface {
	GetGroup(ctx context.Context, name string) (*models.GroupDB, error)
	AddGroup(ctx context.Context, g *models.GroupDB) error
	UpdateGroup(ctx context.Context, name string, g *models.GroupDB) error
	DeleteGroup(ctx context.Context, name string) error
	ListGroups(ctx context.Context, limit, offset int) ([]*models.GroupDB, error)
	AddUserToGroup(ctx context.Context, groupName string, userIDs []string) error
	RemoveUserFromGroup(ctx context.Context, groupName string, userIDs []string) error
}

// PATInterface defines CRUD operations for Personal Access Tokens.
type PATInterface interface {
	CreatePAT(ctx context.Context, pat *models.PATDB) error
	GetPATByHash(ctx context.Context, hash string) (*models.PATDB, error)
	ListPATs(ctx context.Context, userID string) ([]*models.PATDB, error)
	DeletePAT(ctx context.Context, id, userID string) error
	UpdatePATLastUsed(ctx context.Context, id string) error
}

// AuditInterface defines write and read operations for persisted audit events.
type AuditInterface interface {
	InsertAuditEvents(ctx context.Context, events []*models.AuditEventDB) error
	ListAuditEventsDB(ctx context.Context, limit, offset int) ([]*models.AuditEventDB, error)
}

// DatabaseInterface combines all database sub-interfaces into a single interface.
//
//nolint:revive // established API name; renaming would be a breaking change
type DatabaseInterface interface {
	Init(ctx context.Context) error
	Migrate(ctx context.Context) error
	Manager() *gorm.DB

	ProviderInterface
	UserInterface
	GroupInterface
	RBACInterface
	PATInterface
	AuditInterface
}

// Database wraps a GORM DB instance with an optional logger.
type Database struct {
	*gorm.DB
	Logger            log.Logger
	DropUnusedColumns bool
}

// DropUnusedTableColumns removes columns from dst's table that are not present in the struct definition.
func (db *Database) DropUnusedTableColumns(dst interface{}) {
	stmt := &gorm.Statement{DB: db.DB}
	if err := stmt.Parse(dst); err != nil {
		return
	}
	fields := stmt.Schema.Fields
	columns, _ := db.DB.Migrator().ColumnTypes(dst)

	for i := range columns {
		found := false
		for j := range fields {
			if columns[i].Name() == fields[j].DBName {
				found = true
				break
			}
		}
		if !found {
			if err := db.DB.Migrator().DropColumn(dst, columns[i].Name()); err != nil {
				db.Logger.Warn("failed to drop unused column", log.Str("column", columns[i].Name()))
			}
		}
	}
}

// Init returns ErrNotImplemented; concrete implementations override this method.
func (db *Database) Init(ctx context.Context) error {
	return ErrNotImplemented
}

// Manager returns the underlying GORM DB handle.
func (db *Database) Manager() *gorm.DB {
	return db.DB
}

// Migrate runs auto-migration for all registered models. If DropUnusedColumns is
// enabled, it also drops database columns not present in Go struct definitions.
// DropUnusedColumns is destructive and should remain disabled in production.
func (db *Database) Migrate(ctx context.Context) error {
	err := db.WithContext(ctx).AutoMigrate(
		&models.ProviderDB{}, &models.UserDB{}, &models.GroupDB{},
		&models.RoleDB{}, &models.Policy{}, &models.Permission{},
		&models.PATDB{}, &models.AuditEventDB{},
	)
	if err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}

	if err := db.createJoinTableIndexes(); err != nil {
		return err
	}

	if db.DropUnusedColumns {
		db.Logger.Warn("drop_unused_columns is enabled — this is a destructive operation and may cause data loss in production")
		db.DropUnusedTableColumns(&models.ProviderDB{})
		db.DropUnusedTableColumns(&models.UserDB{})
		db.DropUnusedTableColumns(&models.GroupDB{})
		db.DropUnusedTableColumns(&models.RoleDB{})
		db.DropUnusedTableColumns(&models.Policy{})
		db.DropUnusedTableColumns(&models.Permission{})
		db.DropUnusedTableColumns(&models.PATDB{})
		db.DropUnusedTableColumns(&models.AuditEventDB{})
	}

	return nil
}

// createJoinTableIndexes creates indexes on RBAC join table FK columns used in
// WHERE / JOIN clauses, and adds a CASCADE foreign key on pat_tokens.user_id.
// IF NOT EXISTS / EXCEPTION patterns make repeated calls idempotent.
func (db *Database) createJoinTableIndexes() error {
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_db_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_roles_role ON group_roles(role_db_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_roles_group ON group_roles(group_db_id)`,
		`CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_db_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_roles_role ON policy_roles(role_db_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_roles_policy ON policy_roles(policy_name)`,
	} {
		if err := db.Exec(idx).Error; err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}

	// GORM constraint tags on plain fields do not create FK constraints.
	if err := db.Exec(`
		DO $$ BEGIN
			ALTER TABLE pat_tokens ADD CONSTRAINT fk_pat_tokens_user
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL;
		END $$;
	`).Error; err != nil {
		return fmt.Errorf("create pat_tokens FK: %w", err)
	}

	return nil
}
