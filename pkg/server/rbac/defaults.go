package rbac

import (
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	ezlog "github.com/flipcloud-ai/ezauth/log"

	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// Default system policy definitions.
// Each policy maps a name to the set of permission names it grants.
var defaultPolicies = map[string][]string{
	// Full admin: all permissions via the global wildcard.
	"system-admin": {"admin::*::*"},

	// All auth-related permissions (permission, policy, role CRUD + assign/unassign).
	"access-admin": {
		"auth::permission::*",
		"auth::policy::*",
		"auth::role::*",
	},

	// User CRUD + role assignment/unassignment.
	"user-admin": {
		"auth::user::*",
		"auth::group::*",
	},

	// Provider CRUD.
	"provider-admin": {
		"ipc::provider::*",
	},

	// Read-only access to all auth resources.
	"access-readonly": {
		"auth::permission::list",
		"auth::permission::get",
		"auth::policy::list",
		"auth::policy::get",
		"auth::role::list",
		"auth::role::get",
		"auth::user::list",
		"auth::user::get",
		"auth::group::list",
		"auth::group::get",
	},

	// Read-only access to users.
	"user-readonly": {
		"auth::user::list",
		"auth::user::get",
		"auth::group::list",
		"auth::group::get",
	},

	// Read-only access to providers.
	"provider-readonly": {
		"ipc::provider::get",
	},

	// Full access to the admin portal UI.
	"portal-admin": {
		"admin::portal::*",
	},

	// Read-only access to audit events.
	"audit-readonly": {
		"admin::audit::list",
	},
}

// Default system roles. Each role maps a name to its policy names.
var defaultRoles = map[string][]string{
	"system-admin":      {"system-admin"},
	"access-admin":      {"access-admin"},
	"user-admin":        {"user-admin"},
	"provider-admin":    {"provider-admin"},
	"access-readonly":   {"access-readonly"},
	"user-readonly":     {"user-readonly"},
	"provider-readonly": {"provider-readonly"},
	"portal-admin":      {"portal-admin"},
	"audit-readonly":    {"audit-readonly"},
}

// SeedDefaults creates or converges the default system policies and roles.
// It is idempotent and convergent — policies and roles are created if missing,
// and their associations are always replaced to match the current definitions.
// Must be called after RouteWalk so that all permissions already exist.
func (a *AuthController) SeedDefaults() error {
	logger := a.logger
	session := a.quietSession()

	if err := session.Transaction(func(tx *gorm.DB) error {
		for name, permNames := range defaultPolicies {
			policy := models.Policy{
				Name:   name,
				System: true,
			}
			res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&policy)
			if res.Error != nil {
				logger.Debug("Failed to seed policy", ezlog.Str("policy", name), ezlog.Err(res.Error))
				continue
			}

			// Fetch fully-populated permission records created by RouteWalk.
			var perms []*models.Permission
			if err := tx.Where("name IN ?", permNames).Find(&perms).Error; err != nil {
				logger.Debug("Failed to fetch permissions for policy", ezlog.Str("policy", name), ezlog.Err(err))
				continue
			}
			if err := tx.Model(&policy).Association("Permission").Replace(perms); err != nil {
				logger.Debug("Failed to associate permissions for policy", ezlog.Str("policy", name), ezlog.Err(err))
			}
			logger.Debug("Seeded default policy", ezlog.Str("policy", name), ezlog.Int("permissions", len(perms)))
		}

		for name, policyNames := range defaultRoles {
			role := models.RoleDB{
				RoleName: name,
				System:   true,
			}
			res := tx.Where("name = ?", name).Attrs(role).FirstOrCreate(&role)
			if res.Error != nil {
				logger.Debug("Failed to seed role", ezlog.Str("role", name), ezlog.Err(res.Error))
				continue
			}

			var policies []*models.Policy
			if err := tx.Where("name IN ?", policyNames).Find(&policies).Error; err != nil {
				logger.Debug("Failed to fetch policies for role", ezlog.Str("role", name), ezlog.Err(err))
				continue
			}
			if err := tx.Model(&role).Association("Policies").Replace(policies); err != nil {
				logger.Debug("Failed to associate policies for role", ezlog.Str("role", name), ezlog.Err(err))
			}
			logger.Debug("Seeded default role", ezlog.Str("role", name), ezlog.Any("policies", policyNames))
		}

		// Bind system-admin role to the admin group so the bootstrap
		// root user has full RBAC access immediately after seeding.
		// Use Replace (not Append) to keep the join table idempotent across restarts.
		if a.adminGroupName != "" {
			var adminGroup models.GroupDB
			if err := tx.First(&adminGroup, "name = ?", a.adminGroupName).Error; err == nil {
				var sysAdminRole models.RoleDB
				if err := tx.First(&sysAdminRole, "name = ?", "system-admin").Error; err == nil {
					if err := tx.Model(&adminGroup).Association("Roles").Replace([]*models.RoleDB{&sysAdminRole}); err != nil {
						logger.Debug("Failed to assign system-admin role to admin group",
							ezlog.Str("group", a.adminGroupName), ezlog.Err(err))
					} else {
						logger.Info("Assigned system-admin role to admin group",
							ezlog.Str("group", a.adminGroupName))
					}
				}
			}
		}

		return nil
	}); err != nil {
		logger.Error("Failed to seed default policies and roles", ezlog.Err(err))
		return fmt.Errorf("seed defaults transaction: %w", err)
	}

	return nil
}
