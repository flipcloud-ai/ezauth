package pgx

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// ListPermissions returns a paginated map of permissions grouped by service.
func (db *PGxDB) ListPermissions(ctx context.Context, service string, limit, offset int) (map[string][]*models.Permission, error) {
	model := db.WithContext(ctx).Model(&models.Permission{})
	if service == "" {
		if limit == 0 {
			limit = 30
		}
		model = model.Order("name").Limit(limit).Offset(offset)
	} else {
		model = model.Where("service = ?", service).Order("action").Limit(limit).Offset(offset)
	}

	result := make(map[string][]*models.Permission)
	rows, err := model.Rows()
	if err != nil {
		e := errors.Unwrap(err)
		if e == nil {
			e = err
		}
		var pgErr *pgconn.PgError
		if errors.As(e, &pgErr) && pgErr.Code == "42P01" {
			db.Logger.Error("RBAC permission table doesn't exist")
			return nil, ezdb.ErrNeedInit
		}
		return nil, fmt.Errorf("list permissions query: %w", err)
	}
	for rows.Next() {
		var permission models.Permission
		err = db.WithContext(ctx).ScanRows(rows, &permission)
		if err != nil {
			db.Logger.Error("Error in scanning RBAC permission record", ezlog.Err(err))
			continue
		}
		result[permission.Service] = append(result[permission.Service], &permission)
	}
	return result, nil
}

// GetPermission retrieves a permission by name from the database.
func (db *PGxDB) GetPermission(ctx context.Context, name string) (*models.Permission, error) {
	return getRecord[models.Permission](ctx, db, "name = ?", name, nil, "RBAC permission")
}

// AddPermission creates a new permission record in the database.
func (db *PGxDB) AddPermission(ctx context.Context, r *models.Permission) error {
	if err := db.WithContext(ctx).Create(r).Error; err != nil {
		return handleCreateError(db, err, "RBAC permission")
	}
	return nil
}

// UpdatePermission updates a permission record in the database.
func (db *PGxDB) UpdatePermission(ctx context.Context, r *models.Permission) error {
	return updateRecord(ctx, db, updateConfig{
		Where:     "name = ?",
		Key:       r.Name,
		Select:    []string{"Name", "Method", "Path"},
		SkipHooks: true,
	}, r, "RBAC permission")
}

// DeletePermission removes a permission by name from the database.
func (db *PGxDB) DeletePermission(ctx context.Context, name string) error {
	return deleteRecord[models.Permission](ctx, db, "name = ?", name, "RBAC permission")
}

// ListPolicies returns a paginated list of RBAC policies from the database.
func (db *PGxDB) ListPolicies(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
	if limit == 0 {
		limit = 30
	}
	records := make([]*models.Policy, 0, limit)
	tx := db.WithContext(ctx).
		Preload("Permission", func(db *gorm.DB) *gorm.DB { return db.Select("name") }).
		Order("name").Limit(limit).Offset(offset).Find(&records)
	if tx.Error != nil {
		if e := checkTableExists(db, tx.Error, "RBAC policy"); e != nil {
			return nil, e
		}
		db.Logger.Error("error listing RBAC policies", ezlog.Err(tx.Error))
		return nil, ezdb.ErrOperation
	}
	return records, nil
}

// GetPolicy retrieves an RBAC policy by name, preloading associated permissions and roles.
func (db *PGxDB) GetPolicy(ctx context.Context, name string) (*models.Policy, error) {
	return getRecord[models.Policy](ctx, db, "name = ?", name, map[string]string{
		"Permission": "Name",
		"Roles":      "ID,Name",
	}, "RBAC policy")
}

// AddPolicy creates a new RBAC policy in the database.
func (db *PGxDB) AddPolicy(ctx context.Context, p *models.Policy) error {
	return db.WithContext(ctx).Session(&gorm.Session{}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		for _, perm := range p.Permission {
			var permission models.Permission
			if err := tx.Where("name = ?", perm.Name).First(&permission).Error; err != nil {
				return ezdb.NewDatabaseError(http.StatusBadRequest, fmt.Errorf("permission %s does not exist", perm.Name))
			}
		}
		if err := tx.Omit("Permission.*").Create(p).Error; err != nil {
			return handleCreateError(db, err, "RBAC policy")
		}
		return nil
	})
}

// UpdatePolicy replaces an existing RBAC policy identified by name.
func (db *PGxDB) UpdatePolicy(ctx context.Context, name string, p *models.Policy) error {
	return db.WithContext(ctx).Session(&gorm.Session{SkipHooks: true}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		if err := p.BeforeSave(tx); err != nil {
			return txErrorToDBError(err)
		}
		// Perform the update
		result := tx.Model(&models.Policy{}).Where("name = ?", name).Select("Name").Updates(p)
		if err := result.Error; err != nil {
			return txErrorToDBError(err)
		}
		if result.RowsAffected == 0 {
			return ezdb.ErrNoRecord
		}

		// Fetch the actual policy record for association operations
		var policy models.Policy
		if err := tx.Where("name = ?", p.Name).First(&policy).Error; err != nil {
			return txErrorToDBError(err)
		}

		// Update policy-permission associations
		names := make([]string, len(p.Permission))
		for i, permissionModel := range p.Permission {
			names[i] = permissionModel.Name
		}
		db.Logger.Debug("Updating RBAC policy with permissions", ezlog.Str("name", name), ezlog.Any("permissions", names))
		var permission []*models.Permission

		if err := tx.Model(&models.Permission{}).Find(&permission, names).Error; err != nil {
			db.Logger.Error("Error in finding RBAC permissions for policy update", ezlog.Err(err))
			return txErrorToDBError(err)
		}

		// Use the fetched model instance (with its primary key set) for association
		if err := tx.Model(&policy).Association("Permission").Replace(permission); err != nil {
			return txErrorToDBError(err)
		}

		// Update policy-role associations if roles are included in the update request
		if p.Roles != nil {
			roles := make([]*models.RoleDB, 0, len(p.Roles))
			roleNames := make([]string, len(p.Roles))
			for i, r := range p.Roles {
				roleNames[i] = r.RoleName
			}
			db.Logger.Debug("Updating RBAC policy with roles", ezlog.Str("name", name), ezlog.Any("roles", roleNames))
			if len(roleNames) > 0 {
				if err := tx.Where("name IN ?", roleNames).Find(&roles).Error; err != nil {
					db.Logger.Error("Error in finding RBAC roles for policy update", ezlog.Err(err))
					return txErrorToDBError(err)
				}
			}

			if err := tx.Model(&policy).Association("Roles").Replace(roles); err != nil {
				return txErrorToDBError(err)
			}
		}

		return nil
	})
}

// DeletePolicy removes the RBAC policy with the given name.
func (db *PGxDB) DeletePolicy(ctx context.Context, name string) error {
	return db.WithContext(ctx).Session(&gorm.Session{}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		if err := tx.Model(&models.Policy{Name: name}).Association("Permission").Clear(); err != nil {
			db.Logger.Error("error clearing permissions for RBAC policy", ezlog.Str("name", name), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		result := tx.Delete(&models.Policy{Name: name})
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				db.Logger.Error("error in deleting RBAC policy", ezlog.Str("name", name), ezlog.Err(result.Error))
				return ezdb.ErrOperation
			}
		}
		if result.RowsAffected == 0 {
			db.Logger.Warn("RBAC policy not found for deletion")
			return ezdb.ErrNoRecord
		}
		return nil
	})
}

// ListRoles returns a paginated list of RBAC roles.
func (db *PGxDB) ListRoles(ctx context.Context, limit, offset int) ([]*models.RoleDB, error) {
	return listRecords[models.RoleDB](ctx, db, limit, offset, "name", "RBAC role")
}

// GetRole retrieves the RBAC role with the given name.
func (db *PGxDB) GetRole(ctx context.Context, name string) (*models.RoleDB, error) {
	return getRecord[models.RoleDB](ctx, db, "name = ?", name, map[string]string{
		"Policies": "Name",
		"Groups":   "ID,Name",
	}, "RBAC role")
}

// AddRole creates a new RBAC role in the database.
func (db *PGxDB) AddRole(ctx context.Context, r *models.RoleDB) error {
	return db.WithContext(ctx).Session(&gorm.Session{}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		for _, policy := range r.Policies {
			var dbPolicy models.Policy
			if err := tx.Where("name = ?", policy.Name).First(&dbPolicy).Error; err != nil {
				return ezdb.NewDatabaseError(http.StatusBadRequest, fmt.Errorf("policy %s does not exist", policy.Name))
			}
		}
		if err := tx.Create(r).Error; err != nil {
			return handleCreateError(db, err, "RBAC role")
		}
		return nil
	})
}

// UpdateRole replaces an existing RBAC role identified by name.
func (db *PGxDB) UpdateRole(ctx context.Context, name string, r *models.RoleDB) error {
	return db.WithContext(ctx).Session(&gorm.Session{SkipHooks: true}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		if err := r.BeforeSave(tx); err != nil {
			return txErrorToDBError(err)
		}
		// Perform the update
		result := tx.Model(&models.RoleDB{}).Where("name = ?", name).Select("RoleName").Updates(r)
		if err := result.Error; err != nil {
			return txErrorToDBError(err)
		}
		if result.RowsAffected == 0 {
			return ezdb.ErrNoRecord
		}

		// Fetch the actual role record for association operations
		var role models.RoleDB
		if err := tx.Where("name = ?", r.RoleName).First(&role).Error; err != nil {
			return txErrorToDBError(err)
		}

		// Update role-policy associations
		policies := make([]*models.Policy, len(r.Policies))
		names := make([]string, len(policies))
		for i, p := range r.Policies {
			names[i] = p.Name
		}
		db.Logger.Debug("Updating RBAC role with permissions", ezlog.Str("name", name), ezlog.Any("permissions", names))

		if err := tx.Model(&models.Policy{}).Find(&policies, names).Error; err != nil {
			db.Logger.Error("Error in finding RBAC permissions for role update", ezlog.Err(err))
			return txErrorToDBError(err)
		}

		// Use the fetched model instance (with its primary key set) for association
		if err := tx.Model(&role).Association("Policies").Replace(policies); err != nil {
			return txErrorToDBError(err)
		}

		// Update group-role associations if groups are included in the update request
		if r.Groups != nil {
			groups := make([]*models.GroupDB, len(r.Groups))
			groupNames := make([]string, len(groups))
			for i, g := range r.Groups {
				groupNames[i] = g.GroupName
			}
			db.Logger.Debug("Updating RBAC role with groups", ezlog.Str("name", name), ezlog.Any("groups", groupNames))

			if err := tx.Model(&models.GroupDB{}).Where("name IN ?", groupNames).Find(&groups).Error; err != nil {
				db.Logger.Error("Error in finding RBAC groups for role update", ezlog.Err(err))
				return txErrorToDBError(err)
			}

			if err := tx.Model(&role).Association("Groups").Replace(groups); err != nil {
				return txErrorToDBError(err)
			}
		}
		return nil
	})
}

// DeleteRole removes the RBAC role with the given name.
func (db *PGxDB) DeleteRole(ctx context.Context, name string) error {
	return deleteRecord[models.RoleDB](ctx, db, "name = ?", name, "RBAC role")
}

func (db *PGxDB) findRolesByNames(tx *gorm.DB, roleNames []string) ([]*models.RoleDB, error) {
	var roles []*models.RoleDB
	if err := tx.Where("name IN ?", roleNames).Find(&roles).Error; err != nil {
		db.Logger.Error("error in finding roles", ezlog.Any("roleNames", roleNames), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	if len(roles) != len(roleNames) {
		found := make(map[string]bool, len(roles))
		for _, r := range roles {
			found[r.RoleName] = true
		}
		for _, name := range roleNames {
			if !found[name] {
				db.Logger.Warn("role not found", ezlog.Str("name", name))
				return nil, ezdb.NewDatabaseError(http.StatusBadRequest, fmt.Errorf("role %s not found", name))
			}
		}
	}
	return roles, nil
}

// AddRoleToUser assigns the given roles to a user.
func (db *PGxDB) AddRoleToUser(ctx context.Context, userID string, roleNames []string) error {
	return db.WithContext(ctx).Session(&gorm.Session{}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		var user models.UserDB
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				db.Logger.Warn("user not found", ezlog.Str("userID", userID))
				return ezdb.NewDatabaseError(http.StatusNotFound, fmt.Errorf("user %s not found", userID))
			}
			db.Logger.Error("error in finding user", ezlog.Str("userID", userID), ezlog.Err(err))
			return ezdb.ErrOperation
		}

		roles, err := db.findRolesByNames(tx, roleNames)
		if err != nil {
			return err
		}

		if err := tx.Model(&user).Association("Roles").Append(roles); err != nil {
			db.Logger.Error("error in associating roles to user", ezlog.Str("userID", userID), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		return nil
	})
}

// RemoveRoleFromUser removes the given roles from a user.
func (db *PGxDB) RemoveRoleFromUser(ctx context.Context, userID string, roleNames []string) error {
	return db.WithContext(ctx).Session(&gorm.Session{}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		var user models.UserDB
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				db.Logger.Warn("user not found", ezlog.Str("userID", userID))
				return ezdb.NewDatabaseError(http.StatusNotFound, fmt.Errorf("user %s not found", userID))
			}
			db.Logger.Error("error in finding user", ezlog.Str("userID", userID), ezlog.Err(err))
			return ezdb.ErrOperation
		}

		roles, err := db.findRolesByNames(tx, roleNames)
		if err != nil {
			return err
		}

		if err := tx.Model(&user).Association("Roles").Delete(roles); err != nil {
			db.Logger.Error("error in removing roles from user", ezlog.Str("userID", userID), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		return nil
	})
}

// AddRoleToGroup assigns the given roles to a group.
func (db *PGxDB) AddRoleToGroup(ctx context.Context, groupName string, roleNames []string) error {
	return db.WithContext(ctx).Session(&gorm.Session{}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		var group models.GroupDB
		if err := tx.First(&group, "name = ?", groupName).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				db.Logger.Warn("group not found", ezlog.Str("groupName", groupName))
				return ezdb.NewDatabaseError(http.StatusNotFound, fmt.Errorf("group %s not found", groupName))
			}
			db.Logger.Error("error in finding group", ezlog.Str("groupName", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}

		roles, err := db.findRolesByNames(tx, roleNames)
		if err != nil {
			return err
		}

		if err := tx.Model(&group).Association("Roles").Append(roles); err != nil {
			db.Logger.Error("error in associating roles to group", ezlog.Str("groupName", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		return nil
	})
}

// RemoveRoleFromGroup removes the given roles from a group.
func (db *PGxDB) RemoveRoleFromGroup(ctx context.Context, groupName string, roleNames []string) error {
	return db.WithContext(ctx).Session(&gorm.Session{}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		var group models.GroupDB
		if err := tx.First(&group, "name = ?", groupName).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				db.Logger.Warn("group not found", ezlog.Str("groupName", groupName))
				return ezdb.NewDatabaseError(http.StatusNotFound, fmt.Errorf("group %s not found", groupName))
			}
			db.Logger.Error("error in finding group", ezlog.Str("groupName", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}

		roles, err := db.findRolesByNames(tx, roleNames)
		if err != nil {
			return err
		}

		if err := tx.Model(&group).Association("Roles").Delete(roles); err != nil {
			db.Logger.Error("error in removing roles from group", ezlog.Str("groupName", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		return nil
	})
}

// deduplicatePermissions removes duplicate permissions by name, preserving order.
func deduplicatePermissions(perms []*models.Permission) []*models.Permission {
	seen := make(map[string]struct{}, len(perms))
	result := make([]*models.Permission, 0, len(perms))
	for _, p := range perms {
		if _, exists := seen[p.Name]; !exists {
			seen[p.Name] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}

// collectPermissionsFromRoles resolves policies → permissions for a set of roles.
func (db *PGxDB) collectPermissionsFromRoles(tx *gorm.DB, roles []*models.RoleDB) ([]*models.Permission, error) {
	if len(roles) == 0 {
		return nil, nil
	}

	roleIDs := make([]string, len(roles))
	for i, r := range roles {
		roleIDs[i] = r.ID.String()
	}

	var policies []*models.Policy
	if err := tx.Model(&models.Policy{}).
		Joins("JOIN policy_roles ON policy_roles.policy_name = rbac_policies.name").
		Where("policy_roles.role_db_id IN ?", roleIDs).
		Preload("Permission").
		Find(&policies).Error; err != nil {
		return nil, err
	}

	var all []*models.Permission
	for _, p := range policies {
		all = append(all, p.Permission...)
	}
	return all, nil
}

// GetRolePermissions returns all permissions assigned to the given role.
func (db *PGxDB) GetRolePermissions(ctx context.Context, roleName string) ([]*models.Permission, error) {
	var role models.RoleDB
	if err := db.WithContext(ctx).Where("name = ?", roleName).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ezdb.ErrNoRecord
		}
		return nil, ezdb.ErrOperation
	}

	perms, err := db.collectPermissionsFromRoles(db.WithContext(ctx), []*models.RoleDB{&role})
	if err != nil {
		db.Logger.Error("error resolving permissions for role", ezlog.Str("roleName", roleName), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	return deduplicatePermissions(perms), nil
}

// GetGroupPermissions returns all permissions assigned to the given group.
func (db *PGxDB) GetGroupPermissions(ctx context.Context, groupName string) ([]*models.Permission, error) {
	var group models.GroupDB
	if err := db.WithContext(ctx).Where("name = ?", groupName).Preload("Roles").First(&group).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ezdb.ErrNoRecord
		}
		return nil, ezdb.ErrOperation
	}

	perms, err := db.collectPermissionsFromRoles(db.WithContext(ctx), group.Roles)
	if err != nil {
		db.Logger.Error("error resolving permissions for group", ezlog.Str("groupName", groupName), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	return deduplicatePermissions(perms), nil
}

// GetUserPermissions returns all permissions assigned to the given user.
func (db *PGxDB) GetUserPermissions(ctx context.Context, userID string) ([]*models.Permission, error) {
	var user models.UserDB
	if err := db.WithContext(ctx).Where("id = ?", userID).
		Preload("Roles").
		Preload("Groups.Roles").
		First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ezdb.ErrNoRecord
		}
		return nil, ezdb.ErrOperation
	}

	// Collect all roles: direct user roles + roles from groups.
	roleMap := make(map[string]*models.RoleDB)
	for _, r := range user.Roles {
		roleMap[r.ID.String()] = r
	}
	for _, g := range user.Groups {
		for _, r := range g.Roles {
			roleMap[r.ID.String()] = r
		}
	}

	allRoles := make([]*models.RoleDB, 0, len(roleMap))
	for _, r := range roleMap {
		allRoles = append(allRoles, r)
	}

	perms, err := db.collectPermissionsFromRoles(db.WithContext(ctx), allRoles)
	if err != nil {
		db.Logger.Error("error resolving permissions for user", ezlog.Str("userID", userID), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	return deduplicatePermissions(perms), nil
}

// GetUserIDsByRole returns all user IDs that have the given role,
// either directly or via a group.
func (db *PGxDB) GetUserIDsByRole(ctx context.Context, roleName string) ([]string, error) {
	var role models.RoleDB
	if err := db.WithContext(ctx).Where("name = ?", roleName).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, ezdb.ErrOperation
	}
	roleID := role.ID.String()

	idSet := make(map[string]struct{})

	// Direct user→role assignments.
	var directIDs []string
	if err := db.WithContext(ctx).Raw(
		"SELECT user_db_id FROM user_roles WHERE role_db_id = ?", roleID,
	).Scan(&directIDs).Error; err != nil {
		db.Logger.Error("error finding users by role", ezlog.Str("roleName", roleName), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	for _, id := range directIDs {
		idSet[id] = struct{}{}
	}

	// Users in groups that have this role.
	var groupIDs []string
	if err := db.WithContext(ctx).Raw(
		"SELECT group_db_id FROM group_roles WHERE role_db_id = ?", roleID,
	).Scan(&groupIDs).Error; err != nil {
		db.Logger.Error("error finding groups by role", ezlog.Str("roleName", roleName), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	if len(groupIDs) > 0 {
		var groupUserIDs []string
		if err := db.WithContext(ctx).Raw(
			"SELECT user_db_id FROM user_groups WHERE group_db_id IN ?", groupIDs,
		).Scan(&groupUserIDs).Error; err != nil {
			db.Logger.Error("error finding users by groups for role", ezlog.Str("roleName", roleName), ezlog.Err(err))
			return nil, ezdb.ErrOperation
		}
		for _, id := range groupUserIDs {
			idSet[id] = struct{}{}
		}
	}

	result := make([]string, 0, len(idSet))
	for id := range idSet {
		result = append(result, id)
	}
	return result, nil
}

// GetRoleUsers returns all usernames that hold the given role, either directly or via a group.
func (db *PGxDB) GetRoleUsers(ctx context.Context, roleName string) ([]string, error) {
	var role models.RoleDB
	if err := db.WithContext(ctx).Where("name = ?", roleName).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, ezdb.ErrOperation
	}
	roleID := role.ID.String()

	var usernames []string
	if err := db.WithContext(ctx).Raw(
		`SELECT DISTINCT u.username FROM users u
		WHERE u.id IN (
			SELECT user_db_id FROM user_roles WHERE role_db_id = ?
			UNION
			SELECT ug.user_db_id FROM user_groups ug
			INNER JOIN group_roles gr ON gr.group_db_id = ug.group_db_id
			WHERE gr.role_db_id = ?
		)
		ORDER BY u.username`,
		roleID, roleID,
	).Scan(&usernames).Error; err != nil {
		db.Logger.Error("error finding users by role", ezlog.Str("roleName", roleName), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	return usernames, nil
}

// GetUserIDsByPolicy returns all user IDs that are affected by the given policy,
// by resolving policy → roles → users/groups.
func (db *PGxDB) GetUserIDsByPolicy(ctx context.Context, policyName string) ([]string, error) {
	var userIDs []string
	if err := db.WithContext(ctx).Raw(
		`SELECT DISTINCT ru.user_db_id
		FROM policy_roles pr
		INNER JOIN user_roles ru ON ru.role_db_id = pr.role_db_id
		WHERE pr.policy_name = ?`,
		policyName,
	).Scan(&userIDs).Error; err != nil {
		db.Logger.Error("error finding user IDs by policy", ezlog.Str("policyName", policyName), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	if len(userIDs) == 0 {
		return nil, nil
	}
	return userIDs, nil
}
