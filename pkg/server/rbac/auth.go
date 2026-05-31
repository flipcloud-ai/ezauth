package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// Permissions CRUD

// cacheOrFetch is a generic cache-first, singleflight-backed database lookup.
// It first checks the cache, then uses singleflight to coalesce concurrent
// requests for the same key into a single database call.
func cacheOrFetch[T any](ctx context.Context, a *AuthController, cacheKey string, fetch func(context.Context) (T, error)) (T, error) {
	if data, err := a.cache.Get(ctx, cacheKey); err == nil {
		var result T
		if json.Unmarshal(data, &result) == nil {
			return result, nil
		}
	}

	// detach from the caller's context so a cancelled caller does not abort
	// the in-flight DB query and poison all other waiters sharing this flight.
	flightCtx := context.WithoutCancel(ctx)
	ch := a.sfGroup.DoChan(cacheKey, func() (any, error) {
		// double-check: another flight may have already populated the cache
		if data, err := a.cache.Get(flightCtx, cacheKey); err == nil {
			var result T
			if json.Unmarshal(data, &result) == nil {
				return result, nil
			}
		}
		result, err := fetch(flightCtx)
		if err != nil {
			return nil, err
		}
		if data, err := json.Marshal(result); err == nil {
			_ = a.cache.Set(flightCtx, cacheKey, data, CacheTTL)
		}
		return result, nil
	})
	select {
	case <-ctx.Done():
		var zero T
		return zero, fmt.Errorf("rbac: context cancelled waiting for db flight: %w", ctx.Err())
	case res := <-ch:
		if res.Err != nil {
			var zero T
			return zero, res.Err
		}
		return res.Val.(T), nil
	}
}

// ListPermissions returns all permissions for the given service, paginated by limit/offset.
func (a *AuthController) ListPermissions(ctx context.Context, service string, limit, offset int) (map[string][]*models.Permission, error) {
	return a.db.ListPermissions(ctx, service, limit, offset)
}

// GetPermission returns the named permission, consulting the cache before the database.
func (a *AuthController) GetPermission(ctx context.Context, name string) (*models.Permission, error) {
	return cacheOrFetch(ctx, a, permissionCacheKey(name), func(flightCtx context.Context) (*models.Permission, error) {
		return a.db.GetPermission(flightCtx, name)
	})
}

// AddPermission persists a new permission and evicts its cache entry.
func (a *AuthController) AddPermission(ctx context.Context, p *models.Permission) error {
	if err := a.db.AddPermission(ctx, p); err != nil {
		return err
	}

	_ = a.cache.Del(ctx, permissionCacheKey(p.Name))
	return nil
}

// UpdatePermission updates a non-system permission and evicts its cache entry.
func (a *AuthController) UpdatePermission(ctx context.Context, p *models.Permission) error {
	existing, err := a.GetPermission(ctx, p.Name)
	if err != nil {
		return err
	}
	if existing.System {
		return ErrSystemResource
	}

	if err := a.db.UpdatePermission(ctx, p); err != nil {
		return err
	}

	_ = a.cache.Del(ctx, permissionCacheKey(p.Name))
	return nil
}

// DeletePermission removes a non-system permission and evicts its cache entry.
func (a *AuthController) DeletePermission(ctx context.Context, name string) error {
	existing, err := a.GetPermission(ctx, name)
	if err != nil {
		return err
	}
	if existing.System {
		return ErrSystemResource
	}

	if err := a.db.DeletePermission(ctx, name); err != nil {
		return err
	}

	// Remove from cache
	_ = a.cache.Del(ctx, permissionCacheKey(name))
	return nil
}

// Policies CRUD

// ListPolicies returns all policies, paginated by limit/offset.
func (a *AuthController) ListPolicies(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
	return a.db.ListPolicies(ctx, limit, offset)
}

// GetPolicy returns the named policy, consulting the cache before the database.
func (a *AuthController) GetPolicy(ctx context.Context, name string) (*models.Policy, error) {
	return cacheOrFetch(ctx, a, policyCacheKey(name), func(flightCtx context.Context) (*models.Policy, error) {
		return a.db.GetPolicy(flightCtx, name)
	})
}

// AddPolicy persists a new policy and evicts its cache entry.
func (a *AuthController) AddPolicy(ctx context.Context, p *models.Policy) error {
	if err := a.db.AddPolicy(ctx, p); err != nil {
		return err
	}

	_ = a.cache.Del(ctx, policyCacheKey(p.Name))
	return nil
}

// UpdatePolicy updates a non-system policy and evicts its cache entry.
func (a *AuthController) UpdatePolicy(ctx context.Context, name string, p *models.Policy) error {
	existing, err := a.GetPolicy(ctx, name)
	if err != nil {
		return err
	}
	if existing.System {
		return ErrSystemResource
	}

	if err := a.db.UpdatePolicy(ctx, name, p); err != nil {
		return err
	}
	_ = a.cache.Del(ctx, policyCacheKey(name))
	a.invalidateUserPermissionsByPolicy(ctx, name)

	return nil
}

// DeletePolicy removes a non-system policy and evicts affected user permission cache entries.
func (a *AuthController) DeletePolicy(ctx context.Context, name string) error {
	existing, err := a.GetPolicy(ctx, name)
	if err != nil {
		return err
	}
	if existing.System {
		return ErrSystemResource
	}

	// Collect affected user IDs before deletion while the associations still exist.
	affectedUserIDs, _ := a.db.GetUserIDsByPolicy(ctx, name)

	if err := a.db.DeletePolicy(ctx, name); err != nil {
		return err
	}

	_ = a.cache.Del(ctx, policyCacheKey(name))
	for _, uid := range affectedUserIDs {
		_ = a.cache.Del(ctx, UserPermissionCachePrefix+uid)
	}
	return nil
}

// Roles CRUD

// ListRoles returns all roles, paginated by limit/offset.
func (a *AuthController) ListRoles(ctx context.Context, limit, offset int) ([]*models.RoleDB, error) {
	return a.db.ListRoles(ctx, limit, offset)
}

// GetRole returns the named role, consulting the cache before the database.
func (a *AuthController) GetRole(ctx context.Context, name string) (*models.RoleDB, error) {
	return cacheOrFetch(ctx, a, roleCacheKey(name), func(flightCtx context.Context) (*models.RoleDB, error) {
		return a.db.GetRole(flightCtx, name)
	})
}

// AddRole persists a new role and evicts its cache entry.
func (a *AuthController) AddRole(ctx context.Context, r *models.RoleDB) error {
	if err := a.db.AddRole(ctx, r); err != nil {
		return err
	}

	// Remove from cache
	_ = a.cache.Del(ctx, roleCacheKey(r.RoleName))
	return nil
}

// UpdateRole updates a non-system role and evicts its cache entry.
func (a *AuthController) UpdateRole(ctx context.Context, name string, r *models.RoleDB) error {
	existing, err := a.GetRole(ctx, name)
	if err != nil {
		return err
	}
	if existing.System {
		return ErrSystemResource
	}

	if err := a.db.UpdateRole(ctx, name, r); err != nil {
		return err
	}

	_ = a.cache.Del(ctx, roleCacheKey(r.RoleName))
	a.invalidateUserPermissionsByRole(ctx, name)
	return nil
}

// DeleteRole removes a non-system role and evicts affected user permission cache entries.
func (a *AuthController) DeleteRole(ctx context.Context, name string) error {
	existing, err := a.GetRole(ctx, name)
	if err != nil {
		return err
	}
	if existing.System {
		return ErrSystemResource
	}

	// Collect affected user IDs before deletion while the associations still exist.
	affectedUserIDs, _ := a.db.GetUserIDsByRole(ctx, name)

	if err := a.db.DeleteRole(ctx, name); err != nil {
		return err
	}

	_ = a.cache.Del(ctx, roleCacheKey(name))
	for _, uid := range affectedUserIDs {
		_ = a.cache.Del(ctx, UserPermissionCachePrefix+uid)
	}
	return nil
}

// Role associations

// AddRoleToUser assigns the given roles to a user and evicts their permission cache entry.
func (a *AuthController) AddRoleToUser(ctx context.Context, userID string, roleNames []string) error {
	if err := a.db.AddRoleToUser(ctx, userID, roleNames); err != nil {
		return err
	}
	_ = a.cache.Del(ctx, UserPermissionCachePrefix+userID)
	return nil
}

// RemoveRoleFromUser removes the given roles from a user and evicts their permission cache entry.
func (a *AuthController) RemoveRoleFromUser(ctx context.Context, userID string, roleNames []string) error {
	if err := a.db.RemoveRoleFromUser(ctx, userID, roleNames); err != nil {
		return err
	}
	_ = a.cache.Del(ctx, UserPermissionCachePrefix+userID)
	return nil
}

// AddRoleToGroup assigns the given roles to a group and evicts member user permission cache entries.
func (a *AuthController) AddRoleToGroup(ctx context.Context, groupName string, roleNames []string) error {
	if err := a.db.AddRoleToGroup(ctx, groupName, roleNames); err != nil {
		return err
	}
	a.invalidateGroupUserPermissions(ctx, groupName)
	return nil
}

// RemoveRoleFromGroup removes the given roles from a group and evicts member user permission cache entries.
func (a *AuthController) RemoveRoleFromGroup(ctx context.Context, groupName string, roleNames []string) error {
	if err := a.db.RemoveRoleFromGroup(ctx, groupName, roleNames); err != nil {
		return err
	}
	a.invalidateGroupUserPermissions(ctx, groupName)
	return nil
}

// invalidateGroupUserPermissions evicts the permission cache for all users in the group.
func (a *AuthController) invalidateGroupUserPermissions(ctx context.Context, groupName string) {
	group, err := a.db.GetGroup(ctx, groupName)
	if err != nil {
		a.logger.Warn("failed to load group for cache invalidation, skipping: " + groupName)
		return
	}
	for _, u := range group.Users {
		_ = a.cache.Del(ctx, UserPermissionCachePrefix+u.ID.String())
	}
}

// invalidateUserPermissionsByRole evicts the permission cache for all users affected by a role.
func (a *AuthController) invalidateUserPermissionsByRole(ctx context.Context, roleName string) {
	userIDs, err := a.db.GetUserIDsByRole(ctx, roleName)
	if err != nil {
		a.logger.Warn("failed to find users for role cache invalidation, skipping: " + roleName)
		return
	}
	for _, uid := range userIDs {
		_ = a.cache.Del(ctx, UserPermissionCachePrefix+uid)
	}
}

// invalidateUserPermissionsByPolicy evicts the permission cache for all users affected by a policy.
func (a *AuthController) invalidateUserPermissionsByPolicy(ctx context.Context, policyName string) {
	userIDs, err := a.db.GetUserIDsByPolicy(ctx, policyName)
	if err != nil {
		a.logger.Warn("failed to find users for policy cache invalidation, skipping: " + policyName)
		return
	}
	for _, uid := range userIDs {
		_ = a.cache.Del(ctx, UserPermissionCachePrefix+uid)
	}
}

// Permission resolution

// GetUserPermissions returns all permissions for a user, consulting the cache before the database.
func (a *AuthController) GetUserPermissions(ctx context.Context, userID string) ([]*models.Permission, error) {
	return cacheOrFetch(ctx, a, UserPermissionCachePrefix+userID, func(flightCtx context.Context) ([]*models.Permission, error) {
		return a.db.GetUserPermissions(flightCtx, userID)
	})
}

// GetGroupPermissions returns all permissions for a group.
func (a *AuthController) GetGroupPermissions(ctx context.Context, groupName string) ([]*models.Permission, error) {
	return a.db.GetGroupPermissions(ctx, groupName)
}

// GetRolePermissions returns all permissions for a role.
func (a *AuthController) GetRolePermissions(ctx context.Context, roleName string) ([]*models.Permission, error) {
	return a.db.GetRolePermissions(ctx, roleName)
}

// EnforceRequest evaluates RBAC permissions for the request's subject and path.
func (a *AuthController) EnforceRequest(req *http.Request) (bool, error) {
	ss := apis.GetRequest(req)
	if ss == nil || ss.Session == nil {
		return false, ErrNoSession
	}
	subject := ss.Session.Subject
	if subject == "" {
		return false, ErrNoSession
	}
	var permissions []*models.Permission
	var err error
	switch ss.Session.IDType {
	case apis.UserIDType, "":
		permissions, err = a.GetUserPermissions(req.Context(), subject)
	case apis.GroupIDType:
		permissions, err = a.GetGroupPermissions(req.Context(), subject)
	case apis.RoleIDType:
		permissions, err = a.GetRolePermissions(req.Context(), subject)
	default:
		return false, fmt.Errorf("unsupported identity type: %s", ss.Session.IDType)
	}
	if err != nil {
		return false, err
	}
	cleanedPath := normalizePath(path.Clean(req.URL.Path))
	result := false
	for _, perm := range permissions {
		// Explicit deny wins over any allow.
		if matchPath(cleanedPath, perm.Path) && matchMethod(req.Method, perm.Method) {
			if !perm.Effect {
				return false, ErrExplicitDeny
			}
			result = true
		}
	}
	return result, nil
}
