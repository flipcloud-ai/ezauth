package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"
	"moul.io/zapgorm2"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// RBAC controller cache and key constants.
const (
	CacheTTL           = 5 * time.Minute
	RBACSystemEntryTTL = 365 * 24 * time.Hour // Long TTL for system entries
)

// Cache key prefixes used by the RBAC controller.
const (
	PolicyCachePrefix         = "policy::"
	RoleCachePrefix           = "role::"
	PermissionCachePrefix     = "permission::"
	UserPermissionCachePrefix = "user_permissions::"
)

func policyCacheKey(name string) string {
	return PolicyCachePrefix + name
}

func roleCacheKey(name string) string {
	return RoleCachePrefix + name
}

func permissionCacheKey(name string) string {
	return PermissionCachePrefix + name
}

// Controller defines the RBAC operations exposed by the auth controller.
type Controller interface {
	EnforceRequest(req *http.Request) (bool, error)
	RouteWalk(router *mux.Router) error
	SeedDefaults() error
	// Permissions CRUD
	ListPermissions(ctx context.Context, service string, limit, offset int) (map[string][]*models.Permission, error)
	GetPermission(ctx context.Context, permission string) (*models.Permission, error)
	AddPermission(ctx context.Context, p *models.Permission) error
	UpdatePermission(ctx context.Context, p *models.Permission) error
	DeletePermission(ctx context.Context, permission string) error

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
}

// AuthController implements Controller using the configured database and cache.
type AuthController struct {
	logger         ezlog.Logger
	cache          cache.Cache[string, []byte]
	db             database.DatabaseInterface
	rbacCfg        *ezcfg.RBACConfig
	authPrefix     string
	adminGroupName string
	sfGroup        singleflight.Group
}

// quietSession returns a gorm session that suppresses log output and skips default transactions.
func (a *AuthController) quietSession() *gorm.DB {
	return a.db.Manager().Session(&gorm.Session{
		Logger:                 zapgorm2.New(ezlog.NewNop().Zap()),
		SkipDefaultTransaction: true,
	})
}

// saveSystemPermission caches a permission and persists it to the database.
// DB save failures are logged but not propagated — the cache is the primary store during route walk.
func (a *AuthController) saveSystemPermission(session *gorm.DB, perm models.Permission) error {
	rule, err := json.Marshal(perm)
	if err != nil {
		return fmt.Errorf("marshal permission: %w", err)
	}
	_ = a.cache.Set(context.Background(), permissionCacheKey(perm.Name), rule, RBACSystemEntryTTL)
	if err := session.Save(&perm).Error; err != nil {
		a.logger.Debug("Failed to save permission to database", ezlog.Str("permission", perm.Name), ezlog.Err(err))
	}
	return nil
}

type resourceKey struct {
	service  string
	resource string
}

// RouteWalk walks the mux router and seeds RBAC permissions for each named route.
func (a *AuthController) RouteWalk(router *mux.Router) error {
	logger := a.logger
	serviceMap := make(map[string][]string)
	resourcePaths := make(map[resourceKey][]string)
	session := a.quietSession()

	err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		name := route.GetName()
		if name == "" {
			logger.Debug("Route without name, skipping RBAC resource creation")
			return nil
		}
		service, resource, action, err := parsePermission(name)
		if err != nil {
			logger.Debug("Route name does not match RBAC resource format, skipping RBAC resource creation", ezlog.Str("route_name", name))
			return nil
		}
		path, err := route.GetPathTemplate()
		if err != nil {
			return fmt.Errorf("get route path template: %w", err)
		}
		methods, err := route.GetMethods()
		if err != nil {
			logger.Warn("Route has no methods, skipping RBAC resource creation", ezlog.Str("route_name", name))
			return nil
		}

		if !slices.Contains(serviceMap[service], resource) {
			if len(serviceMap[service]) == 0 {
				logger.Debug("Discovered RBAC service", ezlog.Str("service", service))
			}
			serviceMap[service] = append(serviceMap[service], resource)
		}
		key := resourceKey{service, resource}
		resourcePaths[key] = append(resourcePaths[key], path)

		logger.Debug("Adding route to RBAC permission cache", ezlog.Str("methods", strings.Join(methods, ",")), ezlog.Str("path", path), ezlog.Str("action", name))
		return a.saveSystemPermission(session, models.Permission{
			Method:  strings.Join(methods, ","),
			Service: service,
			Path:    path,
			Action:  fmt.Sprintf("%s::%s", resource, action),
			Name:    name,
			Effect:  true,
			System:  true,
		})
	})
	if err != nil {
		return fmt.Errorf("walk routes: %w", err)
	}

	// Create wildcard permissions for each discovered resource.
	for service, resources := range serviceMap {
		for _, resource := range resources {
			key := resourceKey{service, resource}
			wcPath := wildcardPathFromPaths(resourcePaths[key])
			if len(strings.Split(wcPath, "/")) <= 3 {
				logger.Debug("Skipping wildcard permission due to overly generic path", ezlog.Str("resource", resource), ezlog.Str("service", service), ezlog.Str("path", wcPath))
				continue
			}
			wildcardName := fmt.Sprintf("%s::%s::*", service, resource)
			logger.Debug("Adding wildcard permission to RBAC permission cache", ezlog.Str("wildcard_name", wildcardName), ezlog.Str("path", wcPath))
			if err := a.saveSystemPermission(session, models.Permission{
				Method:  "ALL",
				Service: service,
				Path:    wcPath,
				Action:  fmt.Sprintf("%s::*", resource),
				Name:    wildcardName,
				Effect:  true,
				System:  true,
			}); err != nil {
				return err
			}
		}
	}

	// Create global admin wildcard permission.
	adminWildcardPath := a.authPrefix + "/*"
	logger.Debug("Adding wildcard permission admin::*::* to RBAC permission cache", ezlog.Str("path", adminWildcardPath))
	return a.saveSystemPermission(session, models.Permission{
		Method:  "ALL",
		Service: "admin",
		Path:    adminWildcardPath,
		Action:  "admin::*",
		Name:    "admin::*::*",
		Effect:  true,
		System:  true,
	})
}

// NewController creates a new RBAC Controller backed by the given database and cache.
func NewController(ctx context.Context, rbacCfg *ezcfg.RBACConfig, db database.DatabaseInterface, c cache.Cache[string, []byte], authPrefix, adminGroupName string) (Controller, error) {
	logger := ezlog.FromContext(ctx, "server")
	r := &AuthController{
		cache:          c,
		rbacCfg:        rbacCfg,
		logger:         logger,
		db:             db,
		authPrefix:     authPrefix,
		adminGroupName: adminGroupName,
	}
	return r, nil
}
