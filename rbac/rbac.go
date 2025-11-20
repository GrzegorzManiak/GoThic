package rbac

import (
	"context"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	internalcache "github.com/grzegorzmaniak/gothic/cache"
	"github.com/grzegorzmaniak/gothic/helpers"
)

const (
	DefaultSubjectPermissionsCacheTTL = 1 * time.Minute
	DefaultRolePermissionsCacheTTL    = 3 * time.Minute
)

const (
	RolePermissionsCacheKeyPrefix    = "role_perms:"    // Key: role_perms:<roleIdentifier>
	SubjectRolesCacheKeyPrefix       = "subject_roles:" // Key: subject_roles:<subjectIdentifier>
	SubjectPermissionsCacheKeyPrefix = "subject_perms:" // Key: subject_perms:<subjectIdentifier>
	SubjectSingleFlightKeyPrefix     = "subject_sf:"    // Key: subject_sf:<subjectIdentifier>
	RoleSingleFlightKeyPrefix        = "role_sf:"       // Key: role_sf:<roleIdentifier>
)

type RouteRbacPolicy uint16

// Note: I chose to use 'PermissionsOrRole' and 'PermissionsOrAllRoles' instead of 'PermissionsOrRole' and 'PermissionsOrRoles'
// as it would be very easy to confuse the two and create a security vulnerability.
const (
	// PermissionsOrRole requires that the sessions have either ALL permissions or ONE of the roles
	PermissionsOrRole RouteRbacPolicy = 1 << iota

	// PermissionsOrAllRoles requires that the sessions have ALL permissions AND ALL roles
	PermissionsOrAllRoles

	// PermissionsAndRole requires that the sessions have ALL permissions AND at least ONE of the roles
	PermissionsAndRole

	// PermissionsAndAllRoles requires that the sessions have ALL permissions AND ALL roles
	PermissionsAndAllRoles

	// PermissionsOnly requires that the sessions have ALL permissions (skips role check)
	PermissionsOnly

	// RoleOnly requires that the sessions have at least ONE of the roles (skips permission check)
	RoleOnly
)

type Manager interface {
	// GetSubjectRolesAndPermissions gets the permissions and roles for a specific subject.
	GetSubjectRolesAndPermissions(ctx context.Context, subjectIdentifier string) (Permissions, []string, error)

	// GetRolePermissions gets all the permissions associated with a specific role.
	GetRolePermissions(ctx context.Context, roleIdentifier string) (Permissions, error)

	// GetCache returns a configured gocache CacheInterface instance.
	// This cache is used internally by the Manager for optimizing RBAC data retrieval (e.g., caching role-permission mappings or subject roles)
	GetCache() (cache.CacheInterface[[]byte], error)

	// GetSubjectPermissionsCacheTtl returns the TTL for subject-specific permission entries in the cache.
	GetSubjectPermissionsCacheTtl() time.Duration

	// GetSubjectRolesCacheTtl returns the TTL for subject-specific role entries in the cache.
	GetSubjectRolesCacheTtl() time.Duration

	// GetRolePermissionsCacheTtl returns the TTL for role-specific permission entries in the cache.
	GetRolePermissionsCacheTtl() time.Duration
}

// DefaultRBACManagerConfig allows configuration for the Ristretto cache and TTLs.
type DefaultRBACManagerConfig struct {

	// UserPermissionsCacheTTL is the Time-To-Live for user-specific permission entries in the cache.
	UserPermissionsCacheTTL time.Duration

	// UserRolesCacheTTL is the Time-To-Live for user-specific role entries in the cache.
	UserRolesCacheTTL time.Duration

	// RolePermissionsCacheTTL is the Time-To-Live for role-specific permission entries in the cache.
	RolePermissionsCacheTTL time.Duration
}

// DefaultRBACManager is an implementation of the Manager interface that provides
// a built-in Ristretto instance for caching permissions.
type DefaultRBACManager struct {
	internalcache.DefaultCacheManager
	DefaultRBACManagerConfig
}

func (m *DefaultRBACManager) GetSubjectPermissionsCacheTtl() time.Duration {
	return helpers.DefaultTimeDuration(m.UserPermissionsCacheTTL, DefaultSubjectPermissionsCacheTTL)
}

func (m *DefaultRBACManager) GetSubjectRolesCacheTtl() time.Duration {
	return helpers.DefaultTimeDuration(m.UserRolesCacheTTL, DefaultSubjectPermissionsCacheTTL)
}

func (m *DefaultRBACManager) GetRolePermissionsCacheTtl() time.Duration {
	return helpers.DefaultTimeDuration(m.RolePermissionsCacheTTL, DefaultRolePermissionsCacheTTL)
}
