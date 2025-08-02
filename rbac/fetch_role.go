package rbac

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/eko/gocache/lib/v4/store"
)

// GetRolePermissions retrieves permissions for a specific role.
// It first checks the cache. If not found, it fetches from the rbacManager and caches the result as a JSON byte array.
func GetRolePermissions(
	ctx context.Context,
	roleIdentifier string,
	rbacManager Manager,
) (Permissions, error) {
	cacheInstance, cacheErr := rbacManager.GetCache()
	if cacheErr != nil {
		return rbacManager.GetRolePermissions(ctx, roleIdentifier)
	}

	cacheKey := fmt.Sprintf("%s%s", RolePermissionsCacheKeyPrefix, roleIdentifier)

	cachedString, err := cacheInstance.Get(ctx, cacheKey)
	if err == nil {
		var permissions Permissions
		if jsonErr := json.Unmarshal([]byte(cachedString), &permissions); jsonErr != nil {
			return nil, fmt.Errorf("cache: failed to unmarshal cached permissions for role '%s': %w", roleIdentifier, jsonErr)
		}
		return permissions, nil
	}

	sourcePermissions, fetchErr := rbacManager.GetRolePermissions(ctx, roleIdentifier)
	if fetchErr != nil {
		return nil, fmt.Errorf("manager: failed to fetch role permissions for '%s': %w", roleIdentifier, fetchErr)
	}

	if sourcePermissions != nil {
		permsBytesToCache, jsonErr := json.Marshal(sourcePermissions)
		if jsonErr != nil {
			return nil, fmt.Errorf("cache: failed to marshal permissions for caching for role '%s': %w", roleIdentifier, jsonErr)
		}
		cacheTTL := rbacManager.GetRolePermissionsCacheTtl()
		if errSet := cacheInstance.Set(ctx, cacheKey, string(permsBytesToCache), store.WithExpiration(cacheTTL)); errSet != nil {
			return nil, fmt.Errorf("cache: failed to set permissions in cache for role '%s': %w", roleIdentifier, errSet)
		}
	}

	return sourcePermissions, nil
}
