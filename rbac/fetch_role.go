package rbac

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetRolePermissions retrieves permissions for a specific role.
// It first checks the cache. If not found, it fetches from the rbacManager and caches the result as a JSON byte array.
func GetRolePermissions(
	ctx context.Context,
	roleIdentifier string,
	rbacManager Manager,
) (*Permissions, error) {
	cacheInstance, err := rbacManager.GetCache()
	if err != nil {
		return rbacManager.GetRolePermissions(ctx, roleIdentifier)
	}

	cacheKey := RolePermissionsCacheKeyPrefix + roleIdentifier

	// - Try fetch from cache
	perms, found, err := fetchFromCache(ctx, cacheInstance, cacheKey, func(s []byte) (*Permissions, error) {
		var p Permissions
		if err := json.Unmarshal(s, &p); err != nil {
			return nil, err
		}
		return &p, nil
	})
	if err != nil {
		return nil, err
	}
	if found {
		return perms, nil
	}

	// - Cache miss - get from manager
	sourcePerms, err := rbacManager.GetRolePermissions(ctx, roleIdentifier)
	if err != nil {
		return nil, fmt.Errorf("manager: failed to fetch role permissions for '%s': %w", roleIdentifier, err)
	}
	if sourcePerms == nil {
		return nil, nil
	}

	// - Cache the result asynchronously (optional, but cleaner)
	go func() {
		_ = setInCache(ctx, cacheInstance, cacheKey, sourcePerms, rbacManager.GetRolePermissionsCacheTtl(), func(p *Permissions) ([]byte, error) {
			return json.Marshal(p)
		})
	}()

	return sourcePerms, nil
}
