package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

var roleRequestGroup singleflight.Group

func CacheRolePermissions(
	ctx context.Context,
	roleIdentifier string,
	cacheInstance cache.CacheInterface[[]byte],
	permissions Permissions,
	ttlCache time.Duration,
) error {
	if permissions == nil {
		return nil
	}

	cacheKey := RolePermissionsCacheKeyPrefix + roleIdentifier

	return setInCache(ctx, cacheInstance, cacheKey, permissions, ttlCache, func(p Permissions) ([]byte, error) {
		return json.Marshal(p)
	})
}

func GetRolePermissions(
	ctx context.Context,
	roleIdentifier string,
	rbacManager Manager,
) (Permissions, error) {
	cacheInstance, err := rbacManager.GetCache()
	if err != nil || cacheInstance == nil {
		zap.L().Warn("Cache instance unavailable, fetching role permissions directly from source")
		return rbacManager.GetRolePermissions(ctx, roleIdentifier)
	}

	cacheKey := RolePermissionsCacheKeyPrefix + roleIdentifier

	cachedPerms, found, err := fetchFromCache(ctx, cacheInstance, cacheKey, func(b []byte) (Permissions, error) {
		var p Permissions
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		return p, nil
	})

	if err != nil {
		zap.L().Warn("Failed to read role permissions from cache, will fetch from source", zap.Error(err))
		found = false
		cachedPerms = nil
	}

	if found {
		return cachedPerms, nil
	}

	singleFlightKey := RoleSingleFlightKeyPrefix + roleIdentifier
	result, err, _ := roleRequestGroup.Do(singleFlightKey, func() (interface{}, error) {
		sourcePerms, fetchErr := rbacManager.GetRolePermissions(ctx, roleIdentifier)
		if fetchErr != nil {
			return nil, fmt.Errorf("manager: failed to fetch role permissions for '%s': %w", roleIdentifier, fetchErr)
		}

		// Set only errors on marshaling errors, it wont fail on setting cache
		if cacheErr := CacheRolePermissions(ctx, roleIdentifier, cacheInstance, sourcePerms, rbacManager.GetRolePermissionsCacheTtl()); cacheErr != nil {
			return cacheErr, nil
		}

		return sourcePerms, nil
	})

	if err != nil {
		return nil, err
	}

	perms, ok := result.(Permissions)
	if !ok {
		return nil, fmt.Errorf("unexpected type from singleflight result for role permissions")
	}

	return perms, nil
}
