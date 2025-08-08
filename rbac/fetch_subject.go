package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/eko/gocache/lib/v4/cache"
	"go.uber.org/zap"
	"sync"
)

func FetchSubjectPermissionsFromCache(
	ctx context.Context,
	rbacCacheId string,
	cacheInstance cache.CacheInterface[string],
) (*Permission, bool, error) {
	key := SubjectPermissionsCacheKeyPrefix + rbacCacheId
	return fetchFromCache(ctx, cacheInstance, key, func(s string) (*Permission, error) {
		return DeserializePermission(s)
	})
}

func FetchSubjectRolesFromCache(
	ctx context.Context,
	rbacCacheId string,
	cacheInstance cache.CacheInterface[string],
) (*[]string, bool, error) {
	key := SubjectRolesCacheKeyPrefix + rbacCacheId
	return fetchFromCache(ctx, cacheInstance, key, func(s string) (*[]string, error) {
		var roles []string
		if err := json.Unmarshal([]byte(s), &roles); err != nil {
			return nil, err
		}
		return &roles, nil
	})
}

func CacheRoles(
	ctx context.Context,
	rbacCacheId string,
	cacheInstance cache.CacheInterface[string],
	roles *[]string,
) error {
	if roles == nil {
		return nil
	}
	key := SubjectRolesCacheKeyPrefix + rbacCacheId
	return setInCache(ctx, cacheInstance, key, roles, DefaultRolePermissionsCacheTTL, func(v *[]string) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	})
}

func CachePermissions(
	ctx context.Context,
	rbacCacheId string,
	cacheInstance cache.CacheInterface[string],
	permissions *Permission,
) error {
	if permissions == nil {
		return nil
	}
	key := SubjectPermissionsCacheKeyPrefix + rbacCacheId
	return setInCache(ctx, cacheInstance, key, permissions, DefaultSubjectPermissionsCacheTTL, func(p *Permission) (string, error) {
		return p.Serialize(), nil
	})
}

func FetchSubjectRolesAndPermissions(
	ctx context.Context,
	subjectIdentifier string,
	rbacCacheId string,
	rbacManager Manager,
) (*Permission, *[]string, error) {
	cacheInstance, err := rbacManager.GetCache()
	if err != nil {
		zap.L().Warn("RBAC cache not available, fetching directly from manager", zap.Error(err))
		perms, roles, fetchErr := rbacManager.GetSubjectRolesAndPermissions(ctx, subjectIdentifier)
		if fetchErr != nil {
			return nil, nil, fmt.Errorf("manager: failed to fetch subject data for '%s': %w", rbacCacheId, fetchErr)
		}
		return perms.Flatten(), roles, nil
	}

	var (
		perms    *Permission
		roles    *[]string
		hitPerms bool
		hitRoles bool
		errPerms error
		errRoles error
		wg       sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		perms, hitPerms, errPerms = FetchSubjectPermissionsFromCache(ctx, rbacCacheId, cacheInstance)
	}()
	go func() {
		defer wg.Done()
		roles, hitRoles, errRoles = FetchSubjectRolesFromCache(ctx, rbacCacheId, cacheInstance)
	}()
	wg.Wait()

	if errPerms != nil {
		return nil, nil, errPerms
	}
	if errRoles != nil {
		return nil, nil, errRoles
	}
	if hitPerms && hitRoles {
		return perms, roles, nil
	}

	srcPerms, srcRoles, fetchErr := rbacManager.GetSubjectRolesAndPermissions(ctx, subjectIdentifier)
	if fetchErr != nil {
		return nil, nil, fmt.Errorf("manager: failed to fetch subject data for '%s': %w", rbacCacheId, fetchErr)
	}

	if err := CachePermissions(ctx, rbacCacheId, cacheInstance, srcPerms.Flatten()); err != nil {
		zap.L().Warn("RBAC: Failed to cache user permissions", zap.String("subjectIdentifier", subjectIdentifier), zap.String("rbacCacheId", rbacCacheId), zap.Error(err))
	}
	if err := CacheRoles(ctx, rbacCacheId, cacheInstance, srcRoles); err != nil {
		zap.L().Warn("RBAC: Failed to cache user roles", zap.String("subjectIdentifier", subjectIdentifier), zap.String("rbacCacheId", rbacCacheId), zap.Error(err))
	}

	return srcPerms.Flatten(), srcRoles, nil
}
