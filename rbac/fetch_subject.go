package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

var subjectRequestGroup singleflight.Group

func FetchSubjectPermissionsFromCache(ctx context.Context, rbacCacheId string, cacheInstance cache.CacheInterface[[]byte]) (*Permission, bool, error) {
	key := SubjectPermissionsCacheKeyPrefix + rbacCacheId
	return fetchFromCache(ctx, cacheInstance, key, func(b []byte) (*Permission, error) {
		p := new(Permission)
		err := p.UnmarshalBinary(b)
		return p, err
	})
}

func FetchSubjectRolesFromCache(ctx context.Context, rbacCacheId string, cacheInstance cache.CacheInterface[[]byte]) ([]string, bool, error) {
	key := SubjectRolesCacheKeyPrefix + rbacCacheId
	return fetchFromCache(ctx, cacheInstance, key, func(b []byte) ([]string, error) {
		var roles []string
		if err := json.Unmarshal(b, &roles); err != nil {
			return nil, err
		}
		return roles, nil
	})
}

func CacheRoles(ctx context.Context, rbacCacheId string, cacheInstance cache.CacheInterface[[]byte], roles []string, ttl time.Duration) error {
	if roles == nil {
		return nil
	}
	key := SubjectRolesCacheKeyPrefix + rbacCacheId
	return setInCache(ctx, cacheInstance, key, roles, ttl, func(v []string) ([]byte, error) {
		return json.Marshal(v)
	})
}

func CachePermissions(ctx context.Context, rbacCacheId string, cacheInstance cache.CacheInterface[[]byte], permissions *Permission, ttl time.Duration) error {
	if permissions == nil {
		return nil
	}
	key := SubjectPermissionsCacheKeyPrefix + rbacCacheId
	return setInCache(ctx, cacheInstance, key, permissions, ttl, func(v *Permission) ([]byte, error) {
		return v.MarshalBinary()
	})
}

func FetchSubjectRolesAndPermissions(
	ctx context.Context,
	subjectIdentifier string,
	rbacCacheId string,
	rbacManager Manager,
) (*Permission, []string, error) {
	cacheInstance, err := rbacManager.GetCache()
	if err != nil || cacheInstance == nil {
		zap.L().Warn("Cache instance unavailable, fetching subject roles and permissions directly from source")
		perms, roles, fetchErr := rbacManager.GetSubjectRolesAndPermissions(ctx, subjectIdentifier)
		if fetchErr != nil {
			return nil, nil, fmt.Errorf("manager: failed to fetch subject data for '%s': %w", subjectIdentifier, fetchErr)
		}
		return perms.Flatten(), roles, nil
	}

	var (
		perms    *Permission
		roles    []string
		hitPerms bool
		hitRoles bool
		wg       sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		var errPerms error
		perms, hitPerms, errPerms = FetchSubjectPermissionsFromCache(ctx, rbacCacheId, cacheInstance)
		if errPerms != nil {
			zap.L().Warn("Failed to read permissions from cache", zap.Error(errPerms))
			hitPerms = false
			perms = nil
		}
	}()
	go func() {
		defer wg.Done()
		var errRoles error
		roles, hitRoles, errRoles = FetchSubjectRolesFromCache(ctx, rbacCacheId, cacheInstance)
		if errRoles != nil {
			zap.L().Warn("Failed to read roles from cache", zap.Error(errRoles))
			hitRoles = false
			roles = nil
		}
	}()
	wg.Wait()

	if hitPerms && hitRoles {
		return perms, roles, nil
	}

	type subjectData struct {
		Permissions Permissions
		Roles       []string
	}

	singleFlightKey := SubjectSingleFlightKeyPrefix + rbacCacheId
	result, err, _ := subjectRequestGroup.Do(singleFlightKey, func() (interface{}, error) {
		srcPerms, srcRoles, fetchErr := rbacManager.GetSubjectRolesAndPermissions(ctx, subjectIdentifier)
		if fetchErr != nil {
			return nil, fetchErr
		}

		if cacheErr := CachePermissions(ctx, rbacCacheId, cacheInstance, srcPerms.Flatten(), rbacManager.GetSubjectPermissionsCacheTtl()); cacheErr != nil {
			zap.L().Warn(fmt.Sprintf("Failed to cache subject permissions for '%s'", subjectIdentifier), zap.Error(cacheErr))
		}

		if cacheErr := CacheRoles(ctx, rbacCacheId, cacheInstance, srcRoles, rbacManager.GetSubjectRolesCacheTtl()); cacheErr != nil {
			zap.L().Warn(fmt.Sprintf("Failed to cache subject roles for '%s'", subjectIdentifier), zap.Error(cacheErr))
		}

		return subjectData{Permissions: srcPerms, Roles: srcRoles}, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("manager: failed to fetch subject data for '%s': %w", subjectIdentifier, err)
	}

	data, ok := result.(subjectData)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected type from singleflight result")
	}

	return data.Permissions.Flatten(), data.Roles, nil
}
