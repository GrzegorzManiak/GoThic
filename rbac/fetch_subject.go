package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	"go.uber.org/zap"
	"sync"
)

func FetchSubjectRoles(
	ctx context.Context,
	rbacCacheId string,
	cacheInstance cache.CacheInterface[string],
) (permissions *[]Permission, cacheHit bool, err error) {
	userPermsKey := fmt.Sprintf("%s%s", SubjectPermissionsCacheKeyPrefix, rbacCacheId)
	cachedPermsString, getErr := cacheInstance.Get(ctx, userPermsKey)

	if getErr != nil {
		// - Cache miss, fetch from rbacManager
		return nil, false, nil
	}

	// - Cache hit, unmarshal JSON bytes
	p := &[]Permission{}
	if jsonErr := json.Unmarshal([]byte(cachedPermsString), p); jsonErr != nil {
		return nil, false, fmt.Errorf("cache A: failed to unmarshal cached permissions for '%s': %w", rbacCacheId, jsonErr)
	}

	// - Check if permissions are nil (or empty) and return them
	return p, true, nil
}

func FetchSubjectRolesFromCache(
	ctx context.Context,
	rbacCacheId string,
	cacheInstance cache.CacheInterface[string],
) (roles *[]string, cacheHit bool, err error) {
	userRolesKey := fmt.Sprintf("%s%s", SubjectRolesCacheKeyPrefix, rbacCacheId)
	cachedRolesString, getErr := cacheInstance.Get(ctx, userRolesKey)

	if getErr != nil {
		// - Cache miss, fetch from rbacManager
		return nil, false, nil
	}

	// - Cache hit, unmarshal JSON bytes
	r := &[]string{}
	if jsonErr := json.Unmarshal([]byte(cachedRolesString), r); jsonErr != nil {
		return nil, false, fmt.Errorf("cache A: failed to unmarshal cached roles for '%s': %w", rbacCacheId, jsonErr)
	}

	// - Check if permissions are nil (or empty) and return them
	return r, true, nil
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

	// - Marshal the roles slice into JSON bytes
	rolesBytes, jsonErr := json.Marshal(roles)
	if jsonErr != nil {
		return fmt.Errorf("cache: failed to marshal roles for caching for '%s': %w", rbacCacheId, jsonErr)
	}

	// - Set the cache with the role bytes
	cacheTTL := DefaultRolePermissionsCacheTTL
	userRolesKey := fmt.Sprintf("%s%s", SubjectRolesCacheKeyPrefix, rbacCacheId)
	if errSet := cacheInstance.Set(ctx, userRolesKey, string(rolesBytes), store.WithExpiration(cacheTTL)); errSet != nil {
		return fmt.Errorf("cache: failed to set roles in cache for '%s': %w", rbacCacheId, errSet)
	}

	return nil
}

func CachePermissions(
	ctx context.Context,
	rbacCacheId string,
	cacheInstance cache.CacheInterface[string],
	permissions *[]Permission,
) error {
	if permissions == nil {
		return nil
	}

	// - Marshal the permissions slice into JSON bytes
	permsBytes, jsonErr := json.Marshal(permissions)
	if jsonErr != nil {
		return fmt.Errorf("cache: failed to marshal permissions for caching for '%s': %w", rbacCacheId, jsonErr)
	}

	// - Set the cache with the permissions bytes
	cacheTTL := DefaultSubjectPermissionsCacheTTL
	userPermsKey := fmt.Sprintf("%s%s", SubjectPermissionsCacheKeyPrefix, rbacCacheId)
	if errSet := cacheInstance.Set(ctx, userPermsKey, string(permsBytes), store.WithExpiration(cacheTTL)); errSet != nil {
		return fmt.Errorf("cache: failed to set permissions in cache for '%s': %w", rbacCacheId, errSet)
	}

	return nil
}

// FetchSubjectRolesAndPermissions retrieves a subject's roles and direct permissions.
// It first checks the cache for both. If not found, it fetches from the rbacManager
// and caches the results as JSON byte arrays.
func FetchSubjectRolesAndPermissions(
	ctx context.Context,
	subjectIdentifier string,
	rbacCacheId string,
	rbacManager Manager,
) (permissions *[]Permission, roles *[]string, err error) {
	cacheInstance, cacheErr := rbacManager.GetCache()

	// - Fallback on always fetching from the rbacManager if cache is not available.
	if cacheErr != nil {
		zap.L().Warn("RBAC cache not available, fetching directly from manager", zap.Error(cacheErr))
		return rbacManager.GetSubjectRolesAndPermissions(ctx, subjectIdentifier)
	}

	var (
		loadedPermissions *[]Permission
		loadedRoles       *[]string
		foundPermsInCache bool
		foundRolesInCache bool
		wg                sync.WaitGroup
		permsCacheErr     error
		rolesCacheErr     error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		loadedPermissions, foundPermsInCache, permsCacheErr =
			FetchSubjectRoles(ctx, rbacCacheId, cacheInstance)
	}()

	go func() {
		defer wg.Done()
		loadedRoles, foundRolesInCache, rolesCacheErr =
			FetchSubjectRolesFromCache(ctx, rbacCacheId, cacheInstance)
	}()
	wg.Wait()

	// - If there was an error while fetching permissions from cache, return the error.
	if permsCacheErr != nil {
		return nil, nil, permsCacheErr
	}

	// - If there was an error while fetching roles from cache, return the error.
	if rolesCacheErr != nil {
		return nil, nil, rolesCacheErr
	}

	// - If both permissions and roles were successfully found and unmarshalled from cache, return them.
	if foundPermsInCache && foundRolesInCache {
		return loadedPermissions, loadedRoles, nil
	}

	// - If one or both items were not in cache, fetch from the rbacManager.
	// This call fetches both permissions and roles from the source of truth.
	sourcePermissions, sourceRoles, fetchErr := rbacManager.GetSubjectRolesAndPermissions(ctx, subjectIdentifier)
	if fetchErr != nil {
		return nil, nil, fmt.Errorf("manager: failed to fetch subject data for '%s': %w", rbacCacheId, fetchErr)
	}

	// - Cache the fetched permissions and roles for future use.
	if err := CachePermissions(ctx, rbacCacheId, cacheInstance, sourcePermissions); err != nil {
		zap.L().Warn("RBAC: Failed to cache user permissions",
			zap.String("subjectIdentifier", subjectIdentifier),
			zap.String("rbacCacheId", rbacCacheId),
			zap.Error(err))
	}

	if err := CacheRoles(ctx, rbacCacheId, cacheInstance, sourceRoles); err != nil {
		zap.L().Warn("RBAC: Failed to cache user roles",
			zap.String("subjectIdentifier", subjectIdentifier),
			zap.String("rbacCacheId", rbacCacheId),
			zap.Error(err))
	}

	return sourcePermissions, sourceRoles, nil
}
