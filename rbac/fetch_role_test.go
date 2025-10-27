package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	internalcache "github.com/grzegorzmaniak/gothic/cache"
)

func TestGetRolePermissions(t *testing.T) {
	ctx := context.Background()

	t.Run("Cache miss, successful fetch, cache population, cache hit", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, err := cacheManager.GetCache()
		if err != nil {
			t.Fatalf("Failed to initialize cache: %v", err)
		}

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
				DefaultRBACManagerConfig: DefaultRBACManagerConfig{
					RolePermissionsCacheTTL: 500 * time.Millisecond,
				},
			},
			cacheInstance: cacheInstance,
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				return Permissions{readWrite}, nil
			},
		}

		// First call: cache miss, should fetch from manager
		perms, err := GetRolePermissions(ctx, "admin", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if perms == nil || len(perms) == 0 {
			t.Fatal("Expected permissions, got none")
		}
		if mockMgr.roleCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.roleCallCount)
		}

		// Sleep briefly to ensure cache write completes
		time.Sleep(10 * time.Millisecond)

		// Second call: cache hit, should not call manager
		perms2, err := GetRolePermissions(ctx, "admin", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error on cache hit, got %v", err)
		}
		if perms2 == nil {
			t.Fatal("Expected cached permissions, got none")
		}
		if mockMgr.roleCallCount != 1 {
			t.Errorf("Expected still 1 manager call (cache hit), got %d", mockMgr.roleCallCount)
		}
	})

	t.Run("Manager returns error", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, _ := cacheManager.GetCache()

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				return nil, errors.New("database error")
			},
		}

		_, err := GetRolePermissions(ctx, "admin", mockMgr)
		if err == nil {
			t.Fatal("Expected error from manager, got none")
		}
	})

	t.Run("Cache initialization error falls back to manager", func(t *testing.T) {
		mockMgr := &mockRbacCacheManager{
			cacheError: errors.New("cache init error"),
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				return Permissions{readOnly}, nil
			},
		}

		// `Saturate` the cache
		perms, err := GetRolePermissions(ctx, "user", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with cache fallback, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager, got none")
		}
		if mockMgr.roleCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.roleCallCount)
		}

		// Call again to ensure consistent behavior
		perms, err = GetRolePermissions(ctx, "user", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error on second call with cache fallback, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager on second call, got none")
		}
		if mockMgr.roleCallCount != 2 {
			t.Errorf("Expected 2 manager calls after two attempts, got %d", mockMgr.roleCallCount)
		}
	})

	t.Run("Concurrent requests use singleflight", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, err := cacheManager.GetCache()

		if err != nil {
			t.Fatalf("Failed to initialize cache: %v", err)
		}

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				time.Sleep(50 * time.Millisecond)
				return Permissions{readWrite}, nil
			},
		}

		var wg sync.WaitGroup
		numConcurrent := 10
		results := make([]Permissions, numConcurrent)
		errors := make([]error, numConcurrent)

		for i := 0; i < numConcurrent; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx], errors[idx] = GetRolePermissions(ctx, "concurrent-role", mockMgr)
			}(i)
		}

		wg.Wait()

		// Verify all requests succeeded
		for i := 0; i < numConcurrent; i++ {
			if errors[i] != nil {
				t.Errorf("Request %d failed: %v", i, errors[i])
			}
			if results[i] == nil {
				t.Errorf("Request %d got nil permissions", i)
			}
		}

		// Singleflight should ensure only 1 manager call
		if mockMgr.roleCallCount != 1 {
			t.Errorf("Expected 1 manager call due to singleflight, got %d", mockMgr.roleCallCount)
		}
	})

	t.Run("Corrupted cache data falls back to manager", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, err := cacheManager.GetCache()

		if err != nil {
			t.Fatalf("Failed to initialize cache: %v", err)
		}

		// Pre-populate cache with corrupted data
		corruptCacheKey := RolePermissionsCacheKeyPrefix + "corrupted-role"
		_ = setInCache(ctx, cacheInstance, corruptCacheKey, []byte("not-a-valid-json"), 1*time.Minute, nil)

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				return Permissions{readOnly}, nil
			},
		}

		perms, err := GetRolePermissions(ctx, "corrupted-role", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with corrupted cache fallback, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager after cache corruption, got none")
		}
		if mockMgr.roleCallCount != 1 {
			t.Errorf("Expected 1 manager call after cache corruption, got %d", mockMgr.roleCallCount)
		}
	})

	t.Run("Multiple roles cached independently", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, _ := cacheManager.GetCache()

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				if roleIdentifier == "role1" {
					return Permissions{readWrite}, nil
				}
				return Permissions{readOnly}, nil
			},
		}

		perms1, _ := GetRolePermissions(ctx, "role1", mockMgr)
		perms2, _ := GetRolePermissions(ctx, "role2", mockMgr)

		if mockMgr.roleCallCount != 2 {
			t.Errorf("A: Expected 2 manager calls for different roles, got %d", mockMgr.roleCallCount)
		}

		time.Sleep(10 * time.Millisecond)

		perms1Again, _ := GetRolePermissions(ctx, "role1", mockMgr)
		perms2Again, _ := GetRolePermissions(ctx, "role2", mockMgr)

		if mockMgr.roleCallCount != 2 {
			t.Errorf("B: Expected still 2 manager calls (both cached), got %d", mockMgr.roleCallCount)
		}

		if perms1 == nil || perms2 == nil || perms1Again == nil || perms2Again == nil {
			t.Fatal("Expected all permissions to be valid")
		}
	})

	t.Run("Nil cache instance falls back to manager", func(t *testing.T) {
		mockMgr := &mockRbacCacheManager{
			cacheInstance: nil,
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				return Permissions{readWrite}, nil
			},
		}

		perms, err := GetRolePermissions(ctx, "admin", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with nil cache, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager, got none")
		}
		if mockMgr.roleCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.roleCallCount)
		}
	})

	t.Run("Cache TTL respected", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, _ := cacheManager.GetCache()

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
				DefaultRBACManagerConfig: DefaultRBACManagerConfig{
					RolePermissionsCacheTTL: 50 * time.Millisecond,
				},
			},
			cacheInstance: cacheInstance,
			getRolePermissionsFunc: func(ctx context.Context, roleIdentifier string) (Permissions, error) {
				return Permissions{readWrite}, nil
			},
		}

		// First call populates cache
		_, _ = GetRolePermissions(ctx, "ttl-test", mockMgr)
		if mockMgr.roleCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.roleCallCount)
		}

		// Wait for TTL to expire
		time.Sleep(100 * time.Millisecond)

		_, _ = GetRolePermissions(ctx, "ttl-test", mockMgr)
		if mockMgr.roleCallCount != 2 {
			t.Logf("Cached value was not expired as expected, got %d manager calls", mockMgr.roleCallCount)
		}
	})
}
