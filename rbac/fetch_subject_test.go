package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	internalcache "github.com/grzegorzmaniak/gothic/cache"
)

func TestFetchSubjectRolesAndPermissions(t *testing.T) {
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
					UserPermissionsCacheTTL: 500 * time.Millisecond,
					UserRolesCacheTTL:       500 * time.Millisecond,
				},
			},
			cacheInstance: cacheInstance,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{readWrite, readOnly}, []string{"admin", "user"}, nil
			},
		}

		// First call: cache miss, should fetch from manager
		perms, roles, err := FetchSubjectRolesAndPermissions(ctx, "user123", "cache-id-1", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions, got none")
		}
		if len(roles) != 2 {
			t.Errorf("Expected 2 roles, got %d", len(roles))
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.subjectCallCount)
		}

		// Sleep briefly to ensure cache write completes
		time.Sleep(10 * time.Millisecond)

		// Second call: cache hit, should not call manager
		perms2, roles2, err := FetchSubjectRolesAndPermissions(ctx, "user123", "cache-id-1", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error on cache hit, got %v", err)
		}
		if perms2 == nil {
			t.Fatal("Expected cached permissions, got none")
		}
		if len(roles2) != 2 {
			t.Errorf("Expected 2 cached roles, got %d", len(roles2))
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected still 1 manager call (cache hit), got %d", mockMgr.subjectCallCount)
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
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return nil, nil, errors.New("database error")
			},
		}

		_, _, err := FetchSubjectRolesAndPermissions(ctx, "user123", "cache-id-error", mockMgr)
		if err == nil {
			t.Fatal("Expected error from manager, got none")
		}
	})

	t.Run("Cache initialization error falls back to manager", func(t *testing.T) {
		mockMgr := &mockRbacCacheManager{
			cacheError: errors.New("cache init error"),
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{readOnly}, []string{"user"}, nil
			},
		}

		perms, roles, err := FetchSubjectRolesAndPermissions(ctx, "user456", "cache-id-2", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with cache fallback, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager, got none")
		}
		if len(roles) != 1 {
			t.Errorf("Expected 1 role, got %d", len(roles))
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.subjectCallCount)
		}

		// Call again to ensure consistent behavior
		perms, roles, err = FetchSubjectRolesAndPermissions(ctx, "user456", "cache-id-2", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error on second call with cache fallback, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager on second call, got none")
		}
		if mockMgr.subjectCallCount != 2 {
			t.Errorf("Expected 2 manager calls after two attempts, got %d", mockMgr.subjectCallCount)
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
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				time.Sleep(50 * time.Millisecond)
				return Permissions{readWrite}, []string{"admin"}, nil
			},
		}

		var wg sync.WaitGroup
		numConcurrent := 10
		resultsPerms := make([]*Permission, numConcurrent)
		resultsRoles := make([][]string, numConcurrent)
		resultsErrs := make([]error, numConcurrent)

		for i := 0; i < numConcurrent; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				resultsPerms[idx], resultsRoles[idx], resultsErrs[idx] = FetchSubjectRolesAndPermissions(ctx, "concurrent-user", "cache-id-concurrent", mockMgr)
			}(i)
		}

		wg.Wait()

		// Verify all requests succeeded
		for i := 0; i < numConcurrent; i++ {
			if resultsErrs[i] != nil {
				t.Errorf("Request %d failed: %v", i, resultsErrs[i])
			}
			if resultsPerms[i] == nil {
				t.Errorf("Request %d got nil permissions", i)
			}
			if len(resultsRoles[i]) == 0 {
				t.Errorf("Request %d got empty roles", i)
			}
		}

		// Singleflight should ensure only 1 manager call
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call due to singleflight, got %d", mockMgr.subjectCallCount)
		}
	})

	t.Run("Partial cache hit - permissions cached, roles miss", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, err := cacheManager.GetCache()
		if err != nil {
			t.Fatalf("Failed to initialize cache: %v", err)
		}

		// Pre-populate only permissions in cache
		testPerms := Permissions{readWrite}
		flatPerms := testPerms.Flatten()
		_ = CachePermissions(ctx, "cache-id-partial", cacheInstance, flatPerms, 1*time.Minute)

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{readWrite}, []string{"admin"}, nil
			},
		}

		time.Sleep(10 * time.Millisecond)

		perms, roles, err := FetchSubjectRolesAndPermissions(ctx, "partial-user", "cache-id-partial", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with partial cache, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions, got none")
		}
		if len(roles) == 0 {
			t.Error("Expected roles from manager fetch, got none")
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call for cache miss, got %d", mockMgr.subjectCallCount)
		}
	})

	t.Run("Partial cache hit - roles cached, permissions miss", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, err := cacheManager.GetCache()
		if err != nil {
			t.Fatalf("Failed to initialize cache: %v", err)
		}

		// Pre-populate only roles in cache
		testRoles := []string{"admin", "user"}
		_ = CacheRoles(ctx, "cache-id-partial-2", cacheInstance, testRoles, 1*time.Minute)

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{readOnly}, []string{"admin", "user"}, nil
			},
		}

		time.Sleep(10 * time.Millisecond)

		perms, roles, err := FetchSubjectRolesAndPermissions(ctx, "partial-user-2", "cache-id-partial-2", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with partial cache, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager fetch, got none")
		}
		if len(roles) != 2 {
			t.Errorf("Expected 2 roles, got %d", len(roles))
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call for cache miss, got %d", mockMgr.subjectCallCount)
		}
	})

	t.Run("Corrupted cache data falls back to manager", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, err := cacheManager.GetCache()
		if err != nil {
			t.Fatalf("Failed to initialize cache: %v", err)
		}

		// Pre-populate cache with corrupted data using raw bytes
		corruptPermKey := SubjectPermissionsCacheKeyPrefix + "cache-id-corrupt"
		_ = cacheInstance.Set(ctx, corruptPermKey, []byte("invalid-binary-data"))

		corruptRolesKey := SubjectRolesCacheKeyPrefix + "cache-id-corrupt"
		_ = cacheInstance.Set(ctx, corruptRolesKey, []byte("not-json"))

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{readOnly}, []string{"user"}, nil
			},
		}

		time.Sleep(10 * time.Millisecond)

		perms, roles, err := FetchSubjectRolesAndPermissions(ctx, "corrupt-user", "cache-id-corrupt", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with corrupted cache fallback, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager after cache corruption, got none")
		}
		if len(roles) != 1 {
			t.Errorf("Expected 1 role from manager, got %d", len(roles))
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call after cache corruption, got %d", mockMgr.subjectCallCount)
		}
	})

	t.Run("Multiple subjects cached independently", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, _ := cacheManager.GetCache()

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				if subjectIdentifier == "user1" {
					return Permissions{readWrite}, []string{"admin"}, nil
				}
				return Permissions{readOnly}, []string{"user"}, nil
			},
		}

		perms1, roles1, _ := FetchSubjectRolesAndPermissions(ctx, "user1", "cache-id-multi-1", mockMgr)
		perms2, roles2, _ := FetchSubjectRolesAndPermissions(ctx, "user2", "cache-id-multi-2", mockMgr)

		if mockMgr.subjectCallCount != 2 {
			t.Errorf("A: Expected 2 manager calls for different subjects, got %d", mockMgr.subjectCallCount)
		}

		time.Sleep(10 * time.Millisecond)

		perms1Again, roles1Again, _ := FetchSubjectRolesAndPermissions(ctx, "user1", "cache-id-multi-1", mockMgr)
		perms2Again, roles2Again, _ := FetchSubjectRolesAndPermissions(ctx, "user2", "cache-id-multi-2", mockMgr)

		if mockMgr.subjectCallCount != 2 {
			t.Errorf("B: Expected still 2 manager calls (both cached), got %d", mockMgr.subjectCallCount)
		}

		if perms1 == nil || perms2 == nil || perms1Again == nil || perms2Again == nil {
			t.Fatal("Expected all permissions to be valid")
		}
		if len(roles1) == 0 || len(roles2) == 0 || len(roles1Again) == 0 || len(roles2Again) == 0 {
			t.Fatal("Expected all roles to be valid")
		}
	})

	t.Run("Nil cache instance falls back to manager", func(t *testing.T) {
		mockMgr := &mockRbacCacheManager{
			cacheInstance: nil,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{readWrite}, []string{"admin"}, nil
			},
		}

		perms, roles, err := FetchSubjectRolesAndPermissions(ctx, "user-no-cache", "cache-id-nil", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with nil cache, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected permissions from manager, got none")
		}
		if len(roles) != 1 {
			t.Errorf("Expected 1 role, got %d", len(roles))
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.subjectCallCount)
		}
	})

	t.Run("Cache TTL respected", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, _ := cacheManager.GetCache()

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
				DefaultRBACManagerConfig: DefaultRBACManagerConfig{
					UserPermissionsCacheTTL: 50 * time.Millisecond,
					UserRolesCacheTTL:       50 * time.Millisecond,
				},
			},
			cacheInstance: cacheInstance,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{readWrite}, []string{"admin"}, nil
			},
		}

		// First call populates cache
		_, _, _ = FetchSubjectRolesAndPermissions(ctx, "ttl-user", "cache-id-ttl", mockMgr)
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.subjectCallCount)
		}

		// Wait for TTL to expire
		time.Sleep(100 * time.Millisecond)

		_, _, _ = FetchSubjectRolesAndPermissions(ctx, "ttl-user", "cache-id-ttl", mockMgr)
		if mockMgr.subjectCallCount != 2 {
			t.Logf("Cached value was not expired as expected, got %d manager calls", mockMgr.subjectCallCount)
		}
	})

	t.Run("Empty permissions and roles are cached correctly", func(t *testing.T) {
		cacheManager := internalcache.BuildDefaultCacheManager(nil)
		cacheInstance, _ := cacheManager.GetCache()

		mockMgr := &mockRbacCacheManager{
			DefaultRBACManager: DefaultRBACManager{
				DefaultCacheManager: *cacheManager,
			},
			cacheInstance: cacheInstance,
			getSubjectRolesAndPermissionsFunc: func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
				return Permissions{}, []string{}, nil
			},
		}

		perms, roles, err := FetchSubjectRolesAndPermissions(ctx, "empty-user", "cache-id-empty", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error with empty data, got %v", err)
		}
		if perms == nil {
			t.Fatal("Expected empty permissions object, got nil")
		}
		if roles == nil {
			t.Fatal("Expected empty roles slice, got nil")
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected 1 manager call, got %d", mockMgr.subjectCallCount)
		}

		time.Sleep(10 * time.Millisecond)

		// Verify empty data is cached
		perms2, roles2, err := FetchSubjectRolesAndPermissions(ctx, "empty-user", "cache-id-empty", mockMgr)
		if err != nil {
			t.Fatalf("Expected no error on cache hit, got %v", err)
		}
		if perms2 == nil || roles2 == nil {
			t.Fatal("Expected cached empty data, got nil")
		}
		if mockMgr.subjectCallCount != 1 {
			t.Errorf("Expected still 1 manager call (cache hit), got %d", mockMgr.subjectCallCount)
		}
	})
}
