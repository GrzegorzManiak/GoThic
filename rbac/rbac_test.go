package rbac

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
)

var (
	readWrite = NewPermission(0)
	readOnly  = NewPermission(1)
)

type mockRbacManager struct {
	DefaultRBACManager
}

// GetCache returns a configured gocache CacheInterface instance. For mocking purposes, it returns nil as we
// dont want to use caching in tests.
func (rm *mockRbacManager) GetCache() (cache.CacheInterface[[]byte], error) {
	return nil, nil
}

func (rm *mockRbacManager) GetSubjectRolesAndPermissions(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
	if subjectIdentifier == "user-with-error" {
		return nil, nil, fmt.Errorf("database connection failed")
	}

	switch subjectIdentifier {
	case "admin-user":
		return Permissions{readOnly}, []string{"admin"}, nil
	case "readonly-user":
		return Permissions{}, []string{"user"}, nil
	}
	return Permissions{}, []string{}, nil
}

func (rm *mockRbacManager) GetRolePermissions(ctx context.Context, roleIdentifier string) (Permissions, error) {
	switch roleIdentifier {
	case "admin":
		return Permissions{readWrite}, nil
	case "user":
		return Permissions{readOnly}, nil
	}
	return Permissions{}, nil
}

type mockCache struct {
	data map[string][]byte
	err  error
}

func (m *mockCache) Get(_ context.Context, key any) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if val, ok := m.data[key.(string)]; ok {
		return val, nil
	}
	return nil, errors.New("not found")
}

func (m *mockCache) Set(_ context.Context, key any, value []byte, _ ...store.Option) error {
	if m.err != nil {
		return m.err
	}
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[key.(string)] = value
	return nil
}

func (m *mockCache) Delete(_ context.Context, _ any) error {
	return nil
}

func (m *mockCache) Clear(_ context.Context) error {
	return nil
}

func (m *mockCache) Invalidate(_ context.Context, _ ...store.InvalidateOption) error {
	return nil
}

func (m *mockCache) GetType() string {
	return "mock"
}

type mockRbacCacheManager struct {
	DefaultRBACManager
	getRolePermissionsFunc            func(ctx context.Context, roleIdentifier string) (Permissions, error)
	getSubjectRolesAndPermissionsFunc func(ctx context.Context, subjectIdentifier string) (Permissions, []string, error)
	cacheInstance                     cache.CacheInterface[[]byte]
	cacheError                        error
	roleCallCount                     int
	subjectCallCount                  int
	mu                                sync.Mutex
}

func (m *mockRbacCacheManager) GetCache() (cache.CacheInterface[[]byte], error) {
	if m.cacheError != nil {
		return nil, m.cacheError
	}
	return m.cacheInstance, nil
}

func (m *mockRbacCacheManager) GetSubjectRolesAndPermissions(ctx context.Context, subjectIdentifier string) (Permissions, []string, error) {
	m.mu.Lock()
	m.subjectCallCount++
	m.mu.Unlock()
	if m.getSubjectRolesAndPermissionsFunc != nil {
		return m.getSubjectRolesAndPermissionsFunc(ctx, subjectIdentifier)
	}
	return Permissions{readWrite}, []string{"admin"}, nil
}

func (m *mockRbacCacheManager) GetRolePermissions(ctx context.Context, roleIdentifier string) (Permissions, error) {
	m.mu.Lock()
	m.roleCallCount++
	m.mu.Unlock()
	if m.getRolePermissionsFunc != nil {
		return m.getRolePermissionsFunc(ctx, roleIdentifier)
	}
	return Permissions{readWrite}, nil
}
