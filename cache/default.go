package cache

import (
	"fmt"
	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	ristrettoStore "github.com/eko/gocache/store/ristretto/v4"
	"github.com/grzegorzmaniak/gothic/helpers"
	"go.uber.org/zap"
	"sync"
	"time"
)

const (
	DefaultRistrettoMaxCost                   = 1000000
	DefaultRistrettoNumCounters               = DefaultRistrettoMaxCost * 10
	DefaultRistrettoBufferItems               = 64
	DefaultStoreExpirationForRistrettoAdapter = 5 * time.Minute
)

type DefaultCacheConfig struct {

	// RistrettoMaxCost defines the maximum "cost" for the Ristretto cache.
	// If items have a default cost of 1, this is effectively the max number of items.
	// If 0, a library default (e.g., 1,000,000) will be used.
	RistrettoMaxCost int64

	// RistrettoNumCounters determines the number of counters for Ristretto's admission/eviction policy.
	// A common rule of thumb is 10 * MaxCost.
	// If 0, it will be derived from MaxCost or a library default.
	RistrettoNumCounters int64

	// RistrettoBufferItems configures the number of items Ristretto buffers for better concurrency.
	// If 0, a library default (e.g., 64, which is Ristretto's own default) will be used.
	RistrettoBufferItems int64

	// DefaultStoreExpirationForRistrettoAdapter sets a general default TTL at the gocache store adapter level.
	// This TTL is used if individual Set() calls do not provide their own store.WithExpiration option.
	// Since UserPermissionsCacheTTL and RolePermissionsCacheTTL will be used on Set(), this is a fallback.
	// If 0, it defaults to the longer of UserPermissionsCacheTTL or RolePermissionsCacheTTL.
	DefaultStoreExpirationForRistrettoAdapter time.Duration
}

type DefaultCacheManager struct {
	CacheConfig    DefaultCacheConfig
	CacheInstance  cache.CacheInterface[[]byte]
	CacheInitOnce  sync.Once
	CacheInitError error
}

func (m *DefaultCacheManager) GetCache() (cache.CacheInterface[[]byte], error) {
	m.CacheInitOnce.Do(func() {
		ristrettoClient, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: helpers.DefaultInt64(m.CacheConfig.RistrettoNumCounters, DefaultRistrettoNumCounters),
			MaxCost:     helpers.DefaultInt64(m.CacheConfig.RistrettoMaxCost, DefaultRistrettoMaxCost),
			BufferItems: helpers.DefaultInt64(m.CacheConfig.RistrettoBufferItems, DefaultRistrettoBufferItems),
			Metrics:     false,
		})

		if err != nil {
			zap.L().Error("DefaultCacheManager: Failed to create Ristretto cache client during initialization", zap.Error(err))
			m.CacheInitError = fmt.Errorf("ristretto client initialization failed: %w", err)
			return
		}

		ristrettoStoreAdapter := ristrettoStore.NewRistretto(
			ristrettoClient,
			store.WithExpiration(helpers.DefaultTimeDuration(
				m.CacheConfig.DefaultStoreExpirationForRistrettoAdapter,
				DefaultStoreExpirationForRistrettoAdapter,
			)),
		)

		m.CacheInstance = cache.New[[]byte](ristrettoStoreAdapter)
		zap.L().Info("DefaultCacheManager: Ristretto cache instance initialized successfully.")
	})

	if m.CacheInitError != nil {
		return nil, m.CacheInitError
	}

	if m.CacheInstance == nil {
		zap.L().Error("DefaultCacheManager: Cache instance is nil after initialization attempt without a stored error.")
		return nil, fmt.Errorf("internal error: cache not initialized despite no explicit init error")
	}

	return m.CacheInstance, nil
}

func BuildDefaultCacheManager(config *DefaultCacheConfig) *DefaultCacheManager {
	if config == nil {
		config = &DefaultCacheConfig{}
	}

	return &DefaultCacheManager{
		CacheConfig: *config,
	}
}
