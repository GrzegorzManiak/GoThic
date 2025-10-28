// go
package cache

import (
	"testing"
	"time"
)

func TestBuildDefaultCacheManager_NilConfig_AppliesDefaults(t *testing.T) {
	m := BuildDefaultCacheManager(nil)
	if m == nil {
		t.Fatalf("expected manager, got nil")
	}

	cfg := m.CacheConfig

	if cfg.RistrettoMaxCost != DefaultRistrettoMaxCost {
		t.Fatalf("RistrettoMaxCost: expected %d, got %d", DefaultRistrettoMaxCost, cfg.RistrettoMaxCost)
	}

	if cfg.RistrettoNumCounters != DefaultRistrettoNumCounters {
		t.Fatalf("RistrettoNumCounters: expected %d, got %d", DefaultRistrettoNumCounters, cfg.RistrettoNumCounters)
	}

	if cfg.RistrettoBufferItems != DefaultRistrettoBufferItems {
		t.Fatalf("RistrettoBufferItems: expected %d, got %d", DefaultRistrettoBufferItems, cfg.RistrettoBufferItems)
	}

	if cfg.DefaultStoreExpirationForRistrettoAdapter != DefaultStoreExpirationForRistrettoAdapter {
		t.Fatalf("DefaultStoreExpirationForRistrettoAdapter: expected %v, got %v", DefaultStoreExpirationForRistrettoAdapter, cfg.DefaultStoreExpirationForRistrettoAdapter)
	}
}

func TestBuildDefaultCacheManager_WithCustomConfig_Preserved(t *testing.T) {
	custom := &DefaultCacheConfig{
		RistrettoMaxCost:                          12345,
		RistrettoNumCounters:                      54321,
		RistrettoBufferItems:                      7,
		DefaultStoreExpirationForRistrettoAdapter: 2 * time.Minute,
	}

	m := BuildDefaultCacheManager(custom)
	if m == nil {
		t.Fatalf("expected manager, got nil")
	}

	cfg := m.CacheConfig

	if cfg.RistrettoMaxCost != custom.RistrettoMaxCost {
		t.Fatalf("RistrettoMaxCost: expected %d, got %d", custom.RistrettoMaxCost, cfg.RistrettoMaxCost)
	}
	if cfg.RistrettoNumCounters != custom.RistrettoNumCounters {
		t.Fatalf("RistrettoNumCounters: expected %d, got %d", custom.RistrettoNumCounters, cfg.RistrettoNumCounters)
	}
	if cfg.RistrettoBufferItems != custom.RistrettoBufferItems {
		t.Fatalf("RistrettoBufferItems: expected %d, got %d", custom.RistrettoBufferItems, cfg.RistrettoBufferItems)
	}
	if cfg.DefaultStoreExpirationForRistrettoAdapter != custom.DefaultStoreExpirationForRistrettoAdapter {
		t.Fatalf("DefaultStoreExpirationForRistrettoAdapter: expected %v, got %v", custom.DefaultStoreExpirationForRistrettoAdapter, cfg.DefaultStoreExpirationForRistrettoAdapter)
	}
}

func TestDefaultCacheManager_GetCache_InitializesCache(t *testing.T) {
	m := BuildDefaultCacheManager(nil)
	if m == nil {
		t.Fatalf("expected manager, got nil")
	}

	cacheInstance, err := m.GetCache()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cacheInstance == nil {
		t.Fatalf("expected cache instance, got nil")
	}

	// Call GetCache again to ensure it returns the same instance without error
	cacheInstance2, err2 := m.GetCache()
	if err2 != nil {
		t.Fatalf("expected no error on second call, got %v", err2)
	}
	if cacheInstance2 == nil {
		t.Fatalf("expected cache instance on second call, got nil")
	}
	if cacheInstance != cacheInstance2 {
		t.Fatalf("expected same cache instance on second call, got different instances")
	}
}
