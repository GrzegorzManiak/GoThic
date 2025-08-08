package rbac

import (
	"context"
	"fmt"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	"time"
)

func fetchFromCache[T any](
	ctx context.Context,
	cache cache.CacheInterface[[]byte],
	key string,
	unmarshal func([]byte) (T, error),
) (T, bool, error) {
	var zero T
	val, err := cache.Get(ctx, key)
	if err != nil {
		// - cache miss is not an error
		return zero, false, nil
	}
	data, err := unmarshal(val)
	if err != nil {
		return zero, false, fmt.Errorf("cache: failed to unmarshal key '%s': %w", key, err)
	}
	return data, true, nil
}

func setInCache[T any](
	ctx context.Context,
	cache cache.CacheInterface[[]byte],
	key string,
	value T,
	ttl time.Duration,
	marshal func(T) ([]byte, error),
) error {
	str, err := marshal(value)
	if err != nil {
		return fmt.Errorf("cache: failed to marshal key '%s': %w", key, err)
	}
	if err := cache.Set(ctx, key, str, store.WithExpiration(ttl)); err != nil {
		return fmt.Errorf("cache: failed to set key '%s': %w", key, err)
	}
	return nil
}
