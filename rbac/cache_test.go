package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
)

type testStruct struct {
	Name  string
	Value int
}

/**
 * For some context, this caching mechanism is used in an RBAC (Role-Based Access Control)
 * system to cache permissions and roles associated with subjects (users or entities).
 * Therefore, the default failover behavior is to return a zero value and indicate
 * that the data was not found in cache, allowing the system to fetch fresh data from the
 * primary source (Which itself should also have proper caching)
 *
 * Errors should only be returned in case of critical failures, such as unmarshalling errors,
 * which indicate that the cached data is corrupted or invalid.
 */
func TestFetchFromCache(t *testing.T) {
	ctx := context.Background()
	testData := testStruct{Name: "test", Value: 42}
	marshaledData, _ := json.Marshal(testData)

	tests := []struct {
		name      string
		cache     cache.CacheInterface[[]byte]
		key       string
		data      map[string][]byte
		cacheErr  error
		want      testStruct
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "Nil cache returns zero value",
			cache:     nil,
			key:       "test",
			wantFound: false,
			wantErr:   false,
		},
		{
			name: "Successful fetch",
			cache: &mockCache{
				data: map[string][]byte{"test": marshaledData},
			},
			key:       "test",
			want:      testData,
			wantFound: true,
			wantErr:   false,
		},
		{
			name: "Cache miss",
			cache: &mockCache{
				data: map[string][]byte{},
			},
			key:       "test",
			wantFound: false,
			wantErr:   false,
		},
		{
			name: "Cache error",
			cache: &mockCache{
				err: errors.New("cache error"),
			},
			key:       "test",
			wantFound: false,
			wantErr:   false,
		},
		{
			name: "Unmarshal error",
			cache: &mockCache{
				data: map[string][]byte{"test": []byte("invalid json")},
			},
			key:       "test",
			wantFound: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found, err := fetchFromCache(ctx, tt.cache, tt.key, func(b []byte) (testStruct, error) {
				var ts testStruct
				if err := json.Unmarshal(b, &ts); err != nil {
					return ts, err
				}
				return ts, nil
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("fetchFromCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if found != tt.wantFound {
				t.Errorf("fetchFromCache() found = %v, want %v", found, tt.wantFound)
			}
			if tt.wantFound && got != tt.want {
				t.Errorf("fetchFromCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetNilOrInvalidUnmarshalFunction(t *testing.T) {
	ctx := context.Background()
	mockCacheInstance := &mockCache{
		data: make(map[string][]byte),
	}

	t.Run("Nil marshal function returns error", func(t *testing.T) {
		err := setInCache(ctx, mockCacheInstance, "test", testStruct{Name: "test", Value: 1}, time.Minute, nil)
		if err == nil {
			t.Errorf("Expected error for nil marshal function, got nil")
		}
	})

	t.Run("Marshal function returns error", func(t *testing.T) {
		err := setInCache(ctx, mockCacheInstance, "test", testStruct{Name: "test", Value: 1}, time.Minute, func(v testStruct) ([]byte, error) {
			return nil, errors.New("marshal error")
		})
		if err == nil {
			t.Errorf("Expected error for marshal function failure, got nil")
		}
	})
}

func TestSetInCache(t *testing.T) {
	ctx := context.Background()
	testData := testStruct{Name: "test", Value: 42}

	tests := []struct {
		name     string
		cache    cache.CacheInterface[[]byte]
		key      string
		value    testStruct
		ttl      time.Duration
		wantErr  bool
		cacheErr error
	}{
		{
			name:    "Nil cache returns no error",
			cache:   nil,
			key:     "test",
			value:   testData,
			ttl:     time.Minute,
			wantErr: false,
		},
		{
			name:    "Successful set",
			cache:   &mockCache{},
			key:     "test",
			value:   testData,
			ttl:     time.Minute,
			wantErr: false,
		},
		{
			name: "Cache error on set does not return error",
			cache: &mockCache{
				err: errors.New("cache error"),
			},
			key:     "test",
			value:   testData,
			ttl:     time.Minute,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setInCache(ctx, tt.cache, tt.key, tt.value, tt.ttl, func(v testStruct) ([]byte, error) {
				return json.Marshal(v)
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("setInCache() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSetNilOrInvalidMarshalFunction(t *testing.T) {
	ctx := context.Background()
	mockCacheInstance := &mockCache{
		data: make(map[string][]byte),
	}
	t.Run("Nil marshal function returns error", func(t *testing.T) {
		err := setInCache(ctx, mockCacheInstance, "test", testStruct{Name: "test", Value: 1}, time.Minute, nil)
		if err == nil {
			t.Errorf("Expected error for nil marshal function, got nil")
		}
	})

	t.Run("Marshal function returns error", func(t *testing.T) {
		err := setInCache(ctx, mockCacheInstance, "test", testStruct{Name: "test", Value: 1}, time.Minute, func(v testStruct) ([]byte, error) {
			return nil, errors.New("marshal error")
		})
		if err == nil {
			t.Errorf("Expected error for marshal function failure, got nil")
		}
	})
}
