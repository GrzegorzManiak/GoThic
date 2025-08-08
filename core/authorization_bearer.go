package core

import (
	"encoding/binary"
	"fmt"
	"github.com/eko/gocache/lib/v4/store"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
	"time"
)

func GetAuthorizationBearer(
	ctx *gin.Context,
	sessionManager SessionManager,
) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("context is nil")
	}

	if sessionManager == nil {
		return "", fmt.Errorf("session manager is nil")
	}

	authorizationData := sessionManager.GetAuthorizationData()
	if authorizationData == nil {
		return "", fmt.Errorf("authorization data is nil")
	}

	authorizationHeaderName := helpers.DefaultString(authorizationData.AuthorizationHeaderName, DefaultSessionAuthorizationHeaderName)
	authorizationHeader := ctx.GetHeader(authorizationHeaderName)
	if authorizationHeader == "" {
		return "", fmt.Errorf("authorization header '%s' is empty", authorizationHeaderName)
	}

	return authorizationHeader, nil
}

func IssueBearerToken(
	ctx *gin.Context,
	sessionManager SessionManager,
	group string,
	claims *SessionClaims,
) (string, error) {
	if sessionManager == nil {
		return "", fmt.Errorf("session manager is nil")
	}
	authorizationData := sessionManager.GetAuthorizationData()
	return IssueCustomBearerToken(ctx, sessionManager, group, claims, authorizationData)
}

func IssueCustomBearerToken(
	ctx *gin.Context,
	sessionManager SessionManager,
	group string,
	claims *SessionClaims,
	authorizationData *SessionAuthorizationData,
) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("context is nil")
	}

	if sessionManager == nil {
		return "", fmt.Errorf("session manager is nil")
	}

	if claims == nil {
		return "", fmt.Errorf("claims are nil")
	}

	if authorizationData == nil {
		return "", errors.NewInternalServerError("Authorization data is nil", nil)
	}

	headerExpiration := helpers.DefaultTimeDuration(authorizationData.Expiration, DefaultAuthorizationExpiration)
	headerRefreshTime := helpers.DefaultTimeDuration(authorizationData.VerifyTime, DefaultAuthorizationVerifyTime)
	authorizationHeader := NewSessionHeader(true, headerExpiration, headerRefreshTime)

	authorizationString, err := CreateAuthorization(group, &authorizationHeader, *authorizationData, claims, sessionManager)
	if err != nil {
		return "", err
	}

	if err = sessionManager.StoreSession(ctx, claims, nil); err != nil {
		return "", errors.NewInternalServerError("Failed to store bearer", err)
	}

	return authorizationString, nil
}

func formatCacheKey(sessionIdentifier string) (string, error) {
	if sessionIdentifier == "" {
		return "", fmt.Errorf("session identifier is empty")
	}

	return BearerTokenCacheKeyPrefix + sessionIdentifier, nil
}

func BearerNeedsValidation(
	ctx *gin.Context,
	sessionManager SessionManager,
	claims *SessionClaims,
) (cacheKey string, needsRefresh bool, err error) {
	if ctx == nil {
		return "", false, fmt.Errorf("context is nil")
	}

	if sessionManager == nil {
		return "", false, fmt.Errorf("session manager is nil")
	}

	cache, err := sessionManager.GetCache()
	if err != nil || cache == nil {
		return "", false, fmt.Errorf("BearerNeedsValidation: failed to get cache: %w", err)
	}

	sessionId, ok := claims.GetClaim(SessionIdentifier)
	if !ok || sessionId == "" {
		return "", false, fmt.Errorf("session identifier is missing")
	}

	cacheKey, err = formatCacheKey(sessionId)
	if err != nil {
		return "", false, fmt.Errorf("failed to format cache key: %w", err)
	}

	// - Check if the session is in the cache
	cachedValue, getErr := cache.Get(ctx, cacheKey)
	if getErr != nil {
		// - Cache miss is not a fatal error; it just means we need to validate.
		return cacheKey, true, nil
	}

	if len(cachedValue) < 8 {
		// - The cached value is invalid or corrupted. Force a refresh.
		return cacheKey, true, fmt.Errorf("invalid cache entry for key '%s': expected 8 bytes, got %d", cacheKey, len(cachedValue))
	}

	// - Read the 8-byte slice directly into an uint64
	return cacheKey, binary.BigEndian.Uint64(cachedValue) < uint64(time.Now().Unix()), nil
}

// BearerSetCache sets the cache for the session token.
// We cache with both a TTL and store the refresh timestamp itself.
// Rather than purely relying on TTL for session validation, which delegates
// crucial validation logic to the cache implementation, we explicitly store
// the refresh timestamp. The TTL serves primarily as a cache cleanup mechanism.
func BearerSetCache(
	ctx *gin.Context,
	sessionManager SessionManager,
	cacheKey string,
	header *SessionHeader,
) error {
	if ctx == nil {
		return fmt.Errorf("context is nil")
	}

	if sessionManager == nil {
		return fmt.Errorf("session manager is nil")
	}

	if header == nil {
		return fmt.Errorf("header is nil")
	}

	cache, err := sessionManager.GetCache()
	if err != nil || cache == nil {
		return fmt.Errorf("failed to get cache: %w", err)
	}

	// - Calculate the refresh timestamp.
	refreshPeriod := time.Duration(header.RefreshPeriodSec) * time.Second
	refreshTime := time.Now().Add(refreshPeriod).Unix()

	// - Create an 8-byte slice to hold the binary representation of the timestamp.
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(refreshTime))

	// - The cache TTL should be slightly longer than the refresh period to avoid premature eviction.
	cacheTTL := refreshPeriod + (5 * time.Minute)
	if err = cache.Set(ctx, cacheKey, b, store.WithExpiration(cacheTTL)); err != nil {
		return fmt.Errorf("failed to set cache: %w", err)
	}

	return nil
}
