package core

import (
	"fmt"
	"github.com/eko/gocache/lib/v4/store"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
	"strconv"
	"time"
)

func GetAuthorizationHeader(
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
	cachedSession, getErr := cache.Get(ctx, cacheKey)
	if getErr != nil {
		// - When we get a cache miss, it's returned as an error, therefore, we can't just
		// invalidate the whole request over it. We will just force a refresh.
		return cacheKey, true, nil
	}

	if cachedSession == nil {
		return "", false, nil
	}

	// - Stored as a Unix timestamp; after this time, the session requires validation
	timeStamp, convErr := strconv.ParseInt(string(cachedSession), 10, 64)
	if convErr != nil {
		return "", false, fmt.Errorf("failed to convert cached session to int: %w", convErr)
	}

	// - Check if the token needs validation
	needsRefresh = timeStamp < time.Now().Unix()
	return cacheKey, needsRefresh, nil
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

	// - Set the new refresh time in the cache
	cacheTTL := time.Duration(header.RefreshPeriodSec) * time.Second
	refreshTime := time.Now().Add(cacheTTL).Unix()
	if err = cache.Set(ctx, cacheKey, []byte(strconv.FormatInt(refreshTime, 10)), store.WithExpiration(cacheTTL)); err != nil {
		return fmt.Errorf("failed to set cache: %w", err)
	}

	return nil
}
