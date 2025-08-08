package core

import (
	"context"
	"fmt"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/grzegorzmaniak/gothic/rbac"
)

const (
	SessionIdentifier   = "___id" // Identifier
	SessionModeClaim    = "___sm" // Session mode
	RbacCacheIdentifier = "___ri" // RBAC (cache) identifier
	CsrfTokenTie        = "___ct" // CSRF token tie
	VersionClaim        = "___v"  // Version
)

const (
	BearerTokenCacheKeyPrefix = "bearer_token:" // Key: bearer_token:<tokenIdentifier>
)

type SessionManager interface {

	// GetAuthorizationData Is used to get the cookie data for the session manager
	GetAuthorizationData() *SessionAuthorizationData

	// GetCsrfData Is used to get the CSRF data for the session manager
	GetCsrfData() *CsrfCookieData

	// GetSessionKey Is used to get the freshest session key for the session manager
	GetSessionKey() (keyBytes []byte, keyIdentifier string, error error)

	// GetOldSessionKey Is used to get an old session key for the session manager
	GetOldSessionKey(string) (keyBytes []byte, error error)

	// VerifySession Is used to verify a session token, and should the token be allowed to be extended
	VerifySession(ctx context.Context, claimsToVerify *SessionClaims, sessionHeader *SessionHeader) (bool, error)

	// StoreSession Is used to store a session token for a given subject
	StoreSession(ctx context.Context, claimsToStore *SessionClaims, sessionHeader *SessionHeader) error

	// VerifyClaims Is used to verify the claims of a session token
	VerifyClaims(ctx context.Context, claimsToVerify *SessionClaims, sessionConfig *APIConfiguration) (bool, error)

	// GetRbacManager Is used to get the RBAC manager for the session manager
	// This is fully optional, and returning nil is perfectly fine.
	GetRbacManager() rbac.Manager

	// GetSubjectIdentifier Is used to get the identifier for a given subject
	GetSubjectIdentifier(subject *SessionClaims) (string, error)

	// GetCache Is used to get the cache for the session manager, we use it to cache authorization, speeds things
	// up a lot, you can use the same cache from rbac manager, but that's not recommended.
	GetCache() (cache.CacheInterface[string], error)
}

type DefaultSessionManager struct{}

// VerifyClaims barebones implementation of the VerifyClaims method
func (m *DefaultSessionManager) VerifyClaims(ctx context.Context, claimsToVerify *SessionClaims, sessionConfig *APIConfiguration) (bool, error) {
	if sessionConfig == nil {
		return false, fmt.Errorf("session config is nil")
	}

	if claimsToVerify == nil {
		return false, fmt.Errorf("claims to verify is nil")
	}

	tokenMode, ok := claimsToVerify.GetClaim(SessionModeClaim)
	if !ok || tokenMode == "" {
		return false, fmt.Errorf("session mode claim is missing")
	}

	if contains(sessionConfig.Allow, tokenMode) {
		return true, nil
	}

	if len(sessionConfig.Allow) > 0 {
		return false, fmt.Errorf("session mode claim is not allowed")
	}

	if contains(sessionConfig.Block, tokenMode) {
		return false, fmt.Errorf("session mode claim is blocked")
	}

	return true, nil
}

// GetRbacManager returns the RBAC manager for the session manager, this is a no-op
func (m *DefaultSessionManager) GetRbacManager() rbac.Manager {
	return nil
}

func contains(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}
