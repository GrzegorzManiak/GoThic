package core

import (
	"encoding/base64"
	"fmt"
	"strings" // Import the strings package for the builder
	"time"

	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
)

const (
	DefaultSessionAuthorizationHeaderName = "x-api-key"
	DefaultSessionAuthorizationName       = "session"
	DefaultSessionAuthorizationPath       = "/"
	DefaultSessionAuthorizationDomain     = "localhost"
	DefaultSessionAuthorizationSecure     = true
	DefaultSessionAuthorizationHttpOnly   = true
	DefaultSessionAuthorizationSameSite   = "Strict"
	DefaultSessionAuthorizationDelimiter  = "."

	DefaultSessionExpiration  = time.Hour * 24 * 7
	DefaultSessionRefreshTime = time.Minute * 5

	DefaultAuthorizationExpiration = time.Hour * 24 * 30
	DefaultAuthorizationVerifyTime = time.Minute * 10

	MinimumSessionAuthorizationSize = 128
	MaximumSessionAuthorizationSize = (1024 * 4) - 1

	MinimumSessionKeyIdSize = 1
	MaximumSessionKeyIdSize = 32

	SessionAuthorizationVersion     = "SG1"
	MaximumAuthorizationVersionSize = 32
	MinimumAuthorizationVersionSize = 1

	SessionModeClaimMinimumSize = 1
	SessionModeClaimMaximumSize = 32
)

type SessionAuthorizationConfiguration struct {
	CookieName              string
	CookiePath              string
	CookieDomain            string
	CookieSecure            bool
	CookieHttpOnly          bool
	CookieSameSite          string
	AuthorizationHeaderName string
	Delimiter               string
	MaxAuthorizationSize    int
	Expiration              time.Duration
	RefreshTime             time.Duration
	VerifyTime              time.Duration
}

func ensureBasicClaims(group string, claims *SessionClaims, sessionManager SessionManager) error {
	if claims == nil {
		return errors.NewInternalServerError("Claims are nil", nil)
	}
	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	if len(group) < SessionModeClaimMinimumSize || len(group) > SessionModeClaimMaximumSize {
		return fmt.Errorf("session mode claim must be between %d and %d characters", SessionModeClaimMinimumSize, SessionModeClaimMaximumSize)
	}
	claims.SetIfNotSet(SessionModeClaim, group)

	newCsrfToken, err := helpers.GenerateID(helpers.AESKeySize32)
	if err != nil {
		return errors.NewInternalServerError("Failed to generate CSRF token", err)
	}
	claims.SetIfNotSet(CsrfTokenTie, newCsrfToken)

	newSessionId, err := helpers.GenerateID(helpers.AESKeySize32)
	if err != nil {
		return errors.NewInternalServerError("Failed to generate session ID", err)
	}
	claims.SetIfNotSet(SessionIdentifier, newSessionId)

	if sessionManager.GetRbacManager() != nil {
		rbacCacheIdentifier, err := helpers.GenerateID(helpers.AESKeySize32)
		if err != nil {
			return errors.NewInternalServerError("Failed to generate RBAC cache identifier", err)
		}
		claims.SetIfNotSet(RbacCacheIdentifier, rbacCacheIdentifier)
	}

	claims.SetClaim(VersionClaim, SessionAuthorizationVersion)
	return nil
}

// CreateAuthorization creates a secure, encrypted, and versioned authorization token.
func CreateAuthorization(
	group string,
	authorizationHeader *SessionHeader,
	authorizationData SessionAuthorizationConfiguration,
	claims *SessionClaims,
	sessionManager SessionManager,
) (string, error) {
	if sessionManager == nil {
		return "", fmt.Errorf("session manager is nil")
	}
	if claims == nil {
		return "", fmt.Errorf("claims are nil")
	}
	if authorizationHeader == nil {
		return "", fmt.Errorf("authorization header is nil")
	}

	if err := ensureBasicClaims(group, claims, sessionManager); err != nil {
		return "", fmt.Errorf("failed to ensure basic claims: %w", err)
	}

	authorizationHeaderString, err := authorizationHeader.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	AuthorizationPayload, err := claims.EncodePayload()
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	delimiter := helpers.DefaultString(authorizationData.Delimiter, DefaultSessionAuthorizationDelimiter)
	authorizationValue := fmt.Sprintf("%s%s%s", authorizationHeaderString, delimiter, AuthorizationPayload)

	sessionKey, keyId, err := sessionManager.GetSessionKey()
	if err != nil {
		return "", fmt.Errorf("failed to get session key: %w", err)
	}

	if len(keyId) < MinimumSessionKeyIdSize || len(keyId) > MaximumSessionKeyIdSize {
		return "", fmt.Errorf("invalid keyId size: must be between %d and %d characters", MinimumSessionKeyIdSize, MaximumSessionKeyIdSize)
	}

	// Encrypt the value with the keyId and version as associated data for integrity.
	associatedData := []byte(keyId + SessionAuthorizationVersion)
	encryptedValue, err := helpers.SymmetricEncrypt(sessionKey, []byte(authorizationValue), associatedData)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt authorization value: %w", err)
	}

	encodedValue := base64.RawURLEncoding.EncodeToString(encryptedValue)

	var sb strings.Builder

	sb.Grow(len(SessionAuthorizationVersion) + len(delimiter) + len(keyId) + len(delimiter) + len(encodedValue))
	sb.WriteString(SessionAuthorizationVersion)
	sb.WriteString(delimiter)
	sb.WriteString(keyId)
	sb.WriteString(delimiter)
	sb.WriteString(encodedValue)

	return sb.String(), nil
}

// CreateRefreshAuthorization generates a new token for an existing session, preserving its original expiration time.
func CreateRefreshAuthorization(
	authorizationData SessionAuthorizationConfiguration,
	claims *SessionClaims,
	oldSessionHeader *SessionHeader,
	sessionManager SessionManager,
) (string, error) {
	if sessionManager == nil {
		return "", fmt.Errorf("session manager is nil")
	}
	if claims == nil {
		return "", fmt.Errorf("claims are nil")
	}
	if oldSessionHeader == nil {
		return "", fmt.Errorf("old session header is nil")
	}

	mode, ok := claims.GetClaim(SessionModeClaim)
	if !ok {
		return "", fmt.Errorf("session mode claim is missing, cannot create refresh token")
	}

	// 1. Calculate the absolute expiration time of the original token.
	absoluteExpiryTime := time.Unix(oldSessionHeader.IssuedAt+oldSessionHeader.LifetimeSec, 0)

	// 2. Calculate the remaining duration from now until that absolute expiration.
	newExpirationDuration := time.Until(absoluteExpiryTime)

	// If the token is already expired, prevent a refresh.
	if newExpirationDuration <= 0 {
		return "", fmt.Errorf("cannot refresh an already expired token")
	}

	// 3. Create a new header with the remaining lifetime and a *new* IssuedAt timestamp.
	sessionRefreshTime := helpers.DefaultTimeDuration(authorizationData.RefreshTime, DefaultSessionRefreshTime)
	authorizationHeader := NewSessionHeader(false, newExpirationDuration, sessionRefreshTime)

	return CreateAuthorization(mode, &authorizationHeader, authorizationData, claims, sessionManager)
}
