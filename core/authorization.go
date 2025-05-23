package core

import (
	"encoding/base64"
	"fmt"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
	"time"
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

	MinimumSessionAuthorizationSize = 128            // Minimum size for a Authorization to be valid
	MaximumSessionAuthorizationSize = (1024 * 4) - 1 // The default maximum size for a Authorization is 4096 bytes

	MinimumSessionKeyIdSize = 1  // Minimum size for a key ID to be valid
	MaximumSessionKeyIdSize = 32 // 32 bytes for AES-256

	SessionAuthorizationVersion     = "SG1" // Version of the Authorization format
	MaximumAuthorizationVersionSize = 32    // Maximum size for the version string
	MinimumAuthorizationVersionSize = 1     // Minimum size for the version string
)

// SessionAuthorizationData defines the properties of the Authorization, including how to parse it.
type SessionAuthorizationData struct {
	CookieName     string // CookieName of the Authorization
	CookiePath     string // CookiePath, for which the Authorization is valid (used when setting)
	CookieDomain   string // CookieDomain, for which the Authorization is valid (used when setting)
	CookieSecure   bool   // If true, Authorization only sent over HTTPS (used when setting)
	CookieHttpOnly bool   // If true, Authorization cannot be accessed by client-side scripts (used when setting)
	CookieSameSite string // CookieSameSite attribute (e.g., "Strict", "Lax", "None") (used when setting)

	// AuthorizationHeaderName is the name of the Authorization header to be used.
	// If not set, the default value is "X-Authorization".
	AuthorizationHeaderName string

	// Delimiter is used to split the Authorization's value into parts.
	// For example, if the Authorization value is "header.payload.signature", the delimiter is ".".
	Delimiter string

	// MaxAuthorizationSize is the maximum size of the Authorization in bytes, default is 4096 bytes.
	MaxAuthorizationSize int

	// Expiration is the expiration time of the session in seconds, after which the session is considered expired
	// and can't be renewed.
	// (Bearer & Cookie)
	Expiration time.Duration

	// RefreshTime is the time after which the session can be renewed, you can invalidate previous sessions
	// if you want to.
	//  (Cookie)
	RefreshTime time.Duration

	// VerifyTime is the time interval between token verification events for a bearer token.
	// If this duration elapses without verification, the token will need to be re-verified.
	// (Bearer)
	VerifyTime time.Duration
}

// EnsureBasicClaims checks if the claims contain the required basic information if not, set it.
func ensureBasicClaims(group string, claims *SessionClaims, sessionManager SessionManager) error {
	if claims == nil {
		return errors.NewInternalServerError("Claims are nil", nil)
	}

	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	// - Session mode
	if setErr := claims.SetIfNotSet(SessionModeClaim, group); setErr != nil {
		return errors.NewInternalServerError("Failed to set session mode claim", setErr)
	}

	// - Csrf Token Tie
	newCsrfToken, err := helpers.GenerateID(helpers.AESKeySize32)
	if err != nil {
		return errors.NewInternalServerError("Failed to generate CSRF token", err)
	}
	if setErr := claims.SetIfNotSet(CsrfTokenTie, newCsrfToken); setErr != nil {
		return errors.NewInternalServerError("Failed to set CSRF token", setErr)
	}

	// - Session ID
	newSessionId, err := helpers.GenerateID(helpers.AESKeySize32)
	if err != nil {
		return errors.NewInternalServerError("Failed to generate session ID", err)
	}
	if setErr := claims.SetIfNotSet(SessionIdentifier, newSessionId); setErr != nil {
		return errors.NewInternalServerError("Failed to set session ID", setErr)
	}

	// - Rbac Cache Identifier (Optional)
	if sessionManager.GetRbacManager() != nil {
		rbacCacheIdentifier, err := helpers.GenerateID(helpers.AESKeySize32)
		if err != nil {
			return errors.NewInternalServerError("Failed to generate RBAC cache identifier", err)
		}

		if setErr := claims.SetIfNotSet(RbacCacheIdentifier, rbacCacheIdentifier); setErr != nil {
			return errors.NewInternalServerError("Failed to set RBAC cache identifier", setErr)
		}
	}

	// - Token version
	if setErr := claims.SetClaim(VersionClaim, SessionAuthorizationVersion); setErr != nil {
		return errors.NewInternalServerError("Failed to set version claim", setErr)
	}

	return nil
}

// CreateAuthorization creates a Authorization with the specified name and value, and sets its attributes.
func CreateAuthorization(
	group string,
	authorizationHeader *SessionHeader,
	authorizationData SessionAuthorizationData,
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

	// - Ensure the claims are set
	if err := ensureBasicClaims(group, claims, sessionManager); err != nil {
		return "", fmt.Errorf("failed to ensure basic claims: %w", err)
	}

	// - Encode the Authorization header and payload
	authorizationHeaderString, err := authorizationHeader.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	AuthorizationPayload, err := claims.EncodePayload()
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	delimiter := helpers.DefaultString(authorizationData.Delimiter, DefaultSessionAuthorizationDelimiter)
	AuthorizationValue := fmt.Sprintf("%s%s%s", authorizationHeaderString, delimiter, AuthorizationPayload)

	// - Fetch the session key from the session manager
	sessionKey, keyId, err := sessionManager.GetSessionKey()
	if err != nil {
		return "", fmt.Errorf("failed to get session key: %w", err)
	}

	if len(keyId) < MinimumSessionKeyIdSize {
		return "", fmt.Errorf("keyId is too short, must be at least %d characters", MinimumSessionKeyIdSize)
	}

	if len(keyId) > MaximumSessionKeyIdSize {
		return "", fmt.Errorf("keyId is too long, must be at most %d characters", MaximumSessionKeyIdSize)
	}

	// - Encrypt the Authorization value
	encryptedValue, err := helpers.SymmetricEncrypt(sessionKey, []byte(AuthorizationValue), []byte(keyId+SessionAuthorizationVersion))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt Authorization value: %w", err)
	}

	// - Encode the encrypted value to base64
	encodedValue := base64.RawURLEncoding.EncodeToString(encryptedValue)

	return fmt.Sprintf("%s%s%s%s%s",
		SessionAuthorizationVersion,
		delimiter,
		keyId,
		delimiter,
		encodedValue,
	), nil
}

// CreateRefreshAuthorization creates a Authorization with the specified name and value, and sets its attributes.
func CreateRefreshAuthorization(authorizationData SessionAuthorizationData, claims *SessionClaims, oldSessionHeader *SessionHeader, sessionManager SessionManager) (string, error) {
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
		return "", fmt.Errorf("session mode claim is missing, cannot create refresh Authorization")
	}

	// - We take the old expires at, - now and add set that to the dereferenced AuthorizationData
	authorizationData.Expiration = time.Unix(oldSessionHeader.ExpiresAt, 0).Sub(time.Now())
	sessionRefreshTime := helpers.DefaultTimeDuration(authorizationData.RefreshTime, DefaultSessionRefreshTime)
	sessionExpiration := helpers.DefaultTimeDuration(authorizationData.Expiration, DefaultSessionExpiration)
	authorizationHeader := NewSessionHeader(false, sessionExpiration, sessionRefreshTime)

	return CreateAuthorization(mode, &authorizationHeader, authorizationData, claims, sessionManager)
}
