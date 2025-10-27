package core

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/helpers"
	"strings"
)

const (
	SourceNone   = "none"
	SourceHeader = "header"
	SourceCookie = "cookie"
)

func extractSessionAuthorizationParts(
	AuthorizationData *SessionAuthorizationConfiguration,
	sessionManager SessionManager,
	authorizationValue string,
) (header string, payload string, err error) {
	// --- 1. Grouped Validations ---
	if AuthorizationData == nil {
		return "", "", fmt.Errorf("AuthorizationData cannot be nil")
	}

	delimiter := helpers.DefaultString(AuthorizationData.Delimiter, DefaultSessionAuthorizationDelimiter)
	name := helpers.DefaultString(AuthorizationData.CookieName, DefaultSessionAuthorizationName)

	if authorizationValue == "" {
		return "", "", fmt.Errorf("authorization token '%s' is empty", name)
	}

	maxSize := helpers.DefaultInt(AuthorizationData.MaxAuthorizationSize, MaximumSessionAuthorizationSize)
	if len(authorizationValue) > maxSize {
		return "", "", fmt.Errorf("authorization token '%s' exceeds maximum size of %d bytes", name, maxSize)
	}
	if len(authorizationValue) < MinimumSessionAuthorizationSize {
		return "", "", fmt.Errorf("authorization token '%s' is too small, minimum size is %d bytes", name, MinimumSessionAuthorizationSize)
	}

	// --- 2. Initial Split & Validation ---
	splitValues := strings.SplitN(authorizationValue, delimiter, 3)
	if len(splitValues) != 3 {
		return "", "", fmt.Errorf("invalid token format for '%s': expected 3 parts, but found %d", name, len(splitValues))
	}

	keyVersion, keyId, encryptedPart := splitValues[0], splitValues[1], splitValues[2]

	if len(keyId) < MinimumSessionKeyIdSize || len(keyId) > MaximumSessionKeyIdSize {
		return "", "", fmt.Errorf("invalid keyId size in token '%s'", name)
	}
	if len(keyVersion) < MinimumAuthorizationVersionSize || len(keyVersion) > MaximumAuthorizationVersionSize {
		return "", "", fmt.Errorf("invalid keyVersion size in token '%s'", name)
	}

	// --- 3. Decryption Logic ---
	sessionKey, err := sessionManager.GetOldSessionKey(keyId)
	if err != nil {
		return "", "", fmt.Errorf("failed to retrieve session key for '%s': %w", name, err)
	}

	decodedValue, err := base64.RawURLEncoding.DecodeString(encryptedPart)
	if err != nil {
		return "", "", fmt.Errorf("failed to base64-decode token '%s': %w", name, err)
	}

	// - The associated data is what authenticates the ciphertext.
	associatedData := []byte(keyId + keyVersion)
	decryptedValue, err := helpers.SymmetricDecrypt(sessionKey, decodedValue, associatedData)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt token '%s': %w", name, err)
	}

	// --- 4. Optimized Final Split (working with []byte) ---
	// Use bytes.Index to find the delimiter without allocating a new slice of strings.
	delimiterBytes := []byte(delimiter)
	splitIndex := bytes.Index(decryptedValue, delimiterBytes)
	if splitIndex == -1 {
		return "", "", fmt.Errorf("invalid decrypted token format for '%s': missing final delimiter", name)
	}

	header = string(decryptedValue[:splitIndex])
	payload = string(decryptedValue[splitIndex+len(delimiterBytes):])

	return header, payload, nil
}

func extractSession(ctx *gin.Context, sessionManager SessionManager) (*SessionHeader, *SessionClaims, string, string, error) {
	authorizationData := sessionManager.GetAuthorizationConfiguration()
	if authorizationData == nil {
		return nil, nil, "", SourceNone, fmt.Errorf("authorization data is not configured")
	}

	// --- Flattened logic for source extraction ---
	source := SourceHeader
	authorizationValue, err := GetAuthorizationBearer(ctx, sessionManager)
	if err != nil {
		// - Check if there is a session cookie
		authorizationValue, err = GetSessionCookie(ctx, sessionManager)
		if err != nil {
			// - No session header or cookie was found. This is a valid sessionless case.
			return nil, nil, "", SourceNone, nil
		}
		source = SourceCookie
	}

	// --- Continue with the extraction logic ---
	headerStr, payloadStr, err := extractSessionAuthorizationParts(authorizationData, sessionManager, authorizationValue)
	if err != nil {
		// - Development only - If this fails, it usually means the session has been tampered with or
		// the session key has changed (like in development mode), therefore, if we are in development mode,
		// we return nil, nil, SourceNone, "", nil, to allow the session to be refreshed with a new session key.
		// Note: In test & production modes, we return the error to prevent silent failures.
		if gin.Mode() == gin.DebugMode {
			return nil, nil, "", SourceNone, nil
		}

		return nil, nil, source, "", fmt.Errorf("failed to extract session parts: %w", err)
	}

	decodedHeader, err := Decode(headerStr) // Decode was already taking a string, this is fine
	if err != nil {
		return nil, nil, source, "", fmt.Errorf("failed to decode header: %w", err)
	}

	claims := &SessionClaims{HasSession: true}
	if err := claims.DecodePayload(payloadStr); err != nil { // DecodePayload was also taking a string
		return nil, nil, source, "", fmt.Errorf("failed to decode payload: %w", err)
	}

	group, ok := claims.GetClaim(SessionModeClaim)
	if !ok || group == "" {
		return nil, nil, source, "", fmt.Errorf("session mode claim is missing or empty")
	}

	return &decodedHeader, claims, group, source, nil
}
