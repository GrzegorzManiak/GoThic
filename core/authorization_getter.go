package core

import (
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
	AuthorizationData *SessionAuthorizationData,
	sessionManager SessionManager,
	authorizationValue string,
) (header string, payload string, err error) {
	if AuthorizationData == nil {
		return "", "", fmt.Errorf("AuthorizationData cannot be nil")
	}

	delimiter := helpers.DefaultString(AuthorizationData.Delimiter, DefaultSessionAuthorizationDelimiter)
	name := helpers.DefaultString(AuthorizationData.CookieName, DefaultSessionAuthorizationName)

	if authorizationValue == "" {
		return "", "", fmt.Errorf("authorization '%s' is empty", name)
	}

	maximumSessionAuthorizationSize := helpers.DefaultInt(AuthorizationData.MaxAuthorizationSize, MaximumSessionAuthorizationSize)
	if len(authorizationValue) > maximumSessionAuthorizationSize {
		return "", "", fmt.Errorf("authorization '%s' exceeds maximum size of %d bytes", name, maximumSessionAuthorizationSize)
	}

	if len(authorizationValue) < MinimumSessionAuthorizationSize {
		return "", "", fmt.Errorf("authorization '%s' is too small, minimum size is %d bytes", name, MinimumSessionAuthorizationSize)
	}

	// - Extract the keyID from the Authorization value
	splitValues := strings.SplitN(authorizationValue, delimiter, 3)
	if len(splitValues) != 3 {
		return "", "", fmt.Errorf("invalid Authorization format for '%s': expected 3 parts delimited by '%s', but found %d parts. Value: '%s'",
			name,
			delimiter,
			len(splitValues),
		)
	}

	keyVersion := splitValues[0]
	keyId := splitValues[1]
	authorizationValue = splitValues[2]

	// - Validate the keyId length
	if len(keyId) > MaximumSessionKeyIdSize {
		return "", "", fmt.Errorf("invalid keyId length for Authorization '%s': expected %d bytes, but found %d bytes", name, MaximumSessionKeyIdSize, len(keyId))
	}

	if len(keyId) < MinimumSessionKeyIdSize {
		return "", "", fmt.Errorf("keyId '%s' is too small, minimum size is %d bytes", keyId, MinimumSessionKeyIdSize)
	}

	// - Validate the keyVersion length
	if len(keyVersion) > MaximumAuthorizationVersionSize {
		return "", "", fmt.Errorf("invalid keyVersion length for Authorization '%s': expected %d bytes, but found %d bytes", name, MaximumAuthorizationVersionSize, len(keyVersion))
	}

	if len(keyVersion) < MinimumAuthorizationVersionSize {
		return "", "", fmt.Errorf("keyVersion '%s' is too small, minimum size is %d bytes", keyVersion, MinimumAuthorizationVersionSize)
	}

	// - Get the session key
	sessionKey, err := sessionManager.GetOldSessionKey(keyId)
	if err != nil {
		return "", "", fmt.Errorf("failed to get session key for Authorization '%s': %w", name, err)
	}

	// - Decrypt the Authorization
	decodedValue, err := base64.RawURLEncoding.DecodeString(authorizationValue)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode Authorization '%s': %w", name, err)
	}

	// - Pass the keyId as associated data to the decryption function
	decryptedValue, err := helpers.SymmetricDecrypt(sessionKey, decodedValue, []byte(keyId+keyVersion))
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt Authorization '%s': %w", name, err)
	}
	authorizationValue = string(decryptedValue)

	// - Split the Authorization string into at most 3 parts.
	// If there are more delimiters, the third part will contain the rest of the string.
	// Example: "a.b.c.d" with delimiter "." and N=3 becomes ["a", "b", "c.d"]
	splitValues = strings.SplitN(authorizationValue, delimiter, 2)

	if len(splitValues) != 2 {
		return "", "", fmt.Errorf("invalid Authorization format for '%s': expected 3 parts delimited by '%s', but found %d parts. Value: '%s'", name, delimiter, len(splitValues))
	}

	// [0] = Header
	// [1] = Payload
	return splitValues[0], splitValues[1], nil
}

func extractSession(ctx *gin.Context, sessionManager SessionManager) (*SessionHeader, *SessionClaims, string, string, error) {
	authorizationData := sessionManager.GetAuthorizationData()
	if authorizationData == nil {
		return nil, nil, "", SourceNone, fmt.Errorf("authorization data is nil")
	}

	source := SourceNone
	authorizationValue, err := GetAuthorizationHeader(ctx, sessionManager)
	if err == nil {
		// - Request is coming from an API key
		source = SourceHeader
	} else {
		authorizationValue, err = GetSessionCookie(ctx, sessionManager)
		if err == nil {
			// - Request is coming from a browser with a session cookie
			source = SourceCookie
		} else {
			// - Request is probably coming from a sessionless browser
			return nil, nil, "", SourceNone, nil
		}
	}

	header, payload, err := extractSessionAuthorizationParts(authorizationData, sessionManager, authorizationValue)
	if err != nil {
		return nil, nil, "", source, fmt.Errorf("failed to extract session Authorization parts: %w", err)
	}

	decodedHeader, err := Decode(header)
	if err != nil {
		return nil, nil, "", source, fmt.Errorf("failed to decode header: %w", err)
	}

	// Note: This explicitly sets the 'HasSession' claim to true as to avoid having to do an implicit session check.
	var claims = &SessionClaims{HasSession: true}
	err = claims.DecodePayload(payload)
	if err != nil {
		return nil, nil, "", source, fmt.Errorf("failed to decode payload: %w", err)
	}

	var group, ok = claims.GetClaim(SessionModeClaim)
	if group == "" || !ok {
		return nil, nil, "", source, fmt.Errorf("session mode claim is missing")
	}

	return &decodedHeader, claims, group, source, nil
}
