package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/helpers"
	"strings"
)

// Note: I'm well aware that this is almost a copy of the extractSessionCookieParts function,
// I just want to make code as simple to follow, so no fancy config stuff, just self-descriptive variable names
// and a big separation of concerns.
func extractCsrfParts(ctx *gin.Context, csrfData *CsrfCookieData, sessionManager SessionManager) (*CompleteCsrfToken, error) {
	if csrfData == nil {
		return nil, fmt.Errorf("csrfData cannot be nil")
	}

	delimiter := helpers.DefaultString(csrfData.Delimiter, DefaultCsrfCookieDelimiter)
	name := helpers.DefaultString(csrfData.Name, DefaultCsrfCookieName)
	csrfHeader := ctx.GetHeader(name)

	if csrfHeader == "" {
		return nil, fmt.Errorf("csrfHeader '%s' is empty", name)
	}

	if len(csrfHeader) > MaximumCsrfHeaderSize {
		return nil, fmt.Errorf("csrfHeader '%s' exceeds maximum size of %d bytes", name, MaximumCsrfHeaderSize)
	}

	if len(csrfHeader) < MinimumCsrfHeaderSize {
		return nil, fmt.Errorf("csrfHeader '%s' is too small, minimum size is %d bytes", name, MinimumCsrfHeaderSize)
	}

	csrfCookie, err := ctx.Cookie(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cookie '%s': %w", name, err)
	}

	if csrfCookie != csrfHeader {
		return nil, fmt.Errorf("csrfHeader '%s' does not match cookie '%s'", name, csrfCookie)
	}

	// - Extract the keyID from the cookie value
	splitValues := strings.SplitN(csrfHeader, delimiter, 3)
	if len(splitValues) != 3 {
		return nil, fmt.Errorf("invalid csrfHeader format for '%s': expected 3 parts delimited by '%s', but found %d parts. Value: '%s'",
			name,
			delimiter,
			len(splitValues),
		)
	}

	keyVersion := splitValues[0]
	keyId := splitValues[1]
	csrfValue := splitValues[2]

	// - Validate the keyId length
	if len(keyId) > MaximumCsrfKeyIdSize {
		return nil, fmt.Errorf("invalid keyId length for cookie '%s': expected %d bytes, but found %d bytes", name, MaximumCsrfKeyIdSize, len(keyId))
	}

	if len(keyId) < MinimumCsrfKeyIdSize {
		return nil, fmt.Errorf("keyId '%s' is too small, minimum size is %d bytes", keyId, MinimumCsrfKeyIdSize)
	}

	// - Validate the keyVersion length
	if len(keyVersion) > MaximumCsrfCookieVersionSize {
		return nil, fmt.Errorf("invalid keyVersion length for cookie '%s': expected %d bytes, but found %d bytes", name, MaximumCsrfCookieVersionSize, len(keyVersion))
	}

	if len(keyVersion) < MinimumCsrfCookieVersionSize {
		return nil, fmt.Errorf("keyVersion '%s' is too small, minimum size is %d bytes", keyVersion, MinimumCsrfCookieVersionSize)
	}

	// - Get the session key
	sessionKey, err := sessionManager.GetOldSessionKey(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get session key for keyId '%s': %w", keyId, err)
	}

	// - Decode the cookie value
	decodedValue, err := base64.RawURLEncoding.DecodeString(csrfValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 value for cookie '%s': %w", name, err)
	}

	// - Decrypt the cookie
	decryptedValue, err := helpers.SymmetricDecrypt(sessionKey, decodedValue, []byte(keyId+keyVersion))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt cookie '%s': %w", name, err)
	}
	csrfValue = string(decryptedValue)

	// - Unmarshal the decrypted value into a CompleteCsrfToken
	var completeToken CompleteCsrfToken
	err = json.Unmarshal([]byte(csrfValue), &completeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal complete CSRF token: %w", err)
	}

	if !completeToken.IsValid() {
		return nil, fmt.Errorf("invalid CSRF token")
	}

	return &completeToken, nil
}

func extractCsrf(ctx *gin.Context, sessionManager SessionManager) (*CompleteCsrfToken, error) {
	if sessionManager == nil {
		return nil, fmt.Errorf("session manager is nil")
	}

	cookieData := sessionManager.GetCsrfData()
	if cookieData == nil {
		return nil, fmt.Errorf("CSRF cookie data is nil")
	}

	completeToken, err := extractCsrfParts(ctx, cookieData, sessionManager)
	if err != nil {
		return nil, fmt.Errorf("failed to extract CSRF cookie parts: %w", err)
	}

	return completeToken, nil
}
