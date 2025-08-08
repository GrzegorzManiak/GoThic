package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/helpers"
	"strings"
)

func extractCsrfParts(ctx *gin.Context, csrfData *CsrfCookieData, sessionManager SessionManager) (*CompleteCsrfToken, error) {
	if csrfData == nil {
		return nil, fmt.Errorf("csrfData cannot be nil")
	}

	name := helpers.DefaultString(csrfData.Name, DefaultCsrfCookieName)
	csrfHeader := ctx.GetHeader(name)

	// --- Grouped initial validations ---
	if csrfHeader == "" {
		return nil, fmt.Errorf("CSRF header '%s' is missing", name)
	}
	if len(csrfHeader) > MaximumCsrfHeaderSize || len(csrfHeader) < MinimumCsrfHeaderSize {
		return nil, fmt.Errorf("CSRF header '%s' has an invalid size", name)
	}

	csrfCookie, err := ctx.Cookie(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSRF cookie '%s': %w", name, err)
	}
	if csrfCookie != csrfHeader {
		return nil, fmt.Errorf("CSRF token mismatch: header does not match cookie")
	}

	delimiter := helpers.DefaultString(csrfData.Delimiter, DefaultCsrfCookieDelimiter)

	firstDelim := strings.Index(csrfHeader, delimiter)
	if firstDelim == -1 {
		return nil, fmt.Errorf("invalid CSRF token format: missing first delimiter")
	}
	keyVersion := csrfHeader[:firstDelim]

	secondDelim := strings.Index(csrfHeader[firstDelim+1:], delimiter)
	if secondDelim == -1 {
		return nil, fmt.Errorf("invalid CSRF token format: missing second delimiter")
	}
	keyId := csrfHeader[firstDelim+1 : firstDelim+1+secondDelim]

	encryptedValue := csrfHeader[firstDelim+1+secondDelim+1:]
	// --- End manual parsing ---

	if len(keyId) < MinimumCsrfKeyIdSize || len(keyId) > MaximumCsrfKeyIdSize {
		return nil, fmt.Errorf("invalid keyId size in CSRF token")
	}
	if len(keyVersion) < MinimumCsrfCookieVersionSize || len(keyVersion) > MaximumCsrfCookieVersionSize {
		return nil, fmt.Errorf("invalid keyVersion size in CSRF token")
	}

	sessionKey, err := sessionManager.GetOldSessionKey(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get session key for CSRF token: %w", err)
	}

	decodedValue, err := base64.RawURLEncoding.DecodeString(encryptedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode CSRF token: %w", err)
	}

	associatedData := []byte(keyId + keyVersion)
	decryptedValue, err := helpers.SymmetricDecrypt(sessionKey, decodedValue, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CSRF token: %w", err)
	}

	var completeToken CompleteCsrfToken
	if err = json.Unmarshal(decryptedValue, &completeToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal complete CSRF token: %w", err)
	}

	if !completeToken.IsValid() {
		return nil, fmt.Errorf("invalid CSRF token contents")
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
		return nil, fmt.Errorf("CSRF validation failed: %w", err)
	}

	return completeToken, nil
}
