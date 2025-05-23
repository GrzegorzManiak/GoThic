package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/grzegorzmaniak/gothic/helpers"
	"time"
)

const (
	DefaultCsrfCookieName      = "X-CSRF-Token"
	DefaultCsrfCookiePath      = "/"
	DefaultCsrfCookieDomain    = ""
	DefaultCsrfCookieSecure    = true
	DefaultCsrfCookieHttpOnly  = false // If true, cookie cannot be accessed by client-side scripts (used when setting)
	DefaultCsrfCookieSameSite  = "Strict"
	DefaultCsrfCookieDelimiter = "."

	DefaultCsrfExpiration  = time.Hour * 8
	DefaultCsrfRefreshTime = time.Minute * 30

	MinimumCsrfHeaderSize = 128  // Minimum size for a cookie to be valid
	MaximumCsrfHeaderSize = 1024 // Should not get bigger than 1KB as the cookie as it stores a fixed size of data

	MinimumCsrfKeyIdSize = 1  // Minimum size for a key ID to be valid
	MaximumCsrfKeyIdSize = 32 // 32 bytes for AES-256

	CsrfCookieVersion            = "CG1" // Version of the cookie format
	MaximumCsrfCookieVersionSize = 32    // Maximum size for the version string
	MinimumCsrfCookieVersionSize = 1     // Minimum size for the version string

	DefaultCsrfTokenTieSize = 32 // Default size for the CSRF
)

type CsrfCookieData struct {
	Name     string // Name of the cookie
	Path     string // Path for which the cookie is valid (used when setting)
	Domain   string // Domain for which the cookie is valid (used when setting)
	Secure   bool   // If true, cookie only sent over HTTPS (used when setting)
	HttpOnly bool   // If true, cookie cannot be accessed by client-side scripts (used when setting)
	SameSite string // SameSite attribute (e.g., "Strict", "Lax", "None") (used when setting)

	// Delimiter is used to split the cookie's value into parts.
	// For example, if the cookie value is "header.payload.signature", the delimiter is ".".
	Delimiter string

	// Expiration is the expiration time of the session in seconds, after which the csrf token is considered expired
	// and cannot be used. Default is 8 hours.
	Expiration time.Duration

	// RefreshTime is the time after which the csrf should be refreshed
	// default is 30 minutes.
	RefreshTime time.Duration

	// CsrfTokenSize is the size of the CSRF token, default is 32 bytes.
	CsrfTokenSize int
}

type CompleteCsrfToken struct {
	CsrfHeader
	Token   string
	Tie     string
	Version string
	Tied    bool
}

func (c *CompleteCsrfToken) IsEmpty() bool {
	return c == nil || len(c.Token) == 0
}

func CreateCsrfToken(
	sessionManager SessionManager,
	cookieData CsrfCookieData,
	csrfTie string,
) (string, error) {
	if sessionManager == nil {
		return "", fmt.Errorf("CSRF, session manager is nil")
	}

	token, err := helpers.GenerateID(helpers.DefaultInt(cookieData.CsrfTokenSize, DefaultCsrfTokenTieSize))
	if err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	csrfExpiration := helpers.DefaultTimeDuration(cookieData.Expiration, DefaultCsrfExpiration)
	csrfRefreshTime := helpers.DefaultTimeDuration(cookieData.RefreshTime, DefaultCsrfRefreshTime)

	completeToken := &CompleteCsrfToken{
		CsrfHeader: NewCsrfHeader(csrfExpiration, csrfRefreshTime),
		Tie:        csrfTie,
		Tied:       len(csrfTie) > 0,
		Version:    CsrfCookieVersion,
		Token:      token,
	}

	marshaledToken, err := json.Marshal(completeToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal complete CSRF token: %w", err)
	}

	// - Fetch the session key from the session manager
	sessionKey, keyId, err := sessionManager.GetSessionKey()
	if err != nil {
		return "", fmt.Errorf("failed to get session key: %w", err)
	}

	if len(keyId) < MinimumCsrfKeyIdSize {
		return "", fmt.Errorf("CSRF keyId is too short, must be at least %d characters", MinimumCsrfKeyIdSize)
	}

	if len(keyId) > MaximumCsrfKeyIdSize {
		return "", fmt.Errorf("CSRF keyId is too long, must be at most %d characters", MaximumCsrfKeyIdSize)
	}

	// - Encrypt the cookie value
	encryptedValue, err := helpers.SymmetricEncrypt(sessionKey, marshaledToken, []byte(keyId+CsrfCookieVersion))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt CSRF value: %w", err)
	}

	// - Encode the encrypted value to base64
	encodedValue := base64.RawURLEncoding.EncodeToString(encryptedValue)
	delimiter := helpers.DefaultString(cookieData.Delimiter, DefaultCsrfCookieDelimiter)

	return fmt.Sprintf("%s%s%s%s%s",
		completeToken.Version,
		delimiter,
		keyId,
		delimiter,
		encodedValue,
	), nil
}
