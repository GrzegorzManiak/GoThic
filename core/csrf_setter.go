package core

import (
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
)

// CookieConfig holds all the generic parameters for setting a cookie.
type CookieConfig struct {
	Name     string
	Value    string
	MaxAge   int
	Path     string
	Domain   string
	Secure   bool
	HttpOnly bool
}

func applyCsrfCookie(
	ctx *gin.Context,
	csrfData *CsrfCookieData,
	value string,
	maxAge int,
) {
	// - Ensure that there is no other cookie with the same name
	if ctx == nil {
		return
	}

	ctx.SetCookie(
		helpers.DefaultString(csrfData.Name, DefaultCsrfCookieName),
		value,
		maxAge,
		helpers.DefaultString(csrfData.Path, DefaultCsrfCookiePath),
		helpers.DefaultString(csrfData.Domain, DefaultCsrfCookieDomain),
		helpers.DefaultBool(csrfData.Secure, DefaultCsrfCookieSecure),
		helpers.DefaultBool(csrfData.HttpOnly, DefaultCsrfCookieHttpOnly),
	)
}

func SetCsrfCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	csrfTie string,
) error {
	if ctx == nil {
		return errors.NewInternalServerError("Context is nil", nil)
	}
	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}
	csrfData := sessionManager.GetCsrfData()
	if csrfData == nil {
		return errors.NewInternalServerError("Csrf data is nil", nil)
	}

	csrfString, err := CreateCsrfToken(sessionManager, *csrfData, csrfTie)
	if err != nil {
		return err
	}

	applyCsrfCookie(ctx, csrfData, csrfString, int(helpers.DefaultTimeDuration(csrfData.Expiration, DefaultCsrfExpiration).Seconds()))

	return nil
}

func AutoSetCsrfCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	claims *SessionClaims,
) error {
	if ctx == nil {
		return errors.NewInternalServerError("Context is nil", nil)
	}
	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	// - Handle anonymous user
	if claims == nil {
		return SetCsrfCookie(ctx, sessionManager, "")
	}

	// - Handle authenticated user
	csrfTie, ok := claims.GetClaim(CsrfTokenTie)
	if !ok || csrfTie == "" {
		return errors.NewInternalServerError("Csrf token tie is missing or empty", nil)
	}

	return SetCsrfCookie(ctx, sessionManager, csrfTie)
}

// ClearCsrfCookie now performs a true browser-level deletion of the cookie.
func ClearCsrfCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
) error {
	if ctx == nil {
		return errors.NewInternalServerError("Context is nil", nil)
	}
	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}
	csrfData := sessionManager.GetCsrfData()
	if csrfData == nil {
		return errors.NewInternalServerError("Csrf data is nil", nil)
	}

	applyCsrfCookie(ctx, csrfData, "", -1)

	return nil
}
