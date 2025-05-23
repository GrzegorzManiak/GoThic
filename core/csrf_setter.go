package core

import (
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
)

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

	ctx.SetCookie(
		helpers.DefaultString(csrfData.Name, DefaultCsrfCookieName),
		csrfString,
		int(helpers.DefaultTimeDuration(csrfData.Expiration, DefaultCsrfExpiration).Seconds()),
		helpers.DefaultString(csrfData.Path, DefaultCsrfCookiePath),
		helpers.DefaultString(csrfData.Domain, DefaultCsrfCookieDomain),
		helpers.DefaultBool(csrfData.Secure, DefaultCsrfCookieSecure),
		helpers.DefaultBool(csrfData.HttpOnly, DefaultCsrfCookieHttpOnly),
	)

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

	// - Anonymous user
	if claims == nil {
		return SetCsrfCookie(ctx, sessionManager, "")
	}

	// - Authenticated user
	csrfTie, ok := claims.GetClaim(CsrfTokenTie)
	if !ok {
		return errors.NewInternalServerError("Csrf token tie not found", nil)
	}

	if len(csrfTie) == 0 {
		return errors.NewInternalServerError("Csrf token tie is empty", nil)
	}

	return SetCsrfCookie(ctx, sessionManager, csrfTie)
}

func ClearCsrfCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
) error {
	return AutoSetCsrfCookie(ctx, sessionManager, nil)
}
