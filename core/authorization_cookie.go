package core

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
)

func GetSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("context is nil")
	}

	if sessionManager == nil {
		return "", fmt.Errorf("session manager is nil")
	}

	authorizationData := sessionManager.GetAuthorizationData()
	if authorizationData == nil {
		return "", fmt.Errorf("authorization data is nil")
	}

	authorizationCookieName := helpers.DefaultString(authorizationData.CookieName, DefaultSessionAuthorizationName)
	authorizationCookieValue, err := ctx.Cookie(authorizationCookieName)
	if err != nil || authorizationCookieValue == "" {
		return "", fmt.Errorf("failed to get cookie '%s': %w", authorizationCookieName, err)
	}

	return authorizationCookieValue, nil
}

func SetSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	group string,
	claims *SessionClaims,
) error {
	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	authorizationData := sessionManager.GetAuthorizationData()
	return SetCustomSessionCookie(ctx, sessionManager, group, claims, authorizationData)
}

func SetCustomSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	group string,
	claims *SessionClaims,
	authorizationData *SessionAuthorizationData,
) error {
	if ctx == nil {
		return errors.NewInternalServerError("Context is nil", nil)
	}

	if claims == nil {
		return errors.NewInternalServerError("Session not valid", nil)
	}

	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	if authorizationData == nil {
		return errors.NewInternalServerError("Authorization data is nil", nil)
	}

	// - Create the Authorization header
	sessionExpiration := helpers.DefaultTimeDuration(authorizationData.Expiration, DefaultSessionExpiration)
	sessionRefreshTime := helpers.DefaultTimeDuration(authorizationData.RefreshTime, DefaultSessionRefreshTime)
	authorizationHeader := NewSessionHeader(false, sessionExpiration, sessionRefreshTime)
	authorizationString, err := CreateAuthorization(group, &authorizationHeader, *authorizationData, claims, sessionManager)
	if err != nil {
		return err
	}

	if err = sessionManager.StoreSession(ctx, claims, nil); err != nil {
		return errors.NewInternalServerError("Failed to store session", err)
	}

	ctx.SetCookie(
		helpers.DefaultString(authorizationData.CookieName, DefaultSessionAuthorizationName),
		authorizationString,
		int(helpers.DefaultTimeDuration(authorizationData.Expiration, DefaultSessionExpiration).Seconds()),
		helpers.DefaultString(authorizationData.CookiePath, DefaultSessionAuthorizationPath),
		helpers.DefaultString(authorizationData.CookieDomain, DefaultSessionAuthorizationDomain),
		helpers.DefaultBool(authorizationData.CookieSecure, DefaultSessionAuthorizationSecure),
		helpers.DefaultBool(authorizationData.CookieHttpOnly, DefaultSessionAuthorizationHttpOnly),
	)

	csrfTie, _ := claims.GetClaim(CsrfTokenTie)
	err = SetCsrfCookie(ctx, sessionManager, csrfTie)
	if err != nil {
		return errors.NewInternalServerError("Failed to set CSRF Authorization", err)
	}

	return nil
}

func SetRefreshSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	claims *SessionClaims,
	header *SessionHeader,
) error {
	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	authorizationData := sessionManager.GetAuthorizationData()
	return SetCustomRefreshSessionCookie(ctx, sessionManager, claims, header, authorizationData)
}

func SetCustomRefreshSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	claims *SessionClaims,
	header *SessionHeader,
	authorizationData *SessionAuthorizationData,
) error {
	if ctx == nil {
		return errors.NewInternalServerError("Context is nil", nil)
	}

	if claims == nil {
		return errors.NewInternalServerError("Session not valid", nil)
	}

	if header == nil {
		return errors.NewInternalServerError("Session header is nil", nil)
	}

	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	if ok, err := sessionManager.VerifySession(ctx, claims, header); err != nil || !ok {
		return errors.NewInternalServerError("Session not valid", err)
	}

	if authorizationData == nil {
		return errors.NewInternalServerError("Authorization data is nil", nil)
	}

	authorizationString, err := CreateRefreshAuthorization(*authorizationData, claims, header, sessionManager)
	if err != nil {
		return err
	}

	ctx.SetCookie(
		helpers.DefaultString(authorizationData.CookieName, DefaultSessionAuthorizationName),
		authorizationString,
		int(helpers.DefaultTimeDuration(authorizationData.Expiration, DefaultSessionExpiration).Seconds()),
		helpers.DefaultString(authorizationData.CookiePath, DefaultSessionAuthorizationPath),
		helpers.DefaultString(authorizationData.CookieDomain, DefaultSessionAuthorizationDomain),
		helpers.DefaultBool(authorizationData.CookieSecure, DefaultSessionAuthorizationSecure),
		helpers.DefaultBool(authorizationData.CookieHttpOnly, DefaultSessionAuthorizationHttpOnly),
	)

	return nil
}

func ClearSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
) error {
	if ctx == nil {
		return errors.NewInternalServerError("Context is nil", nil)
	}

	if sessionManager == nil {
		return errors.NewInternalServerError("Session manager is nil", nil)
	}

	authorizationData := sessionManager.GetAuthorizationData()
	if authorizationData == nil {
		return errors.NewInternalServerError("Authorization data is nil", nil)
	}

	ctx.SetCookie(
		helpers.DefaultString(authorizationData.CookieName, DefaultSessionAuthorizationName),
		"",
		-1,
		helpers.DefaultString(authorizationData.CookiePath, DefaultSessionAuthorizationPath),
		helpers.DefaultString(authorizationData.CookieDomain, DefaultSessionAuthorizationDomain),
		helpers.DefaultBool(authorizationData.CookieSecure, DefaultSessionAuthorizationSecure),
		helpers.DefaultBool(authorizationData.CookieHttpOnly, DefaultSessionAuthorizationHttpOnly),
	)

	if err := ClearCsrfCookie(ctx, sessionManager); err != nil {
		return errors.NewInternalServerError("Failed to clear session", err)
	}

	return nil
}
