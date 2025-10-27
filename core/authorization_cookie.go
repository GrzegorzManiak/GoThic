package core

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
)

func applySessionCookie(
	ctx *gin.Context,
	authData *SessionAuthorizationConfiguration,
	value string,
	maxAge int,
) {
	ctx.SetCookie(
		helpers.DefaultString(authData.CookieName, DefaultSessionAuthorizationName),
		value,
		maxAge,
		helpers.DefaultString(authData.CookiePath, DefaultSessionAuthorizationPath),
		helpers.DefaultString(authData.CookieDomain, DefaultSessionAuthorizationDomain),
		helpers.DefaultBool(authData.CookieSecure, DefaultSessionAuthorizationSecure),
		helpers.DefaultBool(authData.CookieHttpOnly, DefaultSessionAuthorizationHttpOnly),
	)
}

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

	authorizationData := sessionManager.GetAuthorizationConfiguration()
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

	authorizationData := sessionManager.GetAuthorizationConfiguration()
	return SetCustomSessionCookie(ctx, sessionManager, group, claims, authorizationData)
}

func SetCustomSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	group string,
	claims *SessionClaims,
	authorizationData *SessionAuthorizationConfiguration,
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

	expirationSeconds := int(helpers.DefaultTimeDuration(authorizationData.Expiration, DefaultSessionExpiration).Seconds())
	applySessionCookie(ctx, authorizationData, authorizationString, expirationSeconds)

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

	authorizationData := sessionManager.GetAuthorizationConfiguration()
	return SetCustomRefreshSessionCookie(ctx, sessionManager, claims, header, authorizationData)
}

func SetCustomRefreshSessionCookie(
	ctx *gin.Context,
	sessionManager SessionManager,
	claims *SessionClaims,
	header *SessionHeader,
	authorizationData *SessionAuthorizationConfiguration,
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

	expirationSeconds := int(helpers.DefaultTimeDuration(authorizationData.Expiration, DefaultSessionExpiration).Seconds())
	applySessionCookie(ctx, authorizationData, authorizationString, expirationSeconds)

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

	authorizationData := sessionManager.GetAuthorizationConfiguration()
	if authorizationData == nil {
		return errors.NewInternalServerError("Authorization data is nil", nil)
	}

	applySessionCookie(ctx, authorizationData, "", -1)

	if err := ClearCsrfCookie(ctx, sessionManager); err != nil {
		return errors.NewInternalServerError("Failed to clear session", err)
	}

	return nil
}
