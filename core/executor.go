package core

import (
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
	"github.com/grzegorzmaniak/gothic/rbac"
	"github.com/grzegorzmaniak/gothic/validation"
	"go.uber.org/zap"
)

// _establishSessionContext handles session extraction, validation, refresh, and claims verification.
// It returns the session header, claims, session group, or an AppError if processing fails.
// Note: The error messages are intentionally left blank as then they are filled in by the default for
// that specific error type. This is to avoid leaking information about the session state to the client.
func _establishSessionContext(
	ctx *gin.Context,
	sessionManager SessionManager,
	sessionConfig *APIConfiguration,
) (*SessionHeader, *SessionClaims, *CompleteCsrfToken, string, *errors.AppError) {

	header, claims, group, tokenType, sessionErr := extractSession(ctx, sessionManager)

	// - Check if a session is required and if the session extraction failed
	if sessionErr != nil && sessionConfig.SessionRequired {
		zap.L().Debug("Session required but extraction failed", zap.Error(sessionErr), zap.String("group_attempted", group))
		return nil, nil, nil, "", errors.NewUnauthorized("", sessionErr)
	}

	switch tokenType {
	case SourceHeader:
		return establishBearerSession(ctx, sessionManager, sessionConfig, claims, header, group)

	case SourceCookie,
		SourceNone:
		return establishCookieSession(ctx, sessionManager, sessionConfig, claims, header, group)

	default:
		zap.L().Debug("Session extraction failed", zap.Error(sessionErr), zap.String("group_attempted", group))
		return nil, nil, nil, "", errors.NewUnauthorized("Invalid session source", sessionErr)
	}
}

func establishBearerSession(
	ctx *gin.Context,
	sessionManager SessionManager,
	sessionConfig *APIConfiguration,
	claims *SessionClaims,
	header *SessionHeader,
	group string,
) (*SessionHeader, *SessionClaims, *CompleteCsrfToken, string, *errors.AppError) {
	// - Validate the bearer SessionHeader if present (even if a session is not required, if a header exists, it should be valid)
	if header != nil && (header.IsExpired() || !header.IsValid()) {
		zap.L().Debug("Bearer session header is invalid or expired", zap.Any("header", header))
		if sessionConfig.SessionRequired {
			return nil, nil, nil, "", errors.NewUnauthorized("", nil)
		}

		header = nil
		claims = nil
		group = ""
	}

	// - Check if the bearer needs to be revalidated
	// Bearer tokens are static and cannot be refreshed; they can only be revalidated.
	// The refresh indicator is stored in the header, which itself cannot be updated.
	// To track refresh timing, a cache is used to store the last refresh time.
	cacheKey, needsRefresh, err := BearerNeedsValidation(ctx, sessionManager, claims)
	if err != nil {
		zap.L().Debug("Error checking if bearer needs validation", zap.Error(err))
		if sessionConfig.SessionRequired {
			return nil, nil, nil, "", errors.NewInternalServerError("", err)
		}

		header = nil
		claims = nil
		group = ""
	}

	if header != nil && claims != nil && needsRefresh {
		// - Verify the session
		if ok, reAuthErr := sessionManager.VerifySession(ctx, claims, header); reAuthErr != nil || !ok {
			return nil, nil, nil, "", errors.NewUnauthorized("", reAuthErr)
		}

		// - Cache the refresh time
		if cacheErr := BearerSetCache(ctx, sessionManager, cacheKey, header); cacheErr != nil {
			zap.L().Debug("Error setting bearer cache", zap.Error(cacheErr))
			return nil, nil, nil, "", errors.NewInternalServerError("", cacheErr)
		}
	}

	isClaimsVerified, verifyErr := sessionManager.VerifyClaims(ctx, claims, sessionConfig)
	if sessionConfig.SessionRequired {

		// - Claims verification failed, but a session is required
		if verifyErr != nil || !isClaimsVerified {
			zap.L().Debug("Bearer required but claims verification failed", zap.Error(verifyErr), zap.Bool("isClaimsVerified", isClaimsVerified))
			return nil, nil, nil, "", errors.NewUnauthorized("", verifyErr)
		}

		// - Insurance: if a session is required, claims must exist and be marked as having a session
		if claims == nil || !claims.HasSession {
			zap.L().Error("Bearer required, but claims are nil or marked as no session after all checks", zap.Any("claims", claims))
			return nil, nil, nil, "", errors.NewInternalServerError("", nil)
		}
	}

	// - If a session is not required, but claims exist and verification failed,
	// it might be treated as an invalid optional session (effectively no session).
	// For simplicity, if VerifyClaims fails for an *existing* optional session, we clear it.
	if !sessionConfig.SessionRequired && claims != nil && (verifyErr != nil || !isClaimsVerified) {
		zap.L().Debug("Optional bearer presented but claims verification failed", zap.Error(verifyErr), zap.Bool("isClaimsVerified", isClaimsVerified))
		header = nil
		claims = nil
		group = ""
	}

	// - Bearers are not tied to CSRF tokens, so we don't need to validate CSRF here
	return header, claims, nil, group, nil
}

func establishCookieSession(
	ctx *gin.Context,
	sessionManager SessionManager,
	sessionConfig *APIConfiguration,
	claims *SessionClaims,
	header *SessionHeader,
	group string,
) (*SessionHeader, *SessionClaims, *CompleteCsrfToken, string, *errors.AppError) {

	var csrfToken *CompleteCsrfToken
	var csrfErr error

	csrfToken, csrfErr = extractCsrf(ctx, sessionManager)
	if csrfErr != nil {
		csrfToken = nil

		// Note: At this stage we don't really want to trust the claims object, could be stale etc, so
		// we will just issue a new anonymous CSRF token
		if err := AutoSetCsrfCookie(ctx, sessionManager, nil); err != nil {
			zap.L().Debug("Error attempting to set CSRF cookie", zap.Error(err))
			return nil, nil, nil, "", errors.NewInternalServerError("Failed to set CSRF cookie", err)
		}

		// Since the dev decided that we don't need CSRF on this route, we will just set csrf to nil
		// which will bypass all further CSRF checks below
		if sessionConfig.RequireCsrf {
			zap.L().Debug("CSRF token is invalid or expired", zap.Error(csrfErr))
			return nil, nil, nil, "", errors.NewUnauthorized("CSRF token is invalid or expired", csrfErr)
		}
	}

	// - Validate the SessionHeader if present (even if a session is not required, if a header exists, it should be valid)
	if header != nil && (header.IsExpired() || !header.IsValid()) {
		zap.L().Debug("Session header is invalid or expired", zap.Any("header", header))
		if sessionConfig.SessionRequired {
			return nil, nil, nil, "", errors.NewUnauthorized("", nil)
		}

		header = nil
		claims = nil
		group = ""
	}

	// - Refresh the SessionHeader if present, valid, and needs refresh
	if header != nil && claims != nil && header.NeedsRefresh() {
		if err := SetRefreshSessionCookie(ctx, sessionManager, claims, header); err != nil {
			zap.L().Debug("Error attempting to refresh session cookie", zap.Error(err))
			return nil, nil, nil, "", errors.NewInternalServerError("Failed to refresh session", err)
		}
	}

	isClaimsVerified, verifyErr := sessionManager.VerifyClaims(ctx, claims, sessionConfig)
	if sessionConfig.SessionRequired {

		// - Claims verification failed, but a session is required
		if verifyErr != nil || !isClaimsVerified {
			zap.L().Debug("Session required but claims verification failed", zap.Error(verifyErr), zap.Bool("isClaimsVerified", isClaimsVerified))
			return nil, nil, nil, "", errors.NewUnauthorized("", verifyErr)
		}

		// - Insurance: if a session is required, claims must exist and be marked as having a session
		if claims == nil || !claims.HasSession {
			zap.L().Error("Session required, but claims are nil or marked as no session after all checks", zap.Any("claims", claims))
			return nil, nil, nil, "", errors.NewInternalServerError("", nil)
		}
	}

	// - If a session is not required, but claims exist and verification failed,
	// it might be treated as an invalid optional session (effectively no session).
	// For simplicity, if VerifyClaims fails for an *existing* optional session, we clear it.
	if !sessionConfig.SessionRequired && claims != nil && (verifyErr != nil || !isClaimsVerified) {
		zap.L().Debug("Optional session presented but claims verification failed", zap.Error(verifyErr), zap.Bool("isClaimsVerified", isClaimsVerified))
		header = nil
		claims = nil
		group = ""
	}

	// - CSRF validation
	if err := validateCsrf(ctx, sessionManager, claims, csrfToken); err != nil {
		zap.L().Debug("CSRF validation failed", zap.Error(err))
		if sessionConfig.RequireCsrf {
			return nil, nil, nil, "", errors.NewUnauthorized("CSRF token is invalid or expired", err)
		}
		csrfToken = &CompleteCsrfToken{}
	}

	return header, claims, csrfToken, group, nil
}

// validateCsrf checks if the CSRF token is valid and matches the session claims.
func validateCsrf(
	ctx *gin.Context,
	sessionManager SessionManager,
	claims *SessionClaims,
	csrfToken *CompleteCsrfToken,
) error {
	if csrfToken == nil {
		return errors.NewUnauthorized("CSRF token is required", nil)
	}

	// - Get the x-CSRF token from the header
	if !csrfToken.IsValid() || csrfToken.IsExpired() {
		if err := AutoSetCsrfCookie(ctx, sessionManager, claims); err != nil {
			zap.L().Debug("Error attempting to set CSRF cookie", zap.Error(err))
			return errors.NewInternalServerError("Failed to set CSRF cookie", err)
		}

		return errors.NewUnauthorized("CSRF token is invalid or expired", nil)
	}

	// - If the CSRF token is not tied, but the user holds a session, it means that they are using a token
	// that belongs to an anonymous session. This is not allowed, as if the user is authenticated, they should
	// use the CSRF token tied to their session.
	if !csrfToken.Tied && claims != nil && claims.HasSession {
		if err := AutoSetCsrfCookie(ctx, sessionManager, claims); err != nil {
			zap.L().Debug("Error attempting to set CSRF cookie", zap.Error(err))
			return errors.NewInternalServerError("Failed to set CSRF cookie", err)
		}

		return errors.NewUnauthorized("CSRF token is invalid or expired", nil)
	}

	if claims != nil && csrfToken.Tied {
		csrfTie, ok := claims.GetClaim(CsrfTokenTie)
		if csrfTie != csrfToken.Tie || !ok {
			if err := AutoSetCsrfCookie(ctx, sessionManager, claims); err != nil {
				zap.L().Debug("Error attempting to set CSRF cookie", zap.Error(err))
				return errors.NewInternalServerError("Failed to set CSRF cookie", err)
			}

			return errors.NewUnauthorized("CSRF token is invalid or expired", nil)
		}
	}

	// - Csrf need refresh
	if csrfToken.NeedsRefresh() {
		if err := AutoSetCsrfCookie(ctx, sessionManager, claims); err != nil {
			zap.L().Debug("Error attempting to set CSRF cookie", zap.Error(err))
			return errors.NewInternalServerError("Failed to set CSRF cookie", err)
		}
	}

	return nil
}

// prepareHandlerData validates input and fetches the subject if required.
// It returns the validated input, subject, subject-fetched status, or an AppError.
func prepareHandlerData[InputType any](
	ctx *gin.Context,
) (*InputType, *errors.AppError) {

	// - Input validation
	input, inputErr := validation.InputData[InputType](ctx)
	if inputErr != nil {
		zap.L().Debug("Error validating input data", zap.Error(inputErr), zap.Any("raw_input_attempt", input)) // 'input' might be partially populated or nil on error
		return nil, inputErr
	}

	return input, nil
}

// processAndSendHandlerOutput validates the handler's output and sends the response.
// Returns an AppError if output processing fails.
func processAndSendHandlerOutput[OutputType any](
	ctx *gin.Context,
	output *OutputType,
	sessionConfig *APIConfiguration,
) *errors.AppError {

	// - Processing stops here, handler is responsible for response
	if sessionConfig.ManualResponse {
		zap.L().Debug("Response handling is manual for this route", zap.Any("output_given_by_handler", output))
		return nil
	}

	// - Output validation
	responseHeaders, responseBody, outputValErr := validation.OutputData(output)
	if outputValErr != nil {
		zap.L().Debug("Error validating output data", zap.Error(outputValErr), zap.Any("raw_output_from_handler", output))
		return outputValErr
	}

	// - Success response
	helpers.SuccessResponse(ctx, 200, responseBody, responseHeaders)
	return nil
}

// processRbac checks if RBAC is enabled and validates permissions/roles.
func processRbac(
	ctx *gin.Context,
	sessionManager SessionManager,
	sessionConfig *APIConfiguration,
	claims *SessionClaims,
) *errors.AppError {
	if (sessionConfig.Roles == nil && sessionConfig.Permissions == nil) || claims == nil {
		return nil
	}

	rbacManager := sessionManager.GetRbacManager()
	if rbacManager == nil {
		return errors.NewInternalServerError("RBAC manager is not set", nil)
	}

	rbacCacheId, ok := claims.GetClaim(RbacCacheIdentifier)
	if !ok || len(rbacCacheId) != helpers.AESKeySize32 {
		zap.L().Debug("RBAC cache ID is not set or invalid", zap.Any("rbacCacheId", rbacCacheId))
		return errors.NewInternalServerError("RBAC cache ID is not set or invalid", nil)
	}

	// - Get the subject identifier from the claims
	subjectIdentifier, err := sessionManager.GetSubjectIdentifier(claims)
	if err != nil {
		zap.L().Debug("Error getting subject identifier", zap.Error(err))
		return errors.NewInternalServerError("Failed to get subject identifier", err)
	}

	rbacOk, err := rbac.CheckPermissions(
		ctx,
		rbacManager,
		subjectIdentifier,
		rbacCacheId,
		sessionConfig.GetFlatPermissions(),
		sessionConfig.GetFlatRoles(),
		sessionConfig.RbacPolicy,
	)
	if err != nil {
		zap.L().Debug("Error checking permissions", zap.Error(err))
		return errors.NewInternalServerError("Failed to check permissions", err)
	}

	if !rbacOk {
		zap.L().Debug("RBAC permissions check failed", zap.Any("rbacCacheId", rbacCacheId))
		insufficientPermsErr := errors.NewUnauthorized("Insufficient permissions", nil)
		insufficientPermsErr.Details = map[string]interface{}{
			"permissions": sessionConfig.Permissions,
			"roles":       sessionConfig.Roles,
		}
		return insufficientPermsErr
	}

	return nil
}

// ExecuteRoute orchestrates the request handling lifecycle, including session management,
// input validation, subject fetching, handler execution, and response generation.
func ExecuteRoute[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	ctx *gin.Context,
	baseRoute BaseRoute,
	sessionConfig *APIConfiguration,
	sessionManager SessionManager,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	// - Stage 1: Establish Session Context
	header, claims, csrfToken, group, appErr := _establishSessionContext(ctx, sessionManager, sessionConfig)
	if appErr != nil {
		helpers.ErrorResponse(ctx, appErr)
		return
	}

	// - Rbac
	if rbacErr := processRbac(ctx, sessionManager, sessionConfig, claims); rbacErr != nil {
		zap.L().Debug("RBAC processing failed", zap.Error(rbacErr))
		helpers.ErrorResponse(ctx, rbacErr)
		return
	}

	// - Stage 2: Prepare Handler Input and Subject Data
	input, appErr := prepareHandlerData[InputType](ctx)
	if appErr != nil {
		helpers.ErrorResponse(ctx, appErr)
		return
	}

	// - Stage 3: Call the specific business logic handler
	output, handlerAppErr := handlerFunc(input, &Handler[BaseRoute]{
		BaseRoute:      baseRoute,
		Context:        ctx,
		SessionHeader:  header,
		Claims:         claims,
		HasSession:     claims != nil && claims.HasSession,
		SessionManager: sessionManager,
		SessionGroup:   group,
		CsrfToken:      csrfToken,
	})

	if handlerAppErr != nil {
		zap.L().Debug("Error returned from route handler", zap.Error(handlerAppErr), zap.Any("input", input))
		helpers.ErrorResponse(ctx, handlerAppErr)
		return
	}

	// - Stage 4: Process Handler Output and Send Response
	if appErr = processAndSendHandlerOutput[OutputType](ctx, output, sessionConfig); appErr != nil {
		helpers.ErrorResponse(ctx, appErr)
	}
}
