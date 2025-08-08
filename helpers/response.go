package helpers

import (
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"go.uber.org/zap"
	"net/http"
)

// ErrorResponse sends a JSON error response to the client.
func ErrorResponse(ctx *gin.Context, appErr *errors.AppError) {
	production := gin.Mode() == gin.ReleaseMode

	if appErr == nil {
		zap.L().Warn("ErrorResponse called with nil error")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "An unexpected error occurred."})
		return
	}

	logFields := []zap.Field{
		zap.Int("statusCode", appErr.Code),
		zap.String("clientMessage", appErr.Message),
	}

	if appErr.Err != nil {
		logFields = append(logFields, zap.Error(appErr.Err))
	}

	if appErr.Details != nil {
		logFields = append(logFields, zap.Any("details", appErr.Details))
	}

	zap.L().Error("Application error occurred", logFields...)
	ctx.AbortWithStatusJSON(appErr.Code, appErr.ToJSONResponse(production))
}

// SuccessResponse sends a JSON success response.
func SuccessResponse(ctx *gin.Context, statusCode int, data interface{}, headers map[string]string) {
	if headers != nil {
		for key, value := range headers {
			ctx.Header(key, value)
		}
	}

	if data == nil {
		ctx.Status(statusCode)
		return
	}

	ctx.JSON(statusCode, data)
}
