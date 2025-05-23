package helpers

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"go.uber.org/zap"
	"net/http"
)

// ErrorResponse sends a JSON error response to the client.
func ErrorResponse(ctx *gin.Context, appErr *errors.AppError) {
	production := gin.Mode() == gin.ReleaseMode

	// - Should not happen.
	if appErr == nil {
		zap.L().Warn("ErrorResponse called with nil error")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "An unexpected error occurred."})
		return
	}

	// - Log the AppError, including its underlying error if present
	logFields := []zap.Field{
		zap.Int("statusCode", appErr.Code),
		zap.String("clientMessage", appErr.Message),
	}

	if appErr.Err != nil {
		logFields = append(logFields, zap.Error(appErr.Err))
	}

	// - Attempt to marshal details for logging if it's complex
	if appErr.Details != nil {
		detailBytes, _ := json.Marshal(appErr.Details)
		logFields = append(logFields, zap.String("details", string(detailBytes)))
	}

	zap.L().Debug("Application error occurred", logFields...)

	// - Send the JSON response using the AppError's ToJSONResponse method
	ctx.JSON(appErr.Code, appErr.ToJSONResponse(production))
	ctx.Abort() // - Ensure no other handlers are called
}

// SuccessResponse sends a JSON success response.
func SuccessResponse(ctx *gin.Context, data interface{}, headers map[string]string) {
	if headers != nil {
		for key, value := range headers {
			ctx.Header(key, value)
		}
	}

	if data == nil {
		ctx.Status(http.StatusNoContent)
		return
	}

	ctx.JSON(http.StatusOK, data)
}
