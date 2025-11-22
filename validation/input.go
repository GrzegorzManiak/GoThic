package validation

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
)

func bindInput(ctx *gin.Context, target interface{}) *errors.AppError {
	// - Bind URI Parameters (Path variables)
	if err := ctx.ShouldBindUri(target); err != nil {
		return errors.NewValidationFailed("Failed to bind URI parameters", err)
	}

	// - Bind Headers (Universal between all requests)
	if err := ctx.ShouldBindHeader(target); err != nil {
		return errors.NewValidationFailed("Failed to bind headers", err)
	}

	// - Bind Query Parameters (Universal between all requests)
	if err := ctx.ShouldBindQuery(target); err != nil {
		return errors.NewValidationFailed("Failed to bind query parameters", err)
	}

	// - Bind JSON Body (Only for POST/PUT/PATCH requests)
	if ctx.Request.Method != http.MethodGet && ctx.Request.Method != http.MethodDelete {

		// - Check if the request has a body and Content-Type is set
		if ctx.Request.ContentLength > 0 || ctx.GetHeader("Content-Type") != "" {
			if err := ctx.ShouldBindJSON(target); err != nil {
				if err != io.EOF || ctx.Request.ContentLength != 0 {
					return errors.NewValidationFailed("Failed to bind JSON body", err)
				}
			}
		}
	}

	return nil
}

// BindInput binds the input data from the request context to the provided struct.
func BindInput[T any](ctx *gin.Context) (*T, *errors.AppError) {
	var input T

	if err := bindInput(ctx, &input); err != nil {
		return nil, err
	}

	return &input, nil
}

// InputData binds and validates the input data from the request context using the Engine's validator.
func InputData[T any](ctx *gin.Context, engine *Engine) (*T, *errors.AppError) {
	if engine == nil || engine.validator == nil {
		return nil, errors.NewInternalServerError("Validator is not initialized", nil)
	}

	input, err := BindInput[T](ctx)
	if err != nil {
		return nil, err
	}

	if err := engine.validator.Struct(*input); err != nil {
		return nil, errors.NewValidationFailed("Input validation failed", err)
	}

	return input, nil
}
