package validation

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/grzegorzmaniak/gothic/errors"
	"go.uber.org/zap"
	"io"
	"net/http"
	"sync"
)

// CustomValidator is a global validator instance for struct validation. Im aware
// that this is not the best practice, but for what we need, it is sufficient.
var (
	CustomValidator *validator.Validate
	mu              sync.Mutex
)

// InitValidator sets the global validator instance to the one provided.
func InitValidator(v *validator.Validate) {
	mu.Lock()
	defer mu.Unlock()
	CustomValidator = v
}

// initDefaultValidator initializes the global validator with a default instance.
func initDefaultValidator() {
	InitValidator(validator.New())
}

// BindInput binds the input data from the request context to the provided struct.
func BindInput[T any](ctx *gin.Context) (*T, *errors.AppError) {
	var input T

	// - Bind Headers (Universal between all requests)
	if err := ctx.ShouldBindHeader(&input); err != nil {
		return nil, errors.NewValidationFailed("Failed to bind headers", err)
	}

	// - Bind Query Parameters (Universal between all requests)
	if err := ctx.ShouldBindQuery(&input); err != nil {
		return nil, errors.NewValidationFailed("Failed to bind query parameters", err)
	}

	// - Bind JSON Body (Only for POST/PUT/PATCH requests)
	if ctx.Request.Method != http.MethodGet && ctx.Request.Method != http.MethodDelete {

		// - Check if the request has a body and Content-Type is set
		if ctx.Request.ContentLength > 0 || ctx.GetHeader("Content-Type") != "" {
			if err := ctx.ShouldBindJSON(&input); err != nil {
				if err != io.EOF || ctx.Request.ContentLength != 0 {
					return nil, errors.NewValidationFailed("Failed to bind JSON body", err)
				}
			}
		}
	}

	return &input, nil
}

// InputData binds and validates the input data from the request context.
func InputData[T any](ctx *gin.Context) (*T, *errors.AppError) {
	if CustomValidator == nil {
		zap.L().Debug("CustomValidator is nil, initializing default validator")
		initDefaultValidator()
	}

	input, err := BindInput[T](ctx)
	if err != nil {
		return nil, err
	}

	if err := CustomValidator.Struct(*input); err != nil {
		return nil, errors.NewValidationFailed("Input validation failed", err)
	}

	return input, nil
}
