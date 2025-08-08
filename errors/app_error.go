package errors

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
)

// AppError represents a custom application error.
// It includes an HTTP status code, a user-friendly message,
// the original underlying error (for logging), and optional details.
type AppError struct {
	// Code is the HTTP status code that should be sent to the client.
	Code int `json:"-"` // Exclude from default JSON marshaling of AppError itself for the client response

	// Message is a human-readable message for the client.
	Message string `json:"message"`

	// Err is the underlying original error. This is primarily for logging
	// and internal debugging, not usually for the client.
	Err error `json:"-"` // Exclude from default JSON marshaling

	// Details can hold any additional structured information about the error
	// that might be useful for the client to consume.
	Details interface{} `json:"details,omitempty"`
}

// Error implements the standard error interface.
// It provides a comprehensive error string, typically for logging.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("AppError: Code=%d, Message=%s, UnderlyingError=%v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("AppError: Code=%d, Message=%s", e.Code, e.Message)
}

// Unwrap returns the underlying error for error chaining (e.g., with errors.Is and errors.As).
func (e *AppError) Unwrap() error {
	return e.Err
}

// FormatValidationErrors converts validator.ValidationErrors into a map for structured client responses.
// If the error is not a validator.ValidationErrors but is still non-nil, it returns the error message string.
// If the error is nil, it returns nil.
func FormatValidationErrors(err error) interface{} {
	if err == nil {
		return nil
	}

	var ves validator.ValidationErrors
	if errors.As(err, &ves) {
		out := make(map[string]string)
		for _, fe := range ves {
			out[fe.Namespace()] = fmt.Sprintf("failed on validation tag '%s'", fe.Tag())
		}
		return out
	}

	// - If it's some other non-nil error type, return its string representation.
	return err.Error()
}

// NewAppError creates a new AppError.
// 'code' is the HTTP status code.
// 'message' is the client-facing error message.
// 'underlyingErr' is the original error, can be nil.
// 'details' is optional structured data for the client.
func NewAppError(code int, message string, underlyingErr error, details ...interface{}) *AppError {
	var d interface{}
	if len(details) > 0 {
		d = details[0] // - Take the first details argument if provided
	}
	return &AppError{
		Code:    code,
		Message: message,
		Err:     underlyingErr,
		Details: d,
	}
}

// ToJSONResponse prepares the AppError for a JSON response to the client.
func (e *AppError) ToJSONResponse(production bool) map[string]interface{} {
	response := map[string]interface{}{
		"error": e.Message,
	}

	if e.Details != nil {
		response["details"] = e.Details
	}

	if e.Err != nil && !production {
		response["underlying_error"] = e.Err.Error()
	}

	return response
}
