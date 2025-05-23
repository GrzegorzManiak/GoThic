package errors

import "net/http"

// NewBadRequest creates a new 400 Bad Request AppError.
func NewBadRequest(message string, underlyingErr error, details ...interface{}) *AppError {
	if message == "" {
		message = "The server could not process the request due to a client error."
	}
	return NewAppError(http.StatusBadRequest, message, underlyingErr, details...)
}

// NewUnauthorized creates a new 401 Unauthorized AppError.
func NewUnauthorized(message string, underlyingErr error, details ...interface{}) *AppError {
	if message == "" {
		message = "Authentication is required and has failed or has not yet been provided."
	}
	return NewAppError(http.StatusUnauthorized, message, underlyingErr, details...)
}

// NewForbidden creates a new 403 Forbidden AppError.
func NewForbidden(message string, underlyingErr error, details ...interface{}) *AppError {
	if message == "" {
		message = "You do not have permission to access this resource."
	}
	return NewAppError(http.StatusForbidden, message, underlyingErr, details...)
}

// NewNotFound creates a new 404 Not Found AppError.
func NewNotFound(message string, underlyingErr error, details ...interface{}) *AppError {
	if message == "" {
		message = "The requested resource could not be found."
	}
	return NewAppError(http.StatusNotFound, message, underlyingErr, details...)
}

// NewConflict creates a new 409 Conflict AppError.
func NewConflict(message string, underlyingErr error, details ...interface{}) *AppError {
	if message == "" {
		message = "The request could not be completed due to a conflict with the current state of the resource."
	}
	return NewAppError(http.StatusConflict, message, underlyingErr, details...)
}

// NewInternalServerError creates a new 500 Internal Server Error AppError.
func NewInternalServerError(message string, underlyingErr error, details ...interface{}) *AppError {
	if message == "" {
		message = "An unexpected error occurred on the server."
	}
	return NewAppError(http.StatusInternalServerError, message, underlyingErr, details...)
}

// NewValidationFailed creates a 422 Unprocessable Entity AppError, used for validation errors.
func NewValidationFailed(message string, underlyingErr error, details ...interface{}) *AppError {
	formattedValidationErrors := FormatValidationErrors(underlyingErr)
	if formattedValidationErrors != nil {
		details = append(details, formattedValidationErrors)
	}
	if message == "" {
		message = "Input validation failed."
	}
	return NewAppError(http.StatusUnprocessableEntity, message, underlyingErr, details...)
}
