package errors

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestAppError_Error tests the Error() method of AppError.
func TestAppError_Error(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlyingErr := errors.New("database connection failed")
		appErr := NewAppError(http.StatusInternalServerError, "Something went wrong", underlyingErr)
		expected := fmt.Sprintf("AppError: Code=%d, Message=%s, UnderlyingError=%v", http.StatusInternalServerError, "Something went wrong", underlyingErr)
		if appErr.Error() != expected {
			t.Errorf("Expected error string '%s', got '%s'", expected, appErr.Error())
		}
	})

	t.Run("without underlying error", func(t *testing.T) {
		appErr := NewAppError(http.StatusBadRequest, "Invalid input", nil)
		expected := fmt.Sprintf("AppError: Code=%d, Message=%s", http.StatusBadRequest, "Invalid input")
		if appErr.Error() != expected {
			t.Errorf("Expected error string '%s', got '%s'", expected, appErr.Error())
		}
	})
}

// TestAppError_Unwrap tests the Unwrap() method.
func TestAppError_Unwrap(t *testing.T) {
	underlyingErr := errors.New("original error")
	appErr := NewAppError(http.StatusInternalServerError, "Wrapper error", underlyingErr)

	if unwrapped := errors.Unwrap(appErr); unwrapped != underlyingErr {
		t.Errorf("Expected unwrapped error to be '%v', got '%v'", underlyingErr, unwrapped)
	}
}

// TestFormatValidationErrors tests the FormatValidationErrors function.
func TestFormatValidationErrors(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		if formatted := FormatValidationErrors(nil); formatted != nil {
			t.Errorf("Expected nil for a nil error, got '%v'", formatted)
		}
	})

	t.Run("with validator.ValidationErrors", func(t *testing.T) {
		validate := validator.New()
		type User struct {
			Username string `validate:"required"`
		}
		user := User{}
		err := validate.Struct(user)

		formatted := FormatValidationErrors(err)
		expected := map[string]string{
			"User.Username": "failed on validation tag 'required'",
		}

		if !reflect.DeepEqual(formatted, expected) {
			t.Errorf("Expected formatted validation errors '%v', got '%v'", expected, formatted)
		}
	})

	t.Run("with other non-nil error", func(t *testing.T) {
		err := errors.New("a simple error")
		formatted := FormatValidationErrors(err)
		if formatted != "a simple error" {
			t.Errorf("Expected formatted error to be 'a simple error', got '%v'", formatted)
		}
	})
}

// TestNewAppError tests the constructor for AppError.
func TestNewAppError(t *testing.T) {
	underlyingErr := errors.New("underlying")
	details := map[string]string{"field": "value"}

	appErr := NewAppError(http.StatusNotFound, "Not Found", underlyingErr, details)

	if appErr.Code != http.StatusNotFound {
		t.Errorf("Expected code %d, got %d", http.StatusNotFound, appErr.Code)
	}
	if appErr.Message != "Not Found" {
		t.Errorf("Expected message 'Not Found', got '%s'", appErr.Message)
	}
	if appErr.Err != underlyingErr {
		t.Errorf("Expected underlying error '%v', got '%v'", underlyingErr, appErr.Err)
	}
	if !reflect.DeepEqual(appErr.Details, details) {
		t.Errorf("Expected details '%v', got '%v'", details, appErr.Details)
	}
}

// TestAppError_ToJSONResponse tests the ToJSONResponse method.
func TestAppError_ToJSONResponse(t *testing.T) {
	underlyingErr := errors.New("internal issue")
	details := "some details"
	appErr := NewAppError(http.StatusInternalServerError, "Server Error", underlyingErr, details)

	t.Run("in production mode", func(t *testing.T) {
		jsonResponse := appErr.ToJSONResponse(true)
		expected := map[string]interface{}{
			"error":   "Server Error",
			"details": "some details",
		}
		if !reflect.DeepEqual(jsonResponse, expected) {
			t.Errorf("Expected JSON response '%v', got '%v'", expected, jsonResponse)
		}
		if _, exists := jsonResponse["underlying_error"]; exists {
			t.Error("Underlying error should not be exposed in production")
		}
	})

	t.Run("in development mode", func(t *testing.T) {
		jsonResponse := appErr.ToJSONResponse(false)
		expected := map[string]interface{}{
			"error":            "Server Error",
			"details":          "some details",
			"underlying_error": "internal issue",
		}
		if !reflect.DeepEqual(jsonResponse, expected) {
			t.Errorf("Expected JSON response '%v', got '%v'", expected, jsonResponse)
		}
		if _, exists := jsonResponse["underlying_error"]; !exists {
			t.Error("Underlying error should be exposed in development")
		}
	})
}
