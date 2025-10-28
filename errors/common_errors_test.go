package errors

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestNewBadRequest tests the NewBadRequest function.
func TestNewBadRequest(t *testing.T) {
	t.Run("with custom message", func(t *testing.T) {
		underlyingErr := errors.New("client error")
		appErr := NewBadRequest("Custom bad request", underlyingErr, "detail")
		if appErr.Code != http.StatusBadRequest {
			t.Errorf("Expected code %d, got %d", http.StatusBadRequest, appErr.Code)
		}
		if appErr.Message != "Custom bad request" {
			t.Errorf("Expected message 'Custom bad request', got '%s'", appErr.Message)
		}
		if appErr.Err != underlyingErr {
			t.Errorf("Expected underlying error '%v', got '%v'", underlyingErr, appErr.Err)
		}
		if appErr.Details != "detail" {
			t.Errorf("Expected details 'detail', got '%v'", appErr.Details)
		}
	})

	t.Run("with default message", func(t *testing.T) {
		appErr := NewBadRequest("", nil)
		expectedMessage := "The server could not process the request due to a client error."
		if appErr.Message != expectedMessage {
			t.Errorf("Expected default message '%s', got '%s'", expectedMessage, appErr.Message)
		}
	})
}

// TestNewUnauthorized tests the NewUnauthorized function.
func TestNewUnauthorized(t *testing.T) {
	appErr := NewUnauthorized("", nil)
	if appErr.Code != http.StatusUnauthorized {
		t.Errorf("Expected code %d, got %d", http.StatusUnauthorized, appErr.Code)
	}
	expectedMessage := "Authentication is required and has failed or has not yet been provided."
	if appErr.Message != expectedMessage {
		t.Errorf("Expected default message '%s', got '%s'", expectedMessage, appErr.Message)
	}
}

// TestNewForbidden tests the NewForbidden function.
func TestNewForbidden(t *testing.T) {
	appErr := NewForbidden("custom forbidden", nil)
	if appErr.Code != http.StatusForbidden {
		t.Errorf("Expected code %d, got %d", http.StatusForbidden, appErr.Code)
	}
	if appErr.Message != "custom forbidden" {
		t.Errorf("Expected message 'custom forbidden', got '%s'", appErr.Message)
	}
}

// TestNewNotFound tests the NewNotFound function.
func TestNewNotFound(t *testing.T) {
	appErr := NewNotFound("", nil)
	if appErr.Code != http.StatusNotFound {
		t.Errorf("Expected code %d, got %d", http.StatusNotFound, appErr.Code)
	}
	expectedMessage := "The requested resource could not be found."
	if appErr.Message != expectedMessage {
		t.Errorf("Expected default message '%s', got '%s'", expectedMessage, appErr.Message)
	}
}

// TestNewConflict tests the NewConflict function.
func TestNewConflict(t *testing.T) {
	appErr := NewConflict("custom conflict", nil)
	if appErr.Code != http.StatusConflict {
		t.Errorf("Expected code %d, got %d", http.StatusConflict, appErr.Code)
	}
	if appErr.Message != "custom conflict" {
		t.Errorf("Expected message 'custom conflict', got '%s'", appErr.Message)
	}
}

// TestNewInternalServerError tests the NewInternalServerError function.
func TestNewInternalServerError(t *testing.T) {
	appErr := NewInternalServerError("", errors.New("db error"))
	if appErr.Code != http.StatusInternalServerError {
		t.Errorf("Expected code %d, got %d", http.StatusInternalServerError, appErr.Code)
	}
	expectedMessage := "An unexpected error occurred on the server."
	if appErr.Message != expectedMessage {
		t.Errorf("Expected default message '%s', got '%s'", expectedMessage, appErr.Message)
	}
	if appErr.Err.Error() != "db error" {
		t.Errorf("Expected underlying error 'db error', got '%s'", appErr.Err.Error())
	}
}

// TestNewValidationFailed tests the NewValidationFailed function.
func TestNewValidationFailed(t *testing.T) {
	t.Run("with validation errors", func(t *testing.T) {
		// Mock a validation error
		type User struct {
			Name string `validate:"required"`
		}
		validate := validator.New()
		err := validate.Struct(User{})

		appErr := NewValidationFailed("", err)
		if appErr.Code != http.StatusUnprocessableEntity {
			t.Errorf("Expected code %d, got %d", http.StatusUnprocessableEntity, appErr.Code)
		}
		if appErr.Message != "Input validation failed." {
			t.Errorf("Expected message 'Input validation failed.', got '%s'", appErr.Message)
		}

		expectedDetails := map[string]string{"User.Name": "failed on validation tag 'required'"}
		if !reflect.DeepEqual(appErr.Details, expectedDetails) {
			t.Errorf("Expected details '%v', got '%v'", expectedDetails, appErr.Details)
		}
	})

	t.Run("with non-validation error", func(t *testing.T) {
		err := errors.New("some other error")
		appErr := NewValidationFailed("Validation failed", err)
		if appErr.Details != "some other error" {
			t.Errorf("Expected details to contain 'some other error', got '%v'", appErr.Details)
		}
	})
}
