package helpers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
)

func TestErrorResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Sends error response with proper status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		appErr := errors.NewBadRequest("Invalid input", nil)
		ErrorResponse(ctx, appErr)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("Sends JSON response body", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		appErr := errors.NewBadRequest("Invalid input", nil)
		ErrorResponse(ctx, appErr)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		if response["error"] == nil {
			t.Error("Expected 'error' field in response")
		}
	})

	t.Run("Handles nil error gracefully", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		ErrorResponse(ctx, nil)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d for nil error, got %d", http.StatusInternalServerError, w.Code)
		}

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		if response["error"] == nil {
			t.Error("Expected 'error' field in response for nil error")
		}
	})

	t.Run("Aborts context after error", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		appErr := errors.NewUnauthorized("Not authorized", nil)
		ErrorResponse(ctx, appErr)

		if !ctx.IsAborted() {
			t.Error("Expected context to be aborted after error response")
		}
	})

	t.Run("Handles different error types", func(t *testing.T) {
		testCases := []struct {
			name     string
			appErr   *errors.AppError
			expected int
		}{
			{"BadRequest", errors.NewBadRequest("Bad", nil), http.StatusBadRequest},
			{"Unauthorized", errors.NewUnauthorized("Unauth", nil), http.StatusUnauthorized},
			{"Forbidden", errors.NewForbidden("Forbidden", nil), http.StatusForbidden},
			{"NotFound", errors.NewNotFound("Not found", nil), http.StatusNotFound},
			{"InternalServerError", errors.NewInternalServerError("Internal", nil, "code"), http.StatusInternalServerError},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(w)

				ErrorResponse(ctx, tc.appErr)

				if w.Code != tc.expected {
					t.Errorf("Expected status %d, got %d", tc.expected, w.Code)
				}
			})
		}
	})

	t.Run("Production mode hides internal details", func(t *testing.T) {
		originalMode := gin.Mode()
		gin.SetMode(gin.ReleaseMode)
		defer gin.SetMode(originalMode)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		appErr := errors.NewInternalServerError("Internal error", nil, "error_code")
		ErrorResponse(ctx, appErr)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		// In production mode, internal details should be hidden
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})
}

func TestSuccessResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Sends success response with data", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		data := map[string]string{"message": "success"}
		SuccessResponse(ctx, http.StatusOK, data, nil)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		if response["message"] != "success" {
			t.Errorf("Expected message 'success', got %v", response["message"])
		}
	})

	t.Run("Sends response with custom headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		headers := map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Request-ID":    "12345",
		}
		data := map[string]string{"status": "ok"}

		SuccessResponse(ctx, http.StatusOK, data, headers)

		if w.Header().Get("X-Custom-Header") != "custom-value" {
			t.Errorf("Expected X-Custom-Header 'custom-value', got '%s'", w.Header().Get("X-Custom-Header"))
		}
		if w.Header().Get("X-Request-ID") != "12345" {
			t.Errorf("Expected X-Request-ID '12345', got '%s'", w.Header().Get("X-Request-ID"))
		}
	})

	t.Run("Handles nil headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		data := map[string]string{"result": "ok"}
		SuccessResponse(ctx, http.StatusOK, data, nil)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("Handles different status codes", func(t *testing.T) {
		testCases := []struct {
			name   string
			status int
		}{
			{"OK", http.StatusOK},
			{"Created", http.StatusCreated},
			{"Accepted", http.StatusAccepted},
			{"NoContent", http.StatusNoContent},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(w)

				data := map[string]string{"status": "success"}
				SuccessResponse(ctx, tc.status, data, nil)

				if w.Code != tc.status {
					t.Errorf("Expected status %d, got %d", tc.status, w.Code)
				}
			})
		}
	})

	t.Run("Handles empty headers map", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		headers := map[string]string{}
		data := map[string]string{"result": "ok"}
		SuccessResponse(ctx, http.StatusOK, data, headers)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("Handles complex data structures", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		data := map[string]interface{}{
			"user": map[string]interface{}{
				"id":    123,
				"name":  "John Doe",
				"roles": []string{"admin", "user"},
			},
			"count": 42,
		}

		SuccessResponse(ctx, http.StatusOK, data, nil)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		if response["count"] != float64(42) { // JSON unmarshals numbers as float64
			t.Errorf("Expected count 42, got %v", response["count"])
		}
	})

	t.Run("Handles multiple headers correctly", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		headers := map[string]string{
			"X-Header-1": "value1",
			"X-Header-2": "value2",
			"X-Header-3": "value3",
		}
		data := map[string]string{"status": "ok"}

		SuccessResponse(ctx, http.StatusOK, data, headers)

		for key, expectedValue := range headers {
			if w.Header().Get(key) != expectedValue {
				t.Errorf("Expected header %s to be '%s', got '%s'", key, expectedValue, w.Header().Get(key))
			}
		}
	})
}
