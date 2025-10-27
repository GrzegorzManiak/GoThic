package validation

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type testInputStruct struct {
	Name   string `json:"name" validate:"required"`
	Email  string `json:"email" validate:"required,email"`
	Age    int    `json:"age" validate:"gte=0,lte=150"`
	UserID string `header:"X-User-ID"`
	Page   int    `form:"page" validate:"gte=1"`
}

func TestBindInput(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Bind JSON body for POST request", func(t *testing.T) {
		jsonBody := `{"name":"John","email":"john@example.com","age":30}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "user123")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if input.Name != "John" {
			t.Errorf("Expected name 'John', got '%s'", input.Name)
		}
		if input.Email != "john@example.com" {
			t.Errorf("Expected email 'john@example.com', got '%s'", input.Email)
		}
		if input.Age != 30 {
			t.Errorf("Expected age 30, got %d", input.Age)
		}
		if input.UserID != "user123" {
			t.Errorf("Expected UserID 'user123', got '%s'", input.UserID)
		}
		if input.Page != 1 {
			t.Errorf("Expected page 1, got %d", input.Page)
		}
	})

	t.Run("Bind query parameters for GET request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?page=5", nil)
		req.Header.Set("X-User-ID", "user456")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if input.Page != 5 {
			t.Errorf("Expected page 5, got %d", input.Page)
		}
		if input.UserID != "user456" {
			t.Errorf("Expected UserID 'user456', got '%s'", input.UserID)
		}
	})

	t.Run("Bind headers only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-User-ID", "header-user")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if input.UserID != "header-user" {
			t.Errorf("Expected UserID 'header-user', got '%s'", input.UserID)
		}
	})

	t.Run("Invalid JSON returns error", func(t *testing.T) {
		jsonBody := `{"name":"John","email":invalid}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := BindInput[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected error for invalid JSON, got none")
		}
	})

	t.Run("GET request skips JSON binding", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?page=2", nil)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error for GET request, got %v", err)
		}
		if input.Page != 2 {
			t.Errorf("Expected page 2, got %d", input.Page)
		}
	})

	t.Run("DELETE request skips JSON binding", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/test?page=3", nil)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error for DELETE request, got %v", err)
		}
		if input.Page != 3 {
			t.Errorf("Expected page 3, got %d", input.Page)
		}
	})

	t.Run("POST with empty body and no Content-Type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", nil)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error for empty POST body, got %v", err)
		}
		if input.Page != 1 {
			t.Errorf("Expected page 1, got %d", input.Page)
		}
	})

	t.Run("PUT request with JSON body", func(t *testing.T) {
		jsonBody := `{"name":"Jane","email":"jane@example.com","age":25}`
		req := httptest.NewRequest(http.MethodPut, "/test", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if input.Name != "Jane" {
			t.Errorf("Expected name 'Jane', got '%s'", input.Name)
		}
	})

	t.Run("PATCH request with JSON body", func(t *testing.T) {
		jsonBody := `{"name":"Bob","email":"bob@example.com"}`
		req := httptest.NewRequest(http.MethodPatch, "/test", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := BindInput[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if input.Name != "Bob" {
			t.Errorf("Expected name 'Bob', got '%s'", input.Name)
		}
	})
}

func TestInputData(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Valid input passes validation", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `{"name":"John","email":"john@example.com","age":30}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := InputData[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if input.Name != "John" {
			t.Errorf("Expected name 'John', got '%s'", input.Name)
		}
	})

	t.Run("Invalid input fails validation - missing required field", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `{"name":"John","age":30}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := InputData[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected validation error for missing email, got none")
		}
	})

	t.Run("Invalid input fails validation - invalid email format", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `{"name":"John","email":"not-an-email","age":30}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := InputData[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected validation error for invalid email, got none")
		}
	})

	t.Run("Invalid input fails validation - age out of range", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `{"name":"John","email":"john@example.com","age":200}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := InputData[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected validation error for age > 150, got none")
		}
	})

	t.Run("Invalid input fails validation - negative age", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `{"name":"John","email":"john@example.com","age":-5}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := InputData[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected validation error for negative age, got none")
		}
	})

	t.Run("Invalid input fails validation - page less than 1", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `{"name":"John","email":"john@example.com","age":30}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=0", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := InputData[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected validation error for page < 1, got none")
		}
	})

	t.Run("Nil validator initializes default", func(t *testing.T) {
		InitValidator(nil)

		jsonBody := `{"name":"John","email":"john@example.com","age":30}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=1", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := InputData[testInputStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error with auto-initialized validator, got %v", err)
		}
		if CustomValidator == nil {
			t.Error("Expected CustomValidator to be initialized")
		}
		if input.Name != "John" {
			t.Errorf("Expected name 'John', got '%s'", input.Name)
		}
	})

	t.Run("Bind error propagates before validation", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `invalid json`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := InputData[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected error for invalid JSON, got none")
		}
	})

	t.Run("Valid zero values pass validation when allowed", func(t *testing.T) {
		type optionalStruct struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}

		InitValidator(validator.New())

		jsonBody := `{"name":"","count":0}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := InputData[optionalStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error for optional fields, got %v", err)
		}
		if input.Name != "" {
			t.Errorf("Expected empty name, got '%s'", input.Name)
		}
		if input.Count != 0 {
			t.Errorf("Expected count 0, got %d", input.Count)
		}
	})
}

func TestInputDataEdgeCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Multiple validation errors", func(t *testing.T) {
		InitValidator(validator.New())

		jsonBody := `{"name":"","email":"invalid","age":-1}`
		req := httptest.NewRequest(http.MethodPost, "/test?page=0", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		_, err := InputData[testInputStruct](ctx)
		if err == nil {
			t.Error("Expected validation errors for multiple invalid fields, got none")
		}
	})

	t.Run("Empty struct passes validation", func(t *testing.T) {
		type emptyStruct struct{}

		InitValidator(validator.New())

		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := InputData[emptyStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error for empty struct, got %v", err)
		}
		if input == nil {
			t.Error("Expected non-nil input")
		}
	})

	t.Run("Complex nested validation", func(t *testing.T) {
		type nestedStruct struct {
			User struct {
				Name  string `json:"name" validate:"required"`
				Email string `json:"email" validate:"required,email"`
			} `json:"user" validate:"required"`
		}

		InitValidator(validator.New())

		jsonBody := `{"user":{"name":"John","email":"john@example.com"}}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		input, err := InputData[nestedStruct](ctx)
		if err != nil {
			t.Fatalf("Expected no error for valid nested struct, got %v", err)
		}
		if input.User.Name != "John" {
			t.Errorf("Expected nested name 'John', got '%s'", input.User.Name)
		}
	})
}
