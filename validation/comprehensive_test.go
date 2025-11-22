package validation

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

func TestComprehensiveValidation_AllSources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"ID":   {Tags: "required,uuid", URIName: "id"},
		"Name": {Tags: "required,min=3", JSONName: "name"},
		"Page": {Tags: "required,min=1", FormName: "page", Type: "int"},
		"Auth": {Tags: "required", Header: "Authorization"},
	}

	// Setup request
	// URI: /users/:id -> /users/123e4567-e89b-12d3-a456-426614174000
	// Query: ?page=1
	// Header: Authorization: Bearer token
	// Body: {"name": "Alice"}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Mock URI params manually since we are not going through the full router
	ctx.Params = gin.Params{
		{Key: "id", Value: "123e4567-e89b-12d3-a456-426614174000"},
	}

	req := httptest.NewRequest(http.MethodPost, "/users/123e4567-e89b-12d3-a456-426614174000?page=1", bytes.NewBufferString(`{"name": "Alice"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token")
	ctx.Request = req

	result, err := DynamicInputData(ctx, engine, "comprehensive_rules", rules)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result["ID"] != "123e4567-e89b-12d3-a456-426614174000" {
		t.Errorf("expected ID to be bound from URI, got %v", result["ID"])
	}
	if result["Name"] != "Alice" {
		t.Errorf("expected Name to be bound from Body, got %v", result["Name"])
	}
	if result["Page"] != 1 {
		t.Errorf("expected Page to be bound from Query, got %v", result["Page"])
	}
	if result["Auth"] != "Bearer token" {
		t.Errorf("expected Auth to be bound from Header, got %v", result["Auth"])
	}
}

func TestComprehensiveValidation_ValidationFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"ID":   {Tags: "required,uuid", URIName: "id"},
		"Name": {Tags: "required,min=3", JSONName: "name"},
		"Page": {Tags: "required,min=1", FormName: "page", Type: "int"},
		"Auth": {Tags: "required", Header: "Authorization"},
	}

	// Invalid Request
	// URI: Invalid UUID
	// Query: Invalid Page (0)
	// Header: Missing
	// Body: Name too short

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Params = gin.Params{
		{Key: "id", Value: "not-a-uuid"},
	}

	req := httptest.NewRequest(http.MethodPost, "/users/not-a-uuid?page=0", bytes.NewBufferString(`{"name": "Al"}`))
	req.Header.Set("Content-Type", "application/json")
	// Missing Authorization header
	ctx.Request = req

	_, err := DynamicInputData(ctx, engine, "comprehensive_rules_fail", rules)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	// We expect multiple validation errors.
	// Since we can't easily inspect the exact error message structure without casting,
	// we'll just ensure it failed.
	// In a real scenario, we might want to check specific field errors.
}

func TestComprehensiveValidation_StaticStruct(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	type UserRequest struct {
		ID   string `uri:"id" validate:"required,uuid"`
		Name string `json:"name" validate:"required,min=3"`
		Page int    `form:"page" validate:"required,min=1"`
		Auth string `header:"Authorization" validate:"required"`
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Params = gin.Params{
		{Key: "id", Value: "123e4567-e89b-12d3-a456-426614174000"},
	}

	req := httptest.NewRequest(http.MethodPost, "/users/123e4567-e89b-12d3-a456-426614174000?page=5", bytes.NewBufferString(`{"name": "Bob"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Secret")
	ctx.Request = req

	result, err := InputData[UserRequest](ctx, engine)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.ID != "123e4567-e89b-12d3-a456-426614174000" {
		t.Errorf("expected ID to be bound from URI, got %v", result.ID)
	}
	if result.Name != "Bob" {
		t.Errorf("expected Name to be bound from Body, got %v", result.Name)
	}
	if result.Page != 5 {
		t.Errorf("expected Page to be bound from Query, got %v", result.Page)
	}
	if result.Auth != "Secret" {
		t.Errorf("expected Auth to be bound from Header, got %v", result.Auth)
	}
}
