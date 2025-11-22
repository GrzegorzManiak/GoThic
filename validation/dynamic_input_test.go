package validation

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

func TestDynamicInputData_ValidPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"Email": {Tags: "required,email"},
		"Age":   {Tags: "gte=18,lte=130", Type: "int"},
	}

	jsonBody := `{"email":"me@example.com","age":30}`
	req := httptest.NewRequest(http.MethodPost, "/dynamic", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	result, err := DynamicInputData(ctx, engine, "user_rules", rules)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	email, ok := result["Email"].(string)
	if !ok || email != "me@example.com" {
		t.Fatalf("expected email to be 'me@example.com', got %v", result["Email"])
	}

	age, ok := result["Age"].(int)
	if !ok || age != 30 {
		t.Fatalf("expected age to be 30, got %v (%T)", result["Age"], result["Age"])
	}
}

func TestDynamicInputData_InvalidPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"Email": {Tags: "required,email"},
		"Age":   {Tags: "gte=18,lte=130", Type: "int"},
	}

	jsonBody := `{"email":"invalid","age":10}`
	req := httptest.NewRequest(http.MethodPost, "/dynamic", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	if _, err := DynamicInputData(ctx, engine, "", rules); err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestGetDynamicStructTypeCaching(t *testing.T) {
	engine := NewEngine(validator.New())
	rules := FieldRules{
		"Email": {Tags: "required,email"},
	}

	first, err := getDynamicStructType(engine, "cache-key", rules)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	alteredRules := FieldRules{
		"Email": {Tags: "required"},
		"Name":  {Tags: "required", Type: "string"},
	}

	second, err := getDynamicStructType(engine, "cache-key", alteredRules)
	if err != nil {
		t.Fatalf("expected no error retrieving cached struct, got %v", err)
	}

	if first != second {
		t.Fatalf("expected cached struct types to match for the same cache key")
	}
}

func TestBuildDynamicStructType_RejectsUnexportedField(t *testing.T) {
	_, err := buildDynamicStructType(FieldRules{
		"email": {Tags: "required,email"},
	})

	if err == nil {
		t.Fatal("expected error for unexported field name, got nil")
	}
}

func TestDynamicOutputData_ValidPayload(t *testing.T) {
	engine := NewEngine(validator.New())
	rules := FieldRules{
		"Email": {Tags: "required,email", JSONName: "email"},
		"Age":   {Tags: "gte=18,lte=130", Type: "int"},
	}

	output := map[string]interface{}{
		"Email": "me@example.com",
		"Age":   45,
	}

	headers, body, err := DynamicOutputData(engine, "out_rules", rules, output)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(headers) != 0 {
		t.Fatalf("expected no headers, got %v", headers)
	}

	resultVal := reflect.ValueOf(body)
	if resultVal.Kind() != reflect.Struct {
		t.Fatalf("expected struct output, got %T", body)
	}
	if email := resultVal.FieldByName("Email").String(); email != "me@example.com" {
		t.Fatalf("expected email me@example.com, got %s", email)
	}
}

func TestDynamicOutputData_HeaderExtraction(t *testing.T) {
	engine := NewEngine(validator.New())
	rules := FieldRules{
		"Token": {Tags: "required", Header: "X-Token"},
	}

	output := map[string]interface{}{
		"Token": "abc123",
	}

	headers, _, err := DynamicOutputData(engine, "", rules, output)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if headers["X-Token"] != "abc123" {
		t.Fatalf("expected header X-Token to be abc123, got %s", headers["X-Token"])
	}
}

func TestDynamicOutputData_ValidatorRequired(t *testing.T) {
	engine := &Engine{}
	rules := FieldRules{
		"Email": {Tags: "required,email"},
	}

	_, _, err := DynamicOutputData(engine, "", rules, map[string]interface{}{"Email": "bad"})
	if err == nil {
		t.Fatal("expected error when validator is missing")
	}
}
