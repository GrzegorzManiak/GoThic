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

func TestDynamicInputData_NestedStruct(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"User": {
			Nested: FieldRules{
				"Name": {Tags: "required"},
				"Age":  {Tags: "gte=18", Type: "int"},
			},
		},
	}

	jsonBody := `{"user":{"name":"Alice","age":25}}`
	req := httptest.NewRequest(http.MethodPost, "/dynamic", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	result, err := DynamicInputData(ctx, engine, "nested_user_rules", rules)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	user, ok := result["User"]
	if !ok {
		t.Fatal("expected User field in result")
	}

	// The result["User"] is a struct (not a map) because DynamicInputData returns map[string]interface{}
	// where values are the fields of the dynamic struct.
	// The dynamic struct field "User" is a nested struct.
	// So user should be a struct.

	userVal := reflect.ValueOf(user)
	if userVal.Kind() != reflect.Struct {
		t.Fatalf("expected User to be a struct, got %T", user)
	}

	nameField := userVal.FieldByName("Name")
	if !nameField.IsValid() || nameField.String() != "Alice" {
		t.Fatalf("expected User.Name to be Alice, got %v", nameField)
	}

	ageField := userVal.FieldByName("Age")
	if !ageField.IsValid() || ageField.Int() != 25 {
		t.Fatalf("expected User.Age to be 25, got %v", ageField)
	}
}

func TestDynamicInputData_NestedSlice(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"Users": {
			Type: "[]",
			Nested: FieldRules{
				"Name": {Tags: "required"},
			},
		},
	}

	jsonBody := `{"users":[{"name":"Alice"},{"name":"Bob"}]}`
	req := httptest.NewRequest(http.MethodPost, "/dynamic", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	result, err := DynamicInputData(ctx, engine, "nested_slice_rules", rules)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	users, ok := result["Users"]
	if !ok {
		t.Fatal("expected Users field in result")
	}

	usersVal := reflect.ValueOf(users)
	if usersVal.Kind() != reflect.Slice {
		t.Fatalf("expected Users to be a slice, got %T", users)
	}

	if usersVal.Len() != 2 {
		t.Fatalf("expected 2 users, got %d", usersVal.Len())
	}

	firstUser := usersVal.Index(0)
	if firstUser.FieldByName("Name").String() != "Alice" {
		t.Fatalf("expected first user name to be Alice")
	}
}

func TestDynamicOutputData_NestedStruct(t *testing.T) {
	engine := NewEngine(validator.New())
	rules := FieldRules{
		"User": {
			Nested: FieldRules{
				"Name": {Tags: "required"},
				"Age":  {Tags: "gte=18", Type: "int"},
			},
		},
	}

	output := map[string]interface{}{
		"User": map[string]interface{}{
			"Name": "Bob",
			"Age":  30,
		},
	}

	_, body, err := DynamicOutputData(engine, "nested_output_rules", rules, output)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	bodyVal := reflect.ValueOf(body)
	userField := bodyVal.FieldByName("User")
	if userField.Kind() != reflect.Struct {
		t.Fatalf("expected User field to be struct, got %v", userField.Kind())
	}

	if userField.FieldByName("Name").String() != "Bob" {
		t.Fatalf("expected User.Name to be Bob")
	}
}
