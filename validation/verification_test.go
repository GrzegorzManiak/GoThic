package validation

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

func TestDynamicInputData_NestedHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"Meta": {
			Nested: FieldRules{
				"RequestID": {Header: "X-Request-ID"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "12345")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	result, err := DynamicInputData(ctx, engine, "nested_header_rules", rules)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	meta, ok := result["Meta"]
	if !ok {
		t.Fatal("expected Meta field in result")
	}

	metaVal := reflect.ValueOf(meta)
	if metaVal.FieldByName("RequestID").String() != "" {
		t.Fatalf("expected Meta.RequestID to be empty (binding disabled), got %v", metaVal.FieldByName("RequestID").Interface())
	}
}

func TestDynamicInputData_NestedQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(validator.New())

	rules := FieldRules{
		"User": {
			Nested: FieldRules{
				"Name": {Tags: "required"},
				"Age":  {Type: "int"},
			},
		},
	}

	// Gin's default query binder usually handles nested structs with bracket notation for forms
	// e.g. user[name]=Alice
	// Try dot notation as well if brackets fail, but brackets are standard for nested forms in Gin/Go-Playground
	req := httptest.NewRequest(http.MethodGet, "/?user.name=Alice&user.age=30", nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	// Nested structs are disallowed in query, so validation should fail on required fields if they are missing
	// or simply not bind.
	// In this case, "Name" is required. Since it won't bind, validation should fail.
	_, err := DynamicInputData(ctx, engine, "nested_query_rules", rules)
	if err == nil {
		t.Fatal("expected validation error because nested query binding should be disabled, but got nil")
	}
}
