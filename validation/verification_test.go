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
	if metaVal.FieldByName("RequestID").String() != "12345" {
		t.Fatalf("expected Meta.RequestID to be 12345, got %v", metaVal.FieldByName("RequestID").Interface())
	}
}
