package validation

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

type testOutputStruct struct {
	Message    string `json:"message" validate:"required"`
	StatusCode int    `json:"status_code" validate:"gte=100,lte=599"`
	SessionID  string `header:"X-Session-ID"`
	Token      string `header:"X-Auth-Token" validate:"required"`
	Count      int    `json:"count" validate:"gte=0"`
}

func TestOutputData(t *testing.T) {
	t.Run("Valid output with headers", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "Success",
			StatusCode: 200,
			SessionID:  "session123",
			Token:      "token456",
			Count:      10,
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if headers == nil {
			t.Fatal("Expected non-nil headers")
		}
		if headers["X-Session-ID"] != "session123" {
			t.Errorf("Expected X-Session-ID 'session123', got '%s'", headers["X-Session-ID"])
		}
		if headers["X-Auth-Token"] != "token456" {
			t.Errorf("Expected X-Auth-Token 'token456', got '%s'", headers["X-Auth-Token"])
		}
		if result.Message != "Success" {
			t.Errorf("Expected message 'Success', got '%s'", result.Message)
		}
	})

	t.Run("Valid output without headers", func(t *testing.T) {
		type simpleOutput struct {
			Message string `json:"message" validate:"required"`
			Value   int    `json:"value"`
		}

		engine := NewEngine(validator.New())

		output := &simpleOutput{
			Message: "Test",
			Value:   42,
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if len(headers) != 0 {
			t.Errorf("Expected empty headers map, got %d headers", len(headers))
		}
		if result.Message != "Test" {
			t.Errorf("Expected message 'Test', got '%s'", result.Message)
		}
	})

	t.Run("Invalid output - missing required field", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "",
			StatusCode: 200,
			SessionID:  "session123",
			Token:      "token456",
			Count:      10,
		}

		_, _, err := OutputData(engine, output)
		if err == nil {
			t.Error("Expected validation error for missing required message, got none")
		}
	})

	t.Run("Invalid output - missing required header field", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "Success",
			StatusCode: 200,
			SessionID:  "session123",
			Token:      "",
			Count:      10,
		}

		_, _, err := OutputData(engine, output)
		if err == nil {
			t.Error("Expected validation error for missing required token, got none")
		}
	})

	t.Run("Invalid output - status code out of range low", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "Success",
			StatusCode: 50,
			SessionID:  "session123",
			Token:      "token456",
			Count:      10,
		}

		_, _, err := OutputData(engine, output)
		if err == nil {
			t.Error("Expected validation error for status code < 100, got none")
		}
	})

	t.Run("Invalid output - status code out of range high", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "Success",
			StatusCode: 600,
			SessionID:  "session123",
			Token:      "token456",
			Count:      10,
		}

		_, _, err := OutputData(engine, output)
		if err == nil {
			t.Error("Expected validation error for status code > 599, got none")
		}
	})

	t.Run("Invalid output - negative count", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "Success",
			StatusCode: 200,
			SessionID:  "session123",
			Token:      "token456",
			Count:      -5,
		}

		_, _, err := OutputData(engine, output)
		if err == nil {
			t.Error("Expected validation error for negative count, got none")
		}
	})

	t.Run("Nil output returns error", func(t *testing.T) {
		engine := NewEngine(validator.New())

		var output *testOutputStruct

		_, _, err := OutputData(engine, output)
		if err == nil {
			t.Error("Expected error for nil output, got none")
		}
	})

	t.Run("Nil validator initializes default", func(t *testing.T) {
		engine := NewEngine(nil)

		output := &testOutputStruct{
			Message:    "Success",
			StatusCode: 200,
			SessionID:  "session123",
			Token:      "token456",
			Count:      10,
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error with auto-initialized validator, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if len(headers) != 2 {
			t.Errorf("Expected 2 headers, got %d", len(headers))
		}
	})

	t.Run("Multiple headers extracted correctly", func(t *testing.T) {
		type multiHeaderOutput struct {
			Data    string `json:"data" validate:"required"`
			Header1 string `header:"X-Custom-1"`
			Header2 string `header:"X-Custom-2"`
			Header3 string `header:"X-Custom-3"`
		}

		engine := NewEngine(validator.New())

		output := &multiHeaderOutput{
			Data:    "test",
			Header1: "value1",
			Header2: "value2",
			Header3: "value3",
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(headers) != 3 {
			t.Errorf("Expected 3 headers, got %d", len(headers))
		}
		if headers["X-Custom-1"] != "value1" {
			t.Errorf("Expected X-Custom-1 'value1', got '%s'", headers["X-Custom-1"])
		}
		if headers["X-Custom-2"] != "value2" {
			t.Errorf("Expected X-Custom-2 'value2', got '%s'", headers["X-Custom-2"])
		}
		if headers["X-Custom-3"] != "value3" {
			t.Errorf("Expected X-Custom-3 'value3', got '%s'", headers["X-Custom-3"])
		}
		if result.Data != "test" {
			t.Errorf("Expected data 'test', got '%s'", result.Data)
		}
	})

	t.Run("Empty string header values", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "Success",
			StatusCode: 200,
			SessionID:  "",
			Token:      "token456",
			Count:      0,
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if headers["X-Session-ID"] != "" {
			t.Errorf("Expected empty X-Session-ID, got '%s'", headers["X-Session-ID"])
		}
		if result.Count != 0 {
			t.Errorf("Expected count 0, got %d", result.Count)
		}
	})

	t.Run("Valid output with various status codes", func(t *testing.T) {
		engine := NewEngine(validator.New())

		validStatusCodes := []int{100, 200, 201, 204, 301, 400, 404, 500, 503, 599}

		for _, statusCode := range validStatusCodes {
			output := &testOutputStruct{
				Message:    "Test",
				StatusCode: statusCode,
				SessionID:  "session",
				Token:      "token",
				Count:      1,
			}

			_, result, err := OutputData(engine, output)
			if err != nil {
				t.Errorf("Expected no error for status code %d, got %v", statusCode, err)
			}
			if result == nil {
				t.Errorf("Expected non-nil result for status code %d", statusCode)
			}
		}
	})
}

func TestOutputDataEdgeCases(t *testing.T) {
	t.Run("Empty struct with no fields", func(t *testing.T) {
		type emptyOutput struct{}

		engine := NewEngine(validator.New())

		output := &emptyOutput{}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error for empty struct, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if len(headers) != 0 {
			t.Errorf("Expected empty headers, got %d", len(headers))
		}
	})

	t.Run("Struct with only header fields", func(t *testing.T) {
		type headerOnlyOutput struct {
			SessionID string `header:"X-Session-ID"`
			Token     string `header:"X-Token"`
		}

		engine := NewEngine(validator.New())

		output := &headerOnlyOutput{
			SessionID: "session123",
			Token:     "token456",
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(headers) != 2 {
			t.Errorf("Expected 2 headers, got %d", len(headers))
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
	})

	t.Run("Struct with no header fields", func(t *testing.T) {
		type noHeaderOutput struct {
			Message string `json:"message" validate:"required"`
			Count   int    `json:"count"`
		}

		engine := NewEngine(validator.New())

		output := &noHeaderOutput{
			Message: "Test",
			Count:   5,
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(headers) != 0 {
			t.Errorf("Expected no headers, got %d", len(headers))
		}
		if result.Message != "Test" {
			t.Errorf("Expected message 'Test', got '%s'", result.Message)
		}
	})

	t.Run("Multiple validation errors", func(t *testing.T) {
		engine := NewEngine(validator.New())

		output := &testOutputStruct{
			Message:    "",
			StatusCode: 1000,
			SessionID:  "session",
			Token:      "",
			Count:      -10,
		}

		_, _, err := OutputData(engine, output)
		if err == nil {
			t.Error("Expected validation errors for multiple invalid fields, got none")
		}
	})

	t.Run("Nested struct validation", func(t *testing.T) {
		type nestedOutput struct {
			Response struct {
				Message string `json:"message" validate:"required"`
				Code    int    `json:"code" validate:"required"`
			} `json:"response" validate:"required"`
		}

		engine := NewEngine(validator.New())

		output := &nestedOutput{}
		output.Response.Message = "Success"
		output.Response.Code = 200

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error for valid nested struct, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if len(headers) != 0 {
			t.Errorf("Expected no headers, got %d", len(headers))
		}
		if result.Response.Message != "Success" {
			t.Errorf("Expected nested message 'Success', got '%s'", result.Response.Message)
		}
	})

	t.Run("Pointer fields in struct", func(t *testing.T) {
		type pointerOutput struct {
			Message *string `json:"message" validate:"required"`
			Count   *int    `json:"count"`
		}

		engine := NewEngine(validator.New())

		msg := "Test"
		cnt := 5
		output := &pointerOutput{
			Message: &msg,
			Count:   &cnt,
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error for struct with pointers, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if len(headers) != 0 {
			t.Errorf("Expected no headers, got %d", len(headers))
		}
		if *result.Message != "Test" {
			t.Errorf("Expected message 'Test', got '%s'", *result.Message)
		}
	})

	t.Run("Header extraction with non-string fields", func(t *testing.T) {
		type mixedOutput struct {
			Data       string `json:"data" validate:"required"`
			HeaderStr  string `header:"X-String"`
			NotAHeader int    `header:"number"`
		}

		engine := NewEngine(validator.New())

		output := &mixedOutput{
			Data:       "test",
			HeaderStr:  "headerValue",
			NotAHeader: 42,
		}

		headers, result, err := OutputData(engine, output)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(headers) != 1 {
			t.Errorf("Expected 1 header, got %d", len(headers))
		}
		if headers["X-String"] != "headerValue" {
			t.Errorf("Expected X-String 'headerValue', got '%s'", headers["X-String"])
		}
		if result.Data != "test" {
			t.Errorf("Expected data 'test', got '%s'", result.Data)
		}
	})
}
