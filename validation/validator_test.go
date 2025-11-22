package validation

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestNewEngineUsesProvidedValidator(t *testing.T) {
	customVal := validator.New()
	engine := NewEngine(customVal)

	if engine.Validator() != customVal {
		t.Fatal("expected engine to use provided validator instance")
	}
}

func TestNewEngineCreatesDefaultValidator(t *testing.T) {
	engine := NewEngine(nil)
	if engine.Validator() == nil {
		t.Fatal("expected default validator to be created")
	}

	type testStruct struct {
		Email string `validate:"required,email"`
	}

	if err := engine.Validator().Struct(testStruct{Email: "test@example.com"}); err != nil {
		t.Fatalf("expected valid struct, got %v", err)
	}

	if err := engine.Validator().Struct(testStruct{Email: "bad"}); err == nil {
		t.Fatal("expected validation error for invalid email")
	}
}
