package validation

import (
	"sync"
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestInitValidator(t *testing.T) {
	t.Run("Initialize validator sets CustomValidator", func(t *testing.T) {
		once = sync.Once{}
		CustomValidator = nil

		customVal := validator.New()
		InitValidator(customVal)

		if CustomValidator != customVal {
			t.Error("Expected CustomValidator to be set to provided validator")
		}
	})

	t.Run("Subsequent calls to InitValidator do nothing due to sync.Once", func(t *testing.T) {
		firstValidator := CustomValidator

		newVal := validator.New()
		InitValidator(newVal)

		if CustomValidator != firstValidator {
			t.Error("Expected CustomValidator to remain unchanged due to sync.Once")
		}
		if CustomValidator == newVal {
			t.Error("Expected new validator to be ignored due to sync.Once")
		}
	})
}

func TestInitDefaultValidator(t *testing.T) {
	t.Run("Initialize default validator creates new validator instance", func(t *testing.T) {
		once = sync.Once{}
		CustomValidator = nil

		initDefaultValidator()

		if CustomValidator == nil {
			t.Fatal("Expected CustomValidator to be initialized")
		}

		type testStruct struct {
			Email string `validate:"required,email"`
		}

		validData := testStruct{Email: "test@example.com"}
		err := CustomValidator.Struct(validData)
		if err != nil {
			t.Errorf("Expected no validation error for valid data, got %v", err)
		}

		invalidData := testStruct{Email: "not-an-email"}
		err = CustomValidator.Struct(invalidData)
		if err == nil {
			t.Error("Expected validation error for invalid email, got none")
		}
	})
}
