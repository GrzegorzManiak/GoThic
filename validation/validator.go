package validation

import (
	"sync"

	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

// CustomValidator is a global validator instance for struct validation. Im aware
// that this is not the best practice, but for what we need, it is sufficient.
var (
	CustomValidator *validator.Validate
	once            sync.Once
)

// InitValidator sets the global validator instance to the one provided ONCE.
func InitValidator(v *validator.Validate) {
	once.Do(func() {
		zap.L().Debug("Initializing default validator")
		CustomValidator = v
	})
}

// initDefaultValidator initializes the global validator with a default instance.
func initDefaultValidator() {
	InitValidator(validator.New())
}
