package validation

import "github.com/go-playground/validator/v10"

// Engine holds validation state, including the validator instance and dynamic struct cache.
type Engine struct {
	validator          *validator.Validate
	dynamicStructCache dynamicStructCache
}

// NewEngine constructs a validation Engine. If v is nil, a new validator instance is created.
func NewEngine(v *validator.Validate) *Engine {
	if v == nil {
		v = validator.New()
	}

	return &Engine{
		validator: v,
	}
}

// Validator exposes the underlying validator instance.
func (e *Engine) Validator() *validator.Validate {
	if e == nil {
		return nil
	}
	return e.validator
}
