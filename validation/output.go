package validation

import (
	"reflect"

	"github.com/grzegorzmaniak/gothic/errors"
	"go.uber.org/zap"
)

// OutputData validates the output struct and prepares headers and body for response.
// It returns the header map, the validated output struct, and any error that occurred.
// NOTE: I dont think that this is the fastest way to do this, so if you have any
// suggestions, please let me know. (Or make a PR)
func OutputData[Output any](output *Output) (map[string]string, *Output, *errors.AppError) {
	// - Initialize an empty header map
	headers := make(map[string]string)

	if output == nil {
		return headers, nil, errors.NewInternalServerError("Output data is nil, cannot validate", nil, "nil_output_validation")
	}

	if CustomValidator == nil {
		zap.L().Debug("CustomValidator is nil, initializing default validator")
		initDefaultValidator()
	}

	// - Validate the output structure
	if err := CustomValidator.Struct(*output); err != nil {
		return headers, nil, errors.NewValidationFailed("Output data validation failed", err)
	}

	// - Extract headers from the struct fields tagged with `header:"X-Header-CookieName"`
	val := reflect.ValueOf(*output)
	typ := val.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if headerTag, ok := field.Tag.Lookup("header"); ok {
			if field.Type.Kind() != reflect.String {
				zap.L().Warn("Header field is not of type string, skipping", zap.String("field", field.Name))
				continue
			}
			headerValue := val.Field(i).String()
			headers[headerTag] = headerValue
		}
	}

	// - Return the extracted headers, the validated output, and nil error
	return headers, output, nil
}
