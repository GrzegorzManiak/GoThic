package validation

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"go.uber.org/zap"
)

// FieldRule defines validation and binding metadata for a dynamic field.
// Tags maps directly to the go-playground/validator tags (e.g., "required,email").
// Type allows simple coercion for common primitives; defaults to "string".
// JSONName/FormName/Header provide overrides for binding tags; if empty the field name (lowercased) is used.
type FieldRule struct {
	Tags     string     `json:"tags" yaml:"tags"`
	Type     string     `json:"type,omitempty" yaml:"type,omitempty"`
	JSONName string     `json:"json,omitempty" yaml:"json,omitempty"`
	FormName string     `json:"form,omitempty" yaml:"form,omitempty"`
	URIName  string     `json:"uri,omitempty" yaml:"uri,omitempty"`
	Header   string     `json:"header,omitempty" yaml:"header,omitempty"`
	Nested   FieldRules `json:"nested,omitempty" yaml:"nested,omitempty"`
}

// FieldRules describes a dynamic struct definition keyed by exported field names.
type FieldRules map[string]FieldRule

type dynamicStructCache struct {
	store sync.Map
}

func (c *dynamicStructCache) Get(key string) (reflect.Type, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	if cached, ok := c.store.Load(key); ok {
		if cachedType, ok := cached.(reflect.Type); ok {
			return cachedType, true
		}
	}
	return nil, false
}

func (c *dynamicStructCache) Set(key string, value reflect.Type) {
	if c == nil || key == "" || value == nil {
		return
	}
	c.store.Store(key, value)
}

func resolveFieldType(rule FieldRule) (reflect.Type, error) {
	typeName := strings.TrimSpace(rule.Type)
	if strings.HasPrefix(typeName, "[]") {
		elemRule := FieldRule{
			Type:   strings.TrimPrefix(typeName, "[]"),
			Nested: rule.Nested,
		}
		elemType, err := resolveFieldType(elemRule)
		if err != nil {
			return nil, err
		}
		return reflect.SliceOf(elemType), nil
	}

	if len(rule.Nested) > 0 {
		return buildDynamicStructType(rule.Nested)
	}

	switch strings.ToLower(typeName) {
	case "", "string":
		return reflect.TypeOf(""), nil
	case "int":
		return reflect.TypeOf(int(0)), nil
	case "int64":
		return reflect.TypeOf(int64(0)), nil
	case "float", "float64":
		return reflect.TypeOf(float64(0)), nil
	case "bool", "boolean":
		return reflect.TypeOf(false), nil
	default:
		return nil, fmt.Errorf("unsupported dynamic field type %q", rule.Type)
	}
}

func buildStructTag(fieldName string, rule FieldRule) reflect.StructTag {
	tagParts := make([]string, 0, 4)

	jsonName := rule.JSONName
	if jsonName == "" {
		jsonName = strings.ToLower(fieldName)
	}
	tagParts = append(tagParts, fmt.Sprintf(`json:"%s"`, jsonName))

	// Only add form, header, and uri tags if NOT nested
	if len(rule.Nested) == 0 {
		formName := rule.FormName
		if formName == "" {
			formName = strings.ToLower(fieldName)
		}
		tagParts = append(tagParts, fmt.Sprintf(`form:"%s"`, formName))

		uriName := rule.URIName
		if uriName == "" {
			uriName = strings.ToLower(fieldName)
		}
		tagParts = append(tagParts, fmt.Sprintf(`uri:"%s"`, uriName))

		if rule.Header != "" {
			tagParts = append(tagParts, fmt.Sprintf(`header:"%s"`, rule.Header))
		}
	} else {
		// Explicitly ignore form, header, and uri for nested structs
		tagParts = append(tagParts, `form:"-"`)
		tagParts = append(tagParts, `header:"-"`)
		tagParts = append(tagParts, `uri:"-"`)
	}

	if strings.TrimSpace(rule.Tags) != "" {
		tagParts = append(tagParts, fmt.Sprintf(`validate:"%s"`, strings.TrimSpace(rule.Tags)))
	}

	return reflect.StructTag(strings.Join(tagParts, " "))
}

func buildDynamicStructType(rules FieldRules) (reflect.Type, error) {
	fieldNames := make([]string, 0, len(rules))
	for name := range rules {
		fieldNames = append(fieldNames, name)
	}
	sort.Strings(fieldNames)

	fields := make([]reflect.StructField, 0, len(rules))
	for _, fieldName := range fieldNames {
		if fieldName == "" {
			return nil, fmt.Errorf("field name cannot be empty")
		}

		if !unicode.IsUpper([]rune(fieldName)[0]) {
			return nil, fmt.Errorf("field name %q must start with an uppercase letter", fieldName)
		}

		rule := rules[fieldName]
		fieldType, err := resolveFieldType(rule)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fieldName, err)
		}

		fields = append(fields, reflect.StructField{
			Name: fieldName,
			Type: fieldType,
			Tag:  buildStructTag(fieldName, rule),
		})
	}

	if len(fields) == 0 {
		return reflect.TypeOf(struct{}{}), nil
	}

	return reflect.StructOf(fields), nil
}

func getDynamicStructType(engine *Engine, cacheID string, rules FieldRules) (reflect.Type, error) {
	if engine == nil {
		return nil, errors.NewInternalServerError("Validator is not initialized", nil)
	}

	if cachedType, ok := engine.dynamicStructCache.Get(cacheID); ok {
		return cachedType, nil
	}

	constructed, err := buildDynamicStructType(rules)
	if err != nil {
		return nil, err
	}

	engine.dynamicStructCache.Set(cacheID, constructed)

	return constructed, nil
}

// DynamicInputData builds a dynamic struct based on the provided FieldRules, binds the request into it,
// validates it using the Engine validator, and returns a simple map of field values.
// cacheID allows reusing the reflected struct definition across invocations to avoid rebuild costs.
func DynamicInputData(ctx *gin.Context, engine *Engine, cacheID string, rules FieldRules) (map[string]interface{}, *errors.AppError) {
	if engine == nil || engine.validator == nil {
		return nil, errors.NewInternalServerError("Validator is not initialized", nil)
	}

	structType, err := getDynamicStructType(engine, cacheID, rules)
	if err != nil {
		zap.L().Debug("Failed to build dynamic struct type", zap.Error(err), zap.String("cacheId", cacheID))
		return nil, errors.NewInternalServerError("Failed to prepare dynamic input rules", err)
	}

	target := reflect.New(structType)

	if bindErr := bindInput(ctx, target.Interface()); bindErr != nil {
		return nil, bindErr
	}

	if err := engine.validator.Struct(target.Elem().Interface()); err != nil {
		zap.L().Debug("Dynamic input validation failed", zap.Error(err))
		return nil, errors.NewValidationFailed("Input validation failed", err)
	}

	value := target.Elem()
	result := make(map[string]interface{}, structType.NumField())
	for i := 0; i < structType.NumField(); i++ {
		result[structType.Field(i).Name] = value.Field(i).Interface()
	}

	return result, nil
}

func setDynamicFieldValue(field reflect.Value, value interface{}) error {
	if !field.CanSet() {
		return fmt.Errorf("field %s cannot be set", field.Type().Name())
	}

	if value == nil {
		return nil
	}

	source := reflect.ValueOf(value)
	if !source.IsValid() {
		return nil
	}

	// Direct assignment or conversion
	if source.Type().AssignableTo(field.Type()) {
		field.Set(source)
		return nil
	}

	if source.Type().ConvertibleTo(field.Type()) {
		field.Set(source.Convert(field.Type()))
		return nil
	}

	// Handle slices where the incoming type is []interface{}
	if field.Kind() == reflect.Slice && source.Kind() == reflect.Slice {
		length := source.Len()
		newSlice := reflect.MakeSlice(field.Type(), length, length)
		for i := 0; i < length; i++ {
			if err := setDynamicFieldValue(newSlice.Index(i), source.Index(i).Interface()); err != nil {
				return err
			}
		}
		field.Set(newSlice)
		return nil
	}

	// Handle nested structs (Map -> Struct)
	if field.Kind() == reflect.Struct && source.Kind() == reflect.Map {
		if mapVal, ok := value.(map[string]interface{}); ok {
			for i := 0; i < field.NumField(); i++ {
				structField := field.Type().Field(i)
				if val, exists := mapVal[structField.Name]; exists {
					if err := setDynamicFieldValue(field.Field(i), val); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}

	return fmt.Errorf("cannot assign value of type %T to field type %s", value, field.Type())
}

// DynamicOutputData validates outbound data against FieldRules and extracts headers based on the rules.
// It returns the header map, the validated body (as the reflected struct), or an AppError.
func DynamicOutputData(engine *Engine, cacheID string, rules FieldRules, output map[string]interface{}) (map[string]string, interface{}, *errors.AppError) {
	if engine == nil || engine.validator == nil {
		return nil, nil, errors.NewInternalServerError("Validator is not initialized", nil)
	}

	structType, err := getDynamicStructType(engine, cacheID, rules)
	if err != nil {
		zap.L().Debug("Failed to build dynamic struct type", zap.Error(err), zap.String("cacheId", cacheID))
		return nil, nil, errors.NewInternalServerError("Failed to prepare dynamic output rules", err)
	}

	target := reflect.New(structType).Elem()
	for i := 0; i < structType.NumField(); i++ {
		fieldName := structType.Field(i).Name
		if val, ok := output[fieldName]; ok {
			if err := setDynamicFieldValue(target.Field(i), val); err != nil {
				zap.L().Debug("Failed to set dynamic output field", zap.Error(err), zap.String("field", fieldName))
				return nil, nil, errors.NewValidationFailed("Output validation failed", err)
			}
		}
	}

	if err := engine.validator.Struct(target.Interface()); err != nil {
		zap.L().Debug("Dynamic output validation failed", zap.Error(err))
		return nil, nil, errors.NewValidationFailed("Output validation failed", err)
	}

	headers := make(map[string]string)
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if headerTag, ok := field.Tag.Lookup("header"); ok && headerTag != "" {
			if field.Type.Kind() != reflect.String {
				zap.L().Warn("Header field is not of type string, skipping", zap.String("field", field.Name))
				continue
			}
			headers[headerTag] = target.Field(i).String()
		}
	}

	return headers, target.Interface(), nil
}
