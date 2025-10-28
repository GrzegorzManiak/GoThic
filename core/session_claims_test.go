package core

import (
	"reflect"
	"testing"
)

// TestSessionClaims_HasClaim tests the HasClaim method.
func TestSessionClaims_HasClaim(t *testing.T) {
	sc := &SessionClaims{Claims: map[string]string{"key1": "value1"}}
	if !sc.HasClaim("key1") {
		t.Error("Expected to have claim 'key1', but didn't")
	}
	if sc.HasClaim("key2") {
		t.Error("Expected to not have claim 'key2', but did")
	}
	scNil := &SessionClaims{}
	if scNil.HasClaim("key1") {
		t.Error("Expected to not have claim on nil map, but did")
	}
}

// TestSessionClaims_GetClaim tests the GetClaim method.
func TestSessionClaims_GetClaim(t *testing.T) {
	sc := &SessionClaims{Claims: map[string]string{"key1": "value1"}}
	val, ok := sc.GetClaim("key1")
	if !ok || val != "value1" {
		t.Errorf("Expected 'value1', true; got '%s', %v", val, ok)
	}

	val, ok = sc.GetClaim("key2")
	if ok || val != "" {
		t.Errorf("Expected '', false; got '%s', %v", val, ok)
	}

	scNil := &SessionClaims{}
	val, ok = scNil.GetClaim("key1")
	if ok || val != "" {
		t.Errorf("Expected '', false on nil map; got '%s', %v", val, ok)
	}
}

// TestSessionClaims_SetClaim tests the SetClaim method.
func TestSessionClaims_SetClaim(t *testing.T) {
	sc := &SessionClaims{}
	sc.SetClaim("key1", "value1")
	if val, ok := sc.Claims["key1"]; !ok || val != "value1" {
		t.Errorf("Expected 'value1', got '%s'", val)
	}

	// Test overwrite
	sc.SetClaim("key1", "newValue")
	if val, ok := sc.Claims["key1"]; !ok || val != "newValue" {
		t.Errorf("Expected 'newValue', got '%s'", val)
	}
}

// TestSessionClaims_SetIfNotSet tests the SetIfNotSet method.
func TestSessionClaims_SetIfNotSet(t *testing.T) {
	sc := &SessionClaims{}
	sc.SetIfNotSet("key1", "value1")
	if val, ok := sc.Claims["key1"]; !ok || val != "value1" {
		t.Errorf("Expected 'value1', got '%s'", val)
	}

	// Test not to overwrite
	sc.SetIfNotSet("key1", "newValue")
	if val, ok := sc.Claims["key1"]; !ok || val != "value1" {
		t.Errorf("Expected 'value1' not to be overwritten, got '%s'", val)
	}
}

// TestSessionClaims_EncodeDecodePayload tests the payload encoding and decoding logic.
func TestSessionClaims_EncodeDecodePayload(t *testing.T) {
	originalClaims := &SessionClaims{HasSession: true}
	originalClaims.SetClaim("user_id", "123")
	originalClaims.SetClaim("role", "admin")

	encoded, err := originalClaims.EncodePayload()
	if err != nil {
		t.Fatalf("EncodePayload failed: %v", err)
	}
	if encoded == "" {
		t.Fatal("Encoded payload is empty")
	}

	newClaims := &SessionClaims{}
	err = newClaims.DecodePayload(encoded)
	if err != nil {
		t.Fatalf("DecodePayload failed: %v", err)
	}

	if !reflect.DeepEqual(originalClaims.Claims, newClaims.Claims) {
		t.Errorf("Decoded claims do not match original. Got %v, want %v", newClaims.Claims, originalClaims.Claims)
	}
}

// TestSessionClaims_DecodePayload_Errors tests error cases for DecodePayload.
func TestSessionClaims_DecodePayload_Errors(t *testing.T) {
	sc := &SessionClaims{}

	// Test invalid base64
	err := sc.DecodePayload("not-valid-base64-$$")
	if err == nil {
		t.Error("Expected an error for invalid base64, but got nil")
	}

	// Test valid base64 but invalid json
	// "invalid" in base64 is "aW52YWxpZA=="
	err = sc.DecodePayload("aW52YWxpZA==")
	if err == nil {
		t.Error("Expected an error for invalid json, but got nil")
	}
}
