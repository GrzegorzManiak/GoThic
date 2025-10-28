package core

import (
	"reflect"
	"testing"
	"time"
)

// TestNewSessionHeader tests the creation of a new session header.
func TestNewSessionHeader(t *testing.T) {
	expiresAt := 15 * time.Minute
	refreshAt := 5 * time.Minute
	sh := NewSessionHeader(true, expiresAt, refreshAt)

	if !sh.Bearer {
		t.Error("Expected Bearer to be true")
	}
	if sh.LifetimeSec != int64(expiresAt.Seconds()) {
		t.Errorf("Expected LifetimeSec to be %d, got %d", int64(expiresAt.Seconds()), sh.LifetimeSec)
	}
	if sh.RefreshPeriodSec != int64(refreshAt.Seconds()) {
		t.Errorf("Expected RefreshPeriodSec to be %d, got %d", int64(refreshAt.Seconds()), sh.RefreshPeriodSec)
	}
	if sh.IssuedAt > time.Now().Unix() || sh.IssuedAt < time.Now().Unix()-5 {
		t.Errorf("IssuedAt should be approximately the current time, but was %d", sh.IssuedAt)
	}
}

// TestSessionHeader_EncodeDecode tests the encoding and decoding of a session header.
func TestSessionHeader_EncodeDecode(t *testing.T) {
	originalHeader := NewSessionHeader(false, time.Hour, 30*time.Minute)

	encoded, err := originalHeader.Encode()
	if err != nil {
		t.Fatalf("Encode() failed: %v", err)
	}
	if encoded == "" {
		t.Fatal("Encoded string is empty")
	}

	decodedHeader, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() failed: %v", err)
	}

	if !reflect.DeepEqual(originalHeader, decodedHeader) {
		t.Errorf("Decoded header does not match original. Got %+v, want %+v", decodedHeader, originalHeader)
	}
}

// TestDecode_Errors tests error handling in the Decode function.
func TestDecode_Errors(t *testing.T) {
	// Test with invalid base64
	_, err := Decode("invalid-base64-string-!@#")
	if err == nil {
		t.Error("Expected an error for invalid base64, but got nil")
	}

	// Test with valid base64 but invalid JSON
	// "not-json" encoded in base64
	_, err = Decode("bm90LWpzb24")
	if err == nil {
		t.Error("Expected an error for invalid JSON, but got nil")
	}
}

// TestSessionHeader_IsExpired tests the IsExpired method.
func TestSessionHeader_IsExpired(t *testing.T) {
	// Not expired
	sh := SessionHeader{IssuedAt: time.Now().Unix(), LifetimeSec: 3600}
	if sh.IsExpired() {
		t.Error("Session header should not be expired")
	}

	// Expired
	shExpired := SessionHeader{IssuedAt: time.Now().Unix() - 3601, LifetimeSec: 3600}
	if !shExpired.IsExpired() {
		t.Error("Session header should be expired")
	}
}

// TestSessionHeader_NeedsRefresh tests the NeedsRefresh method.
func TestSessionHeader_NeedsRefresh(t *testing.T) {
	// Does not need refresh
	sh := SessionHeader{IssuedAt: time.Now().Unix(), RefreshPeriodSec: 1800}
	if sh.NeedsRefresh() {
		t.Error("Session header should not need refresh")
	}

	// Needs refresh
	shRefresh := SessionHeader{IssuedAt: time.Now().Unix() - 1801, RefreshPeriodSec: 1800}
	if !shRefresh.NeedsRefresh() {
		t.Error("Session header should need refresh")
	}
}

// TestSessionHeader_IsValid tests the IsValid method.
func TestSessionHeader_IsValid(t *testing.T) {
	// Valid
	sh := SessionHeader{LifetimeSec: 3600, RefreshPeriodSec: 1800, IssuedAt: time.Now().Unix()}
	if !sh.IsValid() {
		t.Error("Session header should be valid")
	}

	// Invalid due to LifetimeSec
	shInvalidLife := SessionHeader{LifetimeSec: 0, RefreshPeriodSec: 1800, IssuedAt: time.Now().Unix()}
	if shInvalidLife.IsValid() {
		t.Error("Session header should be invalid due to zero LifetimeSec")
	}

	// Invalid due to RefreshPeriodSec
	shInvalidRefresh := SessionHeader{LifetimeSec: 3600, RefreshPeriodSec: 0, IssuedAt: time.Now().Unix()}
	if shInvalidRefresh.IsValid() {
		t.Error("Session header should be invalid due to zero RefreshPeriodSec")
	}

	// Invalid due to IssuedAt
	shInvalidIssued := SessionHeader{LifetimeSec: 3600, RefreshPeriodSec: 1800, IssuedAt: 0}
	if shInvalidIssued.IsValid() {
		t.Error("Session header should be invalid due to zero IssuedAt")
	}
}
