package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type SessionClaims struct {
	// Claims is a map of claims that are stored in the session, please use the
	// SetClaim and GetClaim methods to set and get claims.
	Claims map[string]string

	// HasSession indicates if the session is valid, this may seem odd, but implicity
	// is not a good security measure, so we need to explicitly set this to true or false.
	HasSession bool
}

func (d *SessionClaims) HasClaim(claim string) bool {
	if d.Claims == nil {
		return false
	}
	_, ok := d.Claims[claim]
	return ok
}

func (d *SessionClaims) GetClaim(claim string) (string, bool) {
	if d.Claims == nil {
		return "", false
	}
	value, ok := d.Claims[claim]
	return value, ok
}

func (d *SessionClaims) SetClaim(claim string, value string) error {
	if d.Claims == nil {
		d.Claims = make(map[string]string)
	}
	d.Claims[claim] = value
	return nil
}

func (d *SessionClaims) SetIfNotSet(claim string, value string) error {
	if d.Claims == nil {
		d.Claims = make(map[string]string)
	}
	if !d.HasClaim(claim) {
		d.Claims[claim] = value
	}
	return nil
}

func (d *SessionClaims) EncodePayload() (string, error) {
	jsonBytes, err := json.Marshal(d.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(jsonBytes)
	return encoded, nil
}

func (d *SessionClaims) DecodePayload(payload string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	err = json.Unmarshal(decoded, &d.Claims)
	if err != nil {
		return fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return nil
}
