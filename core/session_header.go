package core

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

type SessionHeader struct {
	Bearer bool `json:"bearer" validate:"required"`

	// LifetimeSec is the number of seconds after IssuedAt that the session expires.
	LifetimeSec int64 `json:"lifetimeSec" validate:"required"`

	// RefreshPeriodSec is the number of seconds after IssuedAt that the session should be refreshed.
	RefreshPeriodSec int64 `json:"refreshPeriodSec" validate:"required"`

	// IssuedAt is the Unix timestamp when the session was created.
	IssuedAt int64 `json:"issuedAt" validate:"required"`
}

func NewSessionHeader(bearer bool, expiresAt time.Duration, refreshAt time.Duration) SessionHeader {
	return SessionHeader{
		LifetimeSec:      int64(expiresAt.Seconds()),
		RefreshPeriodSec: int64(refreshAt.Seconds()),
		IssuedAt:         time.Now().Unix(),
		Bearer:           bearer,
	}
}

func Decode(header string) (SessionHeader, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return SessionHeader{}, err
	}

	var h SessionHeader
	err = json.Unmarshal(decoded, &h)
	if err != nil {
		return SessionHeader{}, err
	}

	return h, nil
}

func (h SessionHeader) Encode() (string, error) {
	jsonBytes, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(jsonBytes)
	return encoded, nil
}

// IsExpired checks if the session header has expired based on the current time.
// This works for all session headers, including bearer tokens and cookies.
func (h SessionHeader) IsExpired() bool {
	return h.IssuedAt+h.LifetimeSec < time.Now().Unix()
}

// NeedsRefresh checks if the session header needs to be refreshed based on the current time.
// Note: Only works if the header is capable of being updated, e.g., session cookies.
// This will not work as expected for bearer tokens.
func (h SessionHeader) NeedsRefresh() bool {
	return h.IssuedAt+h.RefreshPeriodSec < time.Now().Unix()
}

// IsValid checks if the session header is valid based on its fields.
// It does **not** check if the session is expired or needs refresh.
func (h SessionHeader) IsValid() bool {
	return h.LifetimeSec > 0 && h.RefreshPeriodSec > 0 && h.IssuedAt > 0
}
