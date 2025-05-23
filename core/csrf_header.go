package core

import (
	"time"
)

type CsrfHeader struct {
	ExpiresAt int64 `json:"expiresAt" validate:"required"`
	RefreshAt int64 `json:"refreshAt" validate:"required"`
}

func NewCsrfHeader(expiresAt time.Duration, refreshAt time.Duration) CsrfHeader {
	return CsrfHeader{
		ExpiresAt: time.Now().Add(expiresAt).Unix(),
		RefreshAt: time.Now().Add(refreshAt).Unix(),
	}
}

func (h *CsrfHeader) IsExpired() bool {
	return h.ExpiresAt < time.Now().Unix()
}

func (h *CsrfHeader) NeedsRefresh() bool {
	return h.RefreshAt < time.Now().Unix()
}

func (h *CsrfHeader) IsValid() bool {
	return h.ExpiresAt > 0 && h.RefreshAt > 0
}
