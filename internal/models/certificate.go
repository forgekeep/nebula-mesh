package models

import "time"

type CertificateInfo struct {
	ID          string    `json:"id"`
	HostID      string    `json:"host_id"`
	Fingerprint string    `json:"fingerprint"`
	PEM         string    `json:"pem"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IsCurrent   bool      `json:"is_current"`
	CreatedAt   time.Time `json:"created_at"`
}
