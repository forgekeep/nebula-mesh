package models

import "time"

type EnrollmentToken struct {
	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	Token     string    `json:"token"`
	Used      bool      `json:"used"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
