package models

import "time"

// WebhookSubscription is an operator-owned outbound webhook target (#256
// phase 2). The HMAC secret is stored envelope-encrypted (a per-row DEK wrapped
// under the master key, the secret sealed under the DEK), so the encrypted
// fields never serialize to JSON; API responses expose only HasSecret.
type WebhookSubscription struct {
	ID              string   `json:"id"`
	OwnerOperatorID string   `json:"owner_operator_id"`
	URL             string   `json:"url"`
	Events          []string `json:"events"` // empty = all events
	Active          bool     `json:"active"`
	AllowPrivate    bool     `json:"allow_private"`

	// Envelope-encrypted HMAC secret. All nil => unsigned deliveries.
	EncryptedSecretDEK []byte `json:"-"`
	NonceDEK           []byte `json:"-"`
	EncryptedSecret    []byte `json:"-"`
	NonceSecret        []byte `json:"-"`

	// HasSecret is a computed, response-only flag (the secret itself is never
	// returned). It is not persisted as a column.
	HasSecret bool `json:"has_secret"`

	// Per-subscription delivery observability.
	LastDeliveryAt      *time.Time `json:"last_delivery_at,omitempty"`
	LastStatus          string     `json:"last_status,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
