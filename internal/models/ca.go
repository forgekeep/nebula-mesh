package models

import "time"

// CAStatus is the lifecycle status of a CA.
type CAStatus string

const (
	CAStatusActive  CAStatus = "active"
	CAStatusRetired CAStatus = "retired"
)

// CA is a per-operator certificate authority. Private key material lives
// only inside EncryptedKeyMaterial / NonceKey, wrapped under a per-CA DEK
// stored in EncryptedKeyDEK / NonceDEK (envelope encryption — see ADR 0002).
type CA struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	OwnerOperatorID      string    `json:"owner_operator_id"`
	CertPEM              string    `json:"cert_pem"`
	Fingerprint          string    `json:"fingerprint"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	Status               CAStatus  `json:"status"`
	PredecessorID        *string   `json:"predecessor_id,omitempty"`
	EncryptedKeyDEK      []byte    `json:"-"`
	NonceDEK             []byte    `json:"-"`
	EncryptedKeyMaterial []byte    `json:"-"`
	NonceKey             []byte    `json:"-"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}
