package models

import "time"

// OperatorStatus represents the active/disabled state of an operator.
type OperatorStatus string

const (
	OperatorStatusActive   OperatorStatus = "active"
	OperatorStatusDisabled OperatorStatus = "disabled"
)

// OperatorAuthProvider identifies the authentication backend for an operator.
type OperatorAuthProvider string

const (
	OperatorAuthLocal OperatorAuthProvider = "local"
	OperatorAuthOIDC  OperatorAuthProvider = "oidc"
)

// Operator is an administrative user of the management server.
type Operator struct {
	ID           string               `json:"id"`
	Username     string               `json:"username"`
	DisplayName  string               `json:"display_name"`
	PasswordHash string               `json:"-"`
	AuthProvider OperatorAuthProvider `json:"auth_provider"`
	Status       OperatorStatus       `json:"status"`
	Role         string               `json:"role"`
	TOTPSecret   string               `json:"-"`
	TOTPEnabled  bool                 `json:"totp_enabled"`
	OIDCIssuer   string               `json:"oidc_issuer,omitempty"`
	OIDCSubject  string               `json:"oidc_subject,omitempty"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	LastLoginAt  *time.Time           `json:"last_login_at,omitempty"`
}

// OperatorAPIKey is a per-operator API key. Only the hash is stored.
type OperatorAPIKey struct {
	ID         string     `json:"id"`
	OperatorID string     `json:"operator_id"`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// SessionState is the lifecycle phase of an operator session.
type SessionState string

const (
	SessionStateAuthenticated SessionState = "authenticated"
	SessionStatePendingTOTP   SessionState = "pending_totp"
)

// OperatorSession represents a UI session. A session in `pending_totp` state
// is awaiting a second-factor verification and is not yet authenticated.
type OperatorSession struct {
	Token      string
	OperatorID string
	State      SessionState
	ExpiresAt  time.Time
	CreatedAt  time.Time
}
