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

// Operator roles. Operator.Role is a plain string; these are the only two
// values the server accepts.
const (
	OperatorRoleAdmin = "admin"
	OperatorRoleUser  = "user"
)

// ValidOperatorRole reports whether r is a known operator role.
func ValidOperatorRole(r string) bool {
	return r == OperatorRoleAdmin || r == OperatorRoleUser
}

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

	// FailedLoginAttempts counts consecutive failed password logins; it
	// resets to 0 on a successful login or when an expired lock is cleared
	// (#263). LockedUntil, when non-nil and in the future, blocks login
	// regardless of credentials.
	FailedLoginAttempts int        `json:"-"`
	LockedUntil         *time.Time `json:"-"`
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
	// Token is the raw session token carried in the operator's cookie. It is
	// transient: the Store persists only a keyed verifier, never the raw value.
	Token      string
	OperatorID string
	State      SessionState
	ExpiresAt  time.Time
	CreatedAt  time.Time
}
