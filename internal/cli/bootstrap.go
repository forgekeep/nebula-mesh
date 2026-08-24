package cli

import (
	"context"
	"fmt"
	"uuid"

	"golang.org/x/crypto/bcrypt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// DefaultAdminUsername is the username assigned to the auto-seeded admin operator.
const DefaultAdminUsername = "admin"

// SeedAdminOperator creates the initial admin operator from the configured
// password and API key when no operators exist yet. It is safe to call on
// every startup: it is idempotent and a no-op if the operators table is
// already populated. Either uiPassword or apiKey may be empty.
//
// When apiKey is non-empty its keyed verifier is stored as the admin's first
// operator API key. The apiKey value comes from the caller (Init generates
// it inline; Serve passes ""), not from a persisted config field. Runtime
// auth via bearerAuth middleware authenticates exclusively through
// operator_api_keys.
//
// The empty-table check and the inserts are delegated to the store as a
// single atomic operation (SeedInitialAdminOperator). Two concurrent
// first-boot invocations therefore cannot both seed an admin row: the
// race-loser's conditional INSERT sees a non-empty operators table and
// returns (false, nil) without writing.
//
// It returns true if this call performed the seed so the caller can log it.
func SeedAdminOperator(ctx context.Context, s store.Store, uiPassword, apiKey string) (bool, error) {
	secret := uiPassword
	if secret == "" {
		secret = apiKey
	}
	if secret == "" {
		return false, nil // nothing to seed
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return false, fmt.Errorf("hash admin password: %w", err)
	}

	op := &models.Operator{
		ID:           uuid.NewV4().String(),
		Username:     DefaultAdminUsername,
		DisplayName:  "Administrator",
		PasswordHash: string(hash),
		Role:         "admin",
	}
	var key *models.OperatorAPIKey
	if apiKey != "" {
		key = &models.OperatorAPIKey{
			ID:         uuid.NewV4().String(),
			OperatorID: op.ID,
			Name:       "initial-admin-key",
		}
	}

	seeded, err := s.SeedInitialAdminOperator(ctx, op, key, apiKey)
	if err != nil {
		return false, fmt.Errorf("seed admin operator: %w", err)
	}
	return seeded, nil
}
