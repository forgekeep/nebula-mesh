package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// DefaultAdminUsername is the username assigned to the auto-seeded admin operator.
const DefaultAdminUsername = "admin"

// SeedAdminOperator creates the initial admin operator from the configured
// password and API key when no operators exist yet. It is safe to call on
// every startup: it is idempotent and a no-op if the operators table is
// already populated. Either uiPassword or apiKey may be empty.
//
// It returns true if a new admin was seeded so the caller can log it.
func SeedAdminOperator(ctx context.Context, s store.Store, uiPassword, apiKey string) (bool, error) {
	existing, err := s.ListOperators(ctx)
	if err != nil {
		return false, fmt.Errorf("list operators: %w", err)
	}
	if len(existing) > 0 {
		return false, nil
	}

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
		ID:           uuid.New().String(),
		Username:     DefaultAdminUsername,
		DisplayName:  "Administrator",
		PasswordHash: string(hash),
		Role:         "admin",
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		return false, fmt.Errorf("create admin operator: %w", err)
	}

	if apiKey != "" {
		keyHash := sha256.Sum256([]byte(apiKey))
		err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
			ID:         uuid.New().String(),
			OperatorID: op.ID,
			Name:       "legacy-config-key",
			KeyHash:    hex.EncodeToString(keyHash[:]),
		})
		if err != nil {
			return false, fmt.Errorf("seed admin api key: %w", err)
		}
	}

	return true, nil
}

// HashAPIKey hashes an API key for storage. Used by both bootstrap and the
// API auth middleware so the same algorithm is applied on insert and lookup.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
