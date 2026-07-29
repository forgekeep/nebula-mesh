package cli

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func loadRuntimeKeys(encoded string) (*keystore.Master, *credentialhash.Hasher, error) {
	if encoded == "" {
		return nil, nil, keystore.ErrInvalidMasterKey
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", keystore.ErrInvalidMasterKey, err)
	}
	defer keystore.Zeroize(raw)

	master, err := keystore.NewMaster(raw)
	if err != nil {
		return nil, nil, err
	}
	hasher, err := credentialhash.New(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("credential hasher: %w", err)
	}
	return master, hasher, nil
}

func credentialCutoverMasterGuard(master *keystore.Master) func(context.Context, *store.SQLiteStore) error {
	return func(ctx context.Context, s *store.SQLiteStore) error {
		resolver := pki.NewCAResolver(s, master)
		cas, err := s.ListCAs(ctx)
		if err != nil {
			return fmt.Errorf("list CAs: %w", err)
		}
		for _, ca := range cas {
			if _, err := resolver.LoadByID(ctx, ca.ID); err != nil {
				return fmt.Errorf("master key cannot decrypt CA %q (%s): %w", ca.Name, ca.ID, err)
			}
		}
		return nil
	}
}
