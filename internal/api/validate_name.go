package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// conflictingHostName returns the host that already holds name inside the
// network, or nil when the name is free.
//
// This is the friendly fast-path counterpart of validateHostIPs: looking the
// name up before the write lets the operator read a cause that names the
// incumbent, instead of a constraint failure the handler can only report as a
// server fault. excludeHostID keeps a rename that leaves the name unchanged
// from conflicting with itself.
//
// It is a courtesy, not a guarantee — two concurrent writers can both find the
// name free. UNIQUE(network_id, name) stays the authority, and the store still
// reports ErrDuplicateEntry when this check loses the race.
func conflictingHostName(ctx context.Context, s store.Store, networkID, name, excludeHostID string) (*models.Host, error) {
	existing, err := s.GetHostByName(ctx, networkID, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if existing.ID == excludeHostID {
		return nil, nil
	}
	return existing, nil
}

// duplicateHostNameMsg phrases the collision for the API client.
func duplicateHostNameMsg(name string) string {
	return fmt.Sprintf("a host named %q already exists in this network", name)
}
