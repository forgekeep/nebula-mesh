package web

import (
	"context"
	"errors"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// conflictingHostName returns the host that already holds name inside the
// network, or nil when the name is free.
//
// Mirrors validateHostIPForNetwork: resolve the collision before writing so
// the form comes back with a reason naming the incumbent, rather than the
// bare 500 a raw constraint failure leaves the handler with. excludeHostID
// keeps an edit that leaves the name unchanged from conflicting with itself.
//
// The lookup can be raced by a concurrent writer; UNIQUE(network_id, name)
// stays the authority and the store still reports ErrDuplicateEntry if so.
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
