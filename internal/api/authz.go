package api

import (
	"context"
	"errors"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// actorOwnsCA returns true if the actor in ctx is admin, or owns the CA with caID.
// Returns (false, nil) for empty caID or ErrNotFound. Errors only for unexpected DB errors.
func (s *Server) actorOwnsCA(ctx context.Context, caID string) (bool, error) {
	if actorIsAdmin(ctx) {
		return true, nil
	}
	if caID == "" {
		return false, nil
	}
	actor := ActorOf(ctx)
	if actor == nil {
		// actorIsAdmin returned false but ActorOf is nil — defensive; treat as
		// forbidden. Unreachable on the current bearerAuth path; if it ever
		// fires it usually means middleware ordering regressed, so log loud.
		s.logger.Warn("authz: nil actor with non-admin context — bearerAuth ordering regression?", "ca_id", caID)
		return false, nil
	}
	ca, err := s.store.GetCA(ctx, caID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return ca.OwnerOperatorID == actor.ID, nil
}

// canAccessHost returns true if the actor in ctx is admin, or owns the host's CA.
func (s *Server) canAccessHost(ctx context.Context, h *models.Host) (bool, error) {
	if h == nil {
		return false, nil
	}
	return s.actorOwnsCA(ctx, h.CAID)
}

// canAccessNetwork returns true if the actor in ctx is admin, or owns the network's CA.
func (s *Server) canAccessNetwork(ctx context.Context, n *models.Network) (bool, error) {
	if n == nil {
		return false, nil
	}
	return s.actorOwnsCA(ctx, n.CAID)
}
