package api

import (
	"context"
	"fmt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

// caForHost returns the CAManager that should sign certificates for the
// given host. Requires host.CAID to be set; multi-CA resolution via caResolver.
// Hosts without a resolvable CAID are rejected.
func (s *Server) caForHost(ctx context.Context, host *models.Host) (*pki.CAManager, error) {
	if host.CAID == "" {
		return nil, fmt.Errorf("host %s has no ca_id", host.ID)
	}
	if s.caResolver == nil {
		return nil, fmt.Errorf("CA resolver not configured")
	}
	return s.caResolver.LoadByID(ctx, host.CAID)
}
