package api

import (
	"context"
	"fmt"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
)

// caForHost returns the CAManager that should sign certificates for the
// given host. Resolution order:
//
//  1. If a CAResolver is configured and the host has a non-empty CAID
//     that differs from the seeded default, decrypt the CA from the
//     store. Each call returns a fresh manager — there is no in-process
//     cache of unwrapped key material.
//  2. Otherwise fall back to the legacy single-CA manager passed at
//     server construction (s.ca). This keeps tests and pre-migration
//     deployments working unchanged.
func (s *Server) caForHost(ctx context.Context, host *models.Host) (*pki.CAManager, error) {
	if s.caResolver != nil && host.CAID != "" && host.CAID != s.defaultCAID {
		return s.caResolver.LoadByID(ctx, host.CAID)
	}
	if s.ca == nil {
		return nil, fmt.Errorf("no CA available for host %s", host.ID)
	}
	return s.ca, nil
}

