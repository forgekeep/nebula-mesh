package api

import (
	"context"
	"fmt"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

// signForHost signs with the host's own CA, never with a network fallback.
func (s *Server) signForHost(ctx context.Context, host *models.Host, req pki.SignRequest) (cert.Certificate, []byte, error) {
	if host.CAID == "" {
		return nil, nil, fmt.Errorf("host %s has no ca_id", host.ID)
	}
	if s.caResolver == nil {
		return nil, nil, fmt.Errorf("CA resolver not configured")
	}
	return s.caResolver.SignHost(ctx, host.CAID, req)
}
