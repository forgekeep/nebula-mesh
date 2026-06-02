package api

import (
	"context"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/revocation"
)

// Durable-revocation sentinels (GHSA-339v-266x-79xr). Aliased from the shared
// revocation package so the api handlers and the mobilebundle builder enforce
// one canonical rule. errors.Is against these matches errors returned by either
// package.
var (
	errHostBlocked      = revocation.ErrHostBlocked
	errOperatorDisabled = revocation.ErrOperatorDisabled
)

// checkIssuanceAllowed rejects certificate issuance for a blocked host or a
// host whose owning operator has been disabled. Every signing path —
// enrollment and renewal — must call it before caMgr.Sign. See
// revocation.CheckIssuanceAllowed for the rationale.
func (s *Server) checkIssuanceAllowed(ctx context.Context, host *models.Host) error {
	return revocation.CheckIssuanceAllowed(ctx, s.store, host)
}
