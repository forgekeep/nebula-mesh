// Package revocation enforces durable revocation at certificate issuance time
// (GHSA-339v-266x-79xr). Issuance paths used to consult revocation state only
// at poll time; because the blocklist is keyed by certificate fingerprint, a
// blocked host could re-enroll (or regenerate a mobile bundle) and receive a
// fresh certificate with a new fingerprint that no longer matched the blocked
// one — silently undoing the block. Disabling an operator likewise left their
// hosts able to renew forever. Every signing path must call CheckIssuanceAllowed
// before minting a certificate.
package revocation

import (
	"context"
	"errors"
	"fmt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

var (
	// ErrHostBlocked is returned when issuance is refused because the host has
	// been blocked.
	ErrHostBlocked = errors.New("host is blocked")
	// ErrOperatorDisabled is returned when issuance is refused because the
	// operator that owns the host's CA has been disabled.
	ErrOperatorDisabled = errors.New("owning operator is disabled")
)

// CheckIssuanceAllowed reports whether a certificate may be (re-)issued for
// host. It rejects issuance when the host has been blocked or when the operator
// that owns the host's CA has been disabled, so that blocking a host or
// offboarding an operator is durable across re-enroll, renewal, and mobile
// bundle regeneration.
//
// CA retirement is deliberately not checked: CAStatusRetired is not set by any
// production path (rotation uses predecessor/successor links plus trust
// bundles), and a retired-CA guard would risk breaking renewals during a
// rotation grace window for no current benefit.
func CheckIssuanceAllowed(ctx context.Context, s store.Store, host *models.Host) error {
	if host.Status == models.HostStatusBlocked {
		return ErrHostBlocked
	}
	// A host with no CA cannot be signed anyway; the CA resolver rejects it with
	// a clearer message, so defer to that rather than erroring here.
	if host.CAID == "" {
		return nil
	}
	ca, err := s.GetCA(ctx, host.CAID)
	if err != nil {
		return fmt.Errorf("issuance check: resolve CA %s: %w", host.CAID, err)
	}
	op, err := s.GetOperator(ctx, ca.OwnerOperatorID)
	if err != nil {
		return fmt.Errorf("issuance check: resolve operator %s: %w", ca.OwnerOperatorID, err)
	}
	if op.Status == models.OperatorStatusDisabled {
		return ErrOperatorDisabled
	}
	return nil
}
