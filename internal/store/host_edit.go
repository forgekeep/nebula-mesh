package store

import (
	"context"
	"log/slog"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// ApplyHostEdit persists an edited host together with the follow-up writes a
// host edit implies. Both edit paths — the API's PATCH handler and the web
// UI's edit form — go through here so they cannot drift apart on what an edit
// means; they previously kept separate copies of these rules, and the copies
// disagreed about whether a group change needs a new certificate.
//
// Callers are expected to have snapshotted `before`, merged their input into
// `after`, validated it, and established that something actually changed.
//
// The pending-rekey flag is set on the host struct rather than through a
// separate SetPendingRekey write. UpdateHost commits it in the same
// transaction as the config_version reset (SEC-PERSIST-001), so a crash
// between the two cannot leave a host whose certificate-bound fields moved but
// whose re-issuance was never scheduled — which would strand an agent on a
// stale, possibly more permissive, certificate. Setting the flag when it is
// already set is a no-op, so retries stay idempotent.
//
// The returned error is the one from persisting the host; callers map it to
// their own transport (ErrIPTaken → 409, ErrNotFound → 404). The network
// config-version bump is best-effort and only logged: it is a propagation hint
// for peers, and failing an otherwise-applied edit over it would be worse than
// a late peer update.
func ApplyHostEdit(ctx context.Context, s Store, logger *slog.Logger, before, after *models.Host) error {
	if models.CertIdentityChanged(before, after) {
		after.PendingRekey = true
	}

	if err := s.UpdateHost(ctx, after); err != nil {
		return err
	}

	// A role change alters the topology every peer renders (lighthouse and
	// relay entries), not just this host's own config.
	if before.Role != after.Role {
		if err := s.BumpNetworkConfigVersion(ctx, after.NetworkID); err != nil {
			logger.Error("bump network config version", "network", after.NetworkID, "error", err)
		}
	}
	return nil
}
