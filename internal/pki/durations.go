package pki

import "time"

// DefaultAgentCertDuration is the lifetime of host certificates minted for
// agent-managed hosts that auto-rotate via the poll loop (ADR 0004).
// 30 days strikes a balance between rotation overhead and revocation latency.
const DefaultAgentCertDuration = 30 * 24 * time.Hour

// DefaultMobileCertDuration is the lifetime of host certificates minted for
// Mobile Nebula clients (kind=mobile). Mobile rotation requires the operator
// to re-download a bundle and the user to re-import it manually, so a
// longer lifetime reduces operator burden. The signer clamps to remaining
// CA validity (see signer.go), so practical lifetime is min(365d, CA_remaining).
// Revocation via the blocklist remains the immediate security control.
const DefaultMobileCertDuration = 365 * 24 * time.Hour
