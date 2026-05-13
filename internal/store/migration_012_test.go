package store

import "testing"

// TestMigration012_AddsAgentAuthColumns verifies migration 012 added the
// per-host columns required by ADR 0004 implementation (#75): the previous
// cert fingerprint window, the rotation timestamp, the pending-rekey flag,
// and the host's Ed25519 signing public key.
func TestMigration012_AddsAgentAuthColumns(t *testing.T) {
	s := newTestStore(t)
	for _, col := range []string{
		"prev_cert_fingerprint",
		"cert_rotated_at",
		"pending_rekey",
		"signing_pub_pem",
	} {
		if !columnExists(t, s, "hosts", col) {
			t.Errorf("hosts is missing the %s column after Migrate()", col)
		}
	}
}
