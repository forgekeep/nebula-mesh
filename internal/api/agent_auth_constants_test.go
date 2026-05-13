package api

import "testing"

// TestAgentAuthAuditConstants pins the audit action labels and reason codes
// introduced for ADR 0004 (#75). The strings are part of the public API of
// the audit log — UIs and external log aggregators key off them — so flipping
// a string here is a breaking change that needs a deliberate test update.
func TestAgentAuthAuditConstants(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{auditHostAuthFailed, "host.auth.failed"},
		{auditHostRotateCertRequested, "host.rotate-cert.requested"},
		{auditHostReenrollRequested, "host.reenroll.requested"},
		{auditHostRekeyCompleted, "host.rekey.completed"},
		{authReasonUnknownFingerprint, "unknown_fingerprint"},
		{authReasonBadSignature, "bad_signature"},
		{authReasonTimestampSkew, "timestamp_skew"},
		{authReasonReplayedNonce, "replayed_nonce"},
		{authReasonRevoked, "revoked"},
		{authReasonGone, "gone"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("constant = %q, want %q", c.got, c.want)
		}
	}
}
