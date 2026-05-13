package pop

import "testing"

func TestCanonicalString_Format(t *testing.T) {
	got := CanonicalString("GET", "/api/v1/agent/updates", "mgmt.example.com", "2026-05-13T08:30:00Z", "abc-nonce")
	want := "GET\n/api/v1/agent/updates\nmgmt.example.com\n2026-05-13T08:30:00Z\nabc-nonce"
	if got != want {
		t.Errorf("canonical mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestCanonicalString_FieldsAreLineSeparated(t *testing.T) {
	// Embedded newlines in any field would let an attacker hide bytes from
	// the verifier. We don't sanitise the input here — the API layer feeds
	// trusted, fixed-shape values — but the canonical helper must still
	// produce exactly four \n separators.
	got := CanonicalString("GET", "/p", "h", "t", "n")
	count := 0
	for _, c := range got {
		if c == '\n' {
			count++
		}
	}
	if count != 4 {
		t.Errorf("got %d newlines, want 4 in %q", count, got)
	}
}

func TestHeaderConstants(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{HeaderFingerprint, "X-Nebula-Fingerprint"},
		{HeaderTimestamp, "X-Nebula-Timestamp"},
		{HeaderNonce, "X-Nebula-Nonce"},
		{HeaderSignature, "X-Nebula-Signature"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("header constant = %q, want %q", c.got, c.want)
		}
	}
}
