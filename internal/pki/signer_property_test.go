package pki

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// hostSignRequest builds a minimal valid SignRequest for the property tests.
func hostSignRequest(t *testing.T, dur time.Duration) SignRequest {
	t.Helper()
	pub, _ := generateHostKeypair(t)
	return SignRequest{
		Name:      "prop-host",
		PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		Duration:  dur,
	}
}

// TestSign_AfterWipe_ProducesUnverifiableCert pins the behavioral half of the
// GHSA-8h84 contract documented on CAManager.Wipe: "after Wipe(), any
// subsequent Sign() will produce invalid signatures." The existing ca_test.go
// only checks the key bytes are zeroed — the slice-zero property. This asserts
// the consequence: a cert minted after Wipe cannot be verified against the CA,
// so if caKey ever became a non-aliased copy (a clone, a crypto.Signer
// adapter), Wipe leaving the live signer functional would be caught here.
func TestSign_AfterWipe_ProducesUnverifiableCert(t *testing.T) {
	ca := newTestCA(t)

	certPEM, err := ca.CACertPEM()
	if err != nil {
		t.Fatalf("CACertPEM: %v", err)
	}
	pool, err := cert.NewCAPoolFromPEM(certPEM)
	if err != nil {
		t.Fatalf("NewCAPoolFromPEM: %v", err)
	}

	// Positive control: a cert signed with the live key verifies. This rules
	// out a broken verify setup masking the post-wipe assertion below.
	good, err := ca.Sign(hostSignRequest(t, time.Hour))
	if err != nil {
		t.Fatalf("Sign (pre-wipe): %v", err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), good); err != nil {
		t.Fatalf("pre-wipe cert failed to verify: %v", err)
	}

	ca.Wipe()

	// In practice Sign does not error on a zeroed ed25519 key — it produces a
	// signature that cannot verify against the CA's real public key, so the
	// verify-failure branch is the one that fires. The error branch is
	// defensive: a future guard refusing to sign with a wiped key would also
	// satisfy the contract.
	bad, err := ca.Sign(hostSignRequest(t, time.Hour))
	if err != nil {
		return
	}
	if _, err := pool.VerifyCertificate(time.Now(), bad); err == nil {
		t.Error("cert signed after Wipe() verified against the CA pool — key was not effectively destroyed")
	}
}

// TestSign_HostCertIsNeverCA pins that minted host certs are never CA certs.
// signer.go hardcodes IsCA: false; this guards against a future "preserve
// cert shape on renew" refactor (step-ca's Renew copies IsCA/MaxPathLen from
// the old cert — exactly the pattern this must not adopt).
func TestSign_HostCertIsNeverCA(t *testing.T) {
	ca := newTestCA(t)
	hostCert, err := ca.Sign(hostSignRequest(t, time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if hostCert.IsCA() {
		t.Error("minted host cert has IsCA=true; host certs must never be CAs")
	}
}

// TestSign_ClampsNotAfterToCAExpiry pins the existing clamp: a host cert can
// never outlive its CA. A request beyond the CA's expiry is clamped to the
// CA's NotAfter; a request within validity is left untouched.
func TestSign_ClampsNotAfterToCAExpiry(t *testing.T) {
	ca, err := NewCA("short-ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caNotAfter := ca.CACert().NotAfter()

	t.Run("beyond CA expiry is clamped", func(t *testing.T) {
		hostCert, err := ca.Sign(hostSignRequest(t, 30*24*time.Hour))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !hostCert.NotAfter().Equal(caNotAfter) {
			t.Errorf("notAfter = %v, want clamped to CA expiry %v", hostCert.NotAfter(), caNotAfter)
		}
	})

	t.Run("within validity is not clamped", func(t *testing.T) {
		hostCert, err := ca.Sign(hostSignRequest(t, time.Minute))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !hostCert.NotAfter().Before(caNotAfter) {
			t.Errorf("notAfter = %v, want strictly before CA expiry %v (no clamp expected)", hostCert.NotAfter(), caNotAfter)
		}
		// And it reflects the requested duration (~1m), not some other earlier
		// value — a clamp to the wrong bound would still pass the check above.
		if d := time.Until(hostCert.NotAfter()); d < 30*time.Second || d > 2*time.Minute {
			t.Errorf("notAfter is %v from now, want ~1m (requested duration, unclamped)", d)
		}
	})
}
