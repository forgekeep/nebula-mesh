package pki

import (
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	ca, err := NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	if ca.CACert() == nil {
		t.Fatal("CACert is nil")
	}
	if ca.CACert().Name() != "test-ca" {
		t.Errorf("name = %q, want %q", ca.CACert().Name(), "test-ca")
	}
	if !ca.CACert().IsCA() {
		t.Error("expected IsCA to be true")
	}

	certPEM, err := ca.CACertPEM()
	if err != nil {
		t.Fatalf("CACertPEM: %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("cert PEM is empty")
	}
}

func TestCAFingerprint(t *testing.T) {
	ca, err := NewCA("fp-test", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	fp, err := ca.CACertFingerprint()
	if err != nil {
		t.Fatalf("CACertFingerprint: %v", err)
	}
	if fp == "" {
		t.Error("fingerprint is empty")
	}
}

// TestCAManager_Wipe covers GHSA-8h84-fhqq-q58v: after Wipe(), the
// underlying ed25519 private-key slice is zeroed in place. Callers
// deferred Wipe at every Resolve()/NewCA() site so the plaintext does
// not linger on the heap waiting for GC.
func TestCAManager_Wipe(t *testing.T) {
	ca, err := NewCA("wipe-test", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	key := ca.RawKey()
	if len(key) == 0 {
		t.Fatal("RawKey returned empty slice")
	}
	allZero := func(b []byte) bool {
		for _, v := range b {
			if v != 0 {
				return false
			}
		}
		return true
	}
	if allZero(key) {
		t.Fatal("key already zero before Wipe — test broken")
	}

	ca.Wipe()

	// RawKey shares storage with the internal slice; the live reference
	// taken above must now read as all zeros.
	if !allZero(key) {
		t.Error("Wipe() did not zero the underlying ed25519 key slice")
	}
}

// TestCAManager_Wipe_NilSafe verifies the documented nil-safety so
// callers can do `defer caMgr.Wipe()` before the error check.
func TestCAManager_Wipe_NilSafe(t *testing.T) {
	var nilMgr *CAManager
	nilMgr.Wipe() // must not panic
}
