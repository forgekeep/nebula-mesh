package pki

import (
	"testing"
	"time"
)

func TestCARotation_CreateNew(t *testing.T) {
	oldCA, err := NewCA("old-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	rot, err := NewRotation(oldCA, "new-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("NewRotation: %v", err)
	}

	if rot.OldCA().CACert().Name() != "old-ca" {
		t.Errorf("old CA name = %q", rot.OldCA().CACert().Name())
	}
	if rot.NewCA().CACert().Name() != "new-ca" {
		t.Errorf("new CA name = %q", rot.NewCA().CACert().Name())
	}
}

func TestCARotation_TrustBundle(t *testing.T) {
	oldCA, err := NewCA("old-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	rot, err := NewRotation(oldCA, "new-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := rot.TrustBundle()
	if err != nil {
		t.Fatalf("TrustBundle: %v", err)
	}

	if len(bundle) == 0 {
		t.Fatal("trust bundle is empty")
	}

	// Bundle should contain both CAs
	oldPEM, _ := oldCA.CACertPEM()
	newPEM, _ := rot.NewCA().CACertPEM()

	bundleStr := string(bundle)
	if !contains(bundleStr, string(oldPEM)) {
		t.Error("bundle missing old CA")
	}
	if !contains(bundleStr, string(newPEM)) {
		t.Error("bundle missing new CA")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsBytes([]byte(s), []byte(substr)))
}

func containsBytes(s, sub []byte) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if string(s[i:i+len(sub)]) == string(sub) {
			return true
		}
	}
	return false
}
