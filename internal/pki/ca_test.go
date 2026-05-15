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
