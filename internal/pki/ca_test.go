package pki

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	ca, encKeyPEM, err := NewCA("test-ca", 24*time.Hour)
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
	if len(encKeyPEM) == 0 {
		t.Error("encrypted key PEM is empty")
	}

	certPEM, err := ca.CACertPEM()
	if err != nil {
		t.Fatalf("CACertPEM: %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("cert PEM is empty")
	}
}

func TestSaveAndLoadCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	passphrase := "test-passphrase"

	ca, _, err := NewCA("save-load-test", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	if err := ca.Save(certPath, keyPath, passphrase); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file not found: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file not found: %v", err)
	}

	// Load back
	loaded, err := LoadCA(certPath, keyPath, passphrase)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	if loaded.CACert().Name() != "save-load-test" {
		t.Errorf("loaded name = %q, want %q", loaded.CACert().Name(), "save-load-test")
	}
}

func TestLoadCA_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca, _, err := NewCA("wrong-pass-test", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	if err := ca.Save(certPath, keyPath, "correct"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err = LoadCA(certPath, keyPath, "wrong")
	if err == nil {
		t.Fatal("expected error with wrong passphrase, got nil")
	}
}

func TestCAFingerprint(t *testing.T) {
	ca, _, err := NewCA("fp-test", 24*time.Hour)
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
