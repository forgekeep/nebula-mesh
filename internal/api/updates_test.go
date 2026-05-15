package api

// These tests are intentionally minimal and focus on the trust bundle feature logic.
// Full end-to-end authentication testing is covered in integration tests.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// TestTrustBundleLogic_FindsSuccessor verifies trust bundle creation logic.
// This test checks that when a CA has a successor, the trust bundle is created correctly.
func TestTrustBundleLogic_FindsSuccessor(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// Get the default CA
	ca1, err := st.GetCA(ctx, srv.defaultCAID)
	if err != nil {
		t.Fatalf("get CA: %v", err)
	}

	// Create CA2 as successor of CA1
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	master, _ := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))

	ca2, err := pki.RotateAndStoreCA(ctx, st, master, logger, ca1)
	if err != nil {
		t.Fatalf("rotate CA: %v", err)
	}

	// Verify CA2 is successor of CA1
	if ca2.PredecessorID == nil || *ca2.PredecessorID != ca1.ID {
		t.Fatalf("CA2.PredecessorID = %v, want %s", ca2.PredecessorID, ca1.ID)
	}

	// Test: verify FindCAByPredecessor finds CA2
	found, err := st.FindCAByPredecessor(ctx, ca1.ID)
	if err != nil {
		t.Fatalf("FindCAByPredecessor: %v", err)
	}
	if found == nil {
		t.Fatal("FindCAByPredecessor returned nil, want CA2")
	}
	if found.ID != ca2.ID {
		t.Errorf("FindCAByPredecessor returned ID=%q, want %q", found.ID, ca2.ID)
	}

	// Test: trust bundle format
	bundle := ca1.CertPEM + "\n" + ca2.CertPEM

	// Verify bundle has 2 certificates (Nebula format)
	beginCount := strings.Count(bundle, "-----BEGIN NEBULA CERTIFICATE")
	endCount := strings.Count(bundle, "-----END NEBULA CERTIFICATE")
	if beginCount != 2 || endCount != 2 {
		t.Errorf("bundle has %d BEGIN and %d END markers, want 2 each", beginCount, endCount)
	}

	// Verify both certs are present
	if !strings.Contains(bundle, ca1.CertPEM) {
		t.Error("bundle does not contain CA1 cert")
	}
	if !strings.Contains(bundle, ca2.CertPEM) {
		t.Error("bundle does not contain CA2 cert")
	}
}

// TestTrustBundleLogic_NoSuccessor verifies that when CA has no successor,
// FindCAByPredecessor returns ErrNotFound.
func TestTrustBundleLogic_NoSuccessor(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// Get the default CA (which has no successor)
	ca, err := st.GetCA(ctx, srv.defaultCAID)
	if err != nil {
		t.Fatalf("get CA: %v", err)
	}

	// Test: FindCAByPredecessor returns ErrNotFound for CA without successor
	found, err := st.FindCAByPredecessor(ctx, ca.ID)
	if err != store.ErrNotFound {
		t.Errorf("FindCAByPredecessor err = %v, want ErrNotFound", err)
	}
	if found != nil {
		t.Errorf("FindCAByPredecessor returned CA=%+v, want nil", found)
	}
}

