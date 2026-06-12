package keystore

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func newTestMaster(t *testing.T) *Master {
	t.Helper()
	raw := bytes.Repeat([]byte{0xab}, MasterKeySize)
	m, err := NewMaster(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMaster_FromBase64_RejectsWrongLength(t *testing.T) {
	if _, err := NewMasterFromBase64(""); err == nil {
		t.Error("expected error for empty key")
	}
	if _, err := NewMasterFromBase64(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("expected error for short key")
	}
}

// TestNewMaster_CopiesKeyMaterial proves NewMaster copies its input into the
// AEAD key schedule rather than aliasing it. This is the precondition that
// makes NewMasterFromBase64 safe to zeroize its decoded buffer right after the
// call (#196): wiping the caller's buffer must not corrupt the Master.
func TestNewMaster_CopiesKeyMaterial(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, MasterKeySize)
	m, err := NewMaster(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Caller wipes the source buffer immediately after construction.
	Zeroize(raw)

	// The Master must still wrap/unwrap correctly.
	dek, wrapped, err := m.GenerateDEK([]byte("ca-test"))
	if err != nil {
		t.Fatalf("GenerateDEK after source wipe: %v", err)
	}
	unwrapped, err := m.UnwrapDEK(wrapped, []byte("ca-test"))
	if err != nil {
		t.Fatalf("UnwrapDEK after source wipe: %v", err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Error("dek round-trip mismatch after source key wipe — Master aliased its input")
	}
}

// TestNewMasterFromBase64_RoundTrip guards that decoding + zeroizing the
// transient buffer still yields a fully functional Master (#196).
func TestNewMasterFromBase64_RoundTrip(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, MasterKeySize))
	m, err := NewMasterFromBase64(b64)
	if err != nil {
		t.Fatal(err)
	}

	dek, wrapped, err := m.GenerateDEK([]byte("ca-test"))
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := m.UnwrapDEK(wrapped, []byte("ca-test"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Error("dek round-trip mismatch via base64-constructed master")
	}
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	m := newTestMaster(t)
	dek, wrapped, err := m.GenerateDEK([]byte("ca-test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != DEKSize {
		t.Fatalf("dek length = %d", len(dek))
	}
	if len(wrapped.Nonce) != NonceSize {
		t.Fatalf("nonce length = %d", len(wrapped.Nonce))
	}

	unwrapped, err := m.UnwrapDEK(wrapped, []byte("ca-test"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Error("dek round-trip mismatch")
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	m := newTestMaster(t)
	dek, _, err := m.GenerateDEK([]byte("ca-test"))
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("super-secret CA private key material")
	blob, err := SealWithDEK(dek, pt, []byte("ca-test"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob.Ciphertext, pt) {
		t.Fatal("plaintext appeared inside ciphertext")
	}
	out, err := OpenWithDEK(dek, blob, []byte("ca-test"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Error("seal/open mismatch")
	}
}

func TestOpen_RejectsTamperedCiphertext(t *testing.T) {
	m := newTestMaster(t)
	dek, _, _ := m.GenerateDEK([]byte("ca-test"))
	blob, _ := SealWithDEK(dek, []byte("payload"), []byte("ca-test"))
	blob.Ciphertext[0] ^= 0xff
	if _, err := OpenWithDEK(dek, blob, []byte("ca-test")); err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestUnwrapDEK_RejectsWrongMaster(t *testing.T) {
	m1 := newTestMaster(t)
	_, wrapped, _ := m1.GenerateDEK([]byte("ca-test"))

	other, _ := NewMaster(bytes.Repeat([]byte{0xcd}, MasterKeySize))
	if _, err := other.UnwrapDEK(wrapped, []byte("ca-test")); err == nil {
		t.Error("expected error when unwrapping with the wrong master key")
	}
}

func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zeroize(b)
	for _, v := range b {
		if v != 0 {
			t.Errorf("zeroize left %d", v)
		}
	}
}

// TestUnwrapDEK_RejectsWrongAAD pins the ca_id binding (L6, 2026-06-12
// audit): an envelope wrapped for one CA must not open under another CA's
// ID — the DB-write swap this binding exists to stop.
func TestUnwrapDEK_RejectsWrongAAD(t *testing.T) {
	m := newTestMaster(t)
	_, wrapped, err := m.GenerateDEK([]byte("ca-A"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.UnwrapDEK(wrapped, []byte("ca-B")); err == nil {
		t.Error("DEK wrapped for ca-A opened under ca-B's AAD")
	}
	if _, err := m.UnwrapDEK(wrapped, nil); err == nil {
		t.Error("DEK wrapped with AAD opened with nil AAD")
	}
	if _, err := m.UnwrapDEK(wrapped, []byte("ca-A")); err != nil {
		t.Errorf("DEK failed to open under its own AAD: %v", err)
	}
}

// TestOpenWithDEK_RejectsWrongAAD mirrors the same property for the inner
// (DEK → key material) layer.
func TestOpenWithDEK_RejectsWrongAAD(t *testing.T) {
	m := newTestMaster(t)
	dek, _, err := m.GenerateDEK([]byte("ca-A"))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealWithDEK(dek, []byte("key material"), []byte("ca-A"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithDEK(dek, blob, []byte("ca-B")); err == nil {
		t.Error("blob sealed for ca-A opened under ca-B's AAD")
	}
	if _, err := OpenWithDEK(dek, blob, nil); err == nil {
		t.Error("blob sealed with AAD opened with nil AAD")
	}
	if _, err := OpenWithDEK(dek, blob, []byte("ca-A")); err != nil {
		t.Errorf("blob failed to open under its own AAD: %v", err)
	}
}
