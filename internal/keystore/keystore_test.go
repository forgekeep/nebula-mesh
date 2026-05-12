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

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	m := newTestMaster(t)
	dek, wrapped, err := m.GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != DEKSize {
		t.Fatalf("dek length = %d", len(dek))
	}
	if len(wrapped.Nonce) != NonceSize {
		t.Fatalf("nonce length = %d", len(wrapped.Nonce))
	}

	unwrapped, err := m.UnwrapDEK(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Error("dek round-trip mismatch")
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	m := newTestMaster(t)
	dek, _, err := m.GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("super-secret CA private key material")
	blob, err := SealWithDEK(dek, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob.Ciphertext, pt) {
		t.Fatal("plaintext appeared inside ciphertext")
	}
	out, err := OpenWithDEK(dek, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Error("seal/open mismatch")
	}
}

func TestOpen_RejectsTamperedCiphertext(t *testing.T) {
	m := newTestMaster(t)
	dek, _, _ := m.GenerateDEK()
	blob, _ := SealWithDEK(dek, []byte("payload"))
	blob.Ciphertext[0] ^= 0xff
	if _, err := OpenWithDEK(dek, blob); err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestUnwrapDEK_RejectsWrongMaster(t *testing.T) {
	m1 := newTestMaster(t)
	_, wrapped, _ := m1.GenerateDEK()

	other, _ := NewMaster(bytes.Repeat([]byte{0xcd}, MasterKeySize))
	if _, err := other.UnwrapDEK(wrapped); err == nil {
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
