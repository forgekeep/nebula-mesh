package credentialhash

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"
)

func TestDigest_SEC_CREDENTIAL_001_IsStableAndCanonical(t *testing.T) {
	hasher, err := New([]byte("master-key-one"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	first, err := hasher.Digest(PurposeOperatorAPIKey, []byte("credential"))
	if err != nil {
		t.Fatalf("first Digest() error = %v", err)
	}
	second, err := hasher.Digest(PurposeOperatorAPIKey, []byte("credential"))
	if err != nil {
		t.Fatalf("second Digest() error = %v", err)
	}
	if first != second {
		t.Fatalf("Digest() results differ: %q != %q", first, second)
	}

	const prefix = "hmac-sha256-v1:"
	if !strings.HasPrefix(first, prefix) {
		t.Fatalf("Digest() = %q, want prefix %q", first, prefix)
	}
	encoded := strings.TrimPrefix(first, prefix)
	if len(encoded) != 64 {
		t.Fatalf("digest hex length = %d, want 64", len(encoded))
	}
	if strings.ToLower(encoded) != encoded {
		t.Fatalf("digest hex = %q, want lowercase", encoded)
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		t.Fatalf("digest hex = %q, want valid hexadecimal: %v", encoded, err)
	}
}

func TestPurpose_SEC_CREDENTIAL_001_HasFixedValues(t *testing.T) {
	for _, test := range []struct {
		purpose Purpose
		want    string
	}{
		{PurposeOperatorAPIKey, "operator-api-key"},
		{PurposeOperatorSession, "operator-session"},
		{PurposeEnrollmentToken, "enrollment-token"},
		{PurposeMeshImportToken, "mesh-import-token"},
		{PurposeTOTPRecoveryCode, "totp-recovery-code"},
	} {
		if string(test.purpose) != test.want {
			t.Errorf("purpose = %q, want %q", test.purpose, test.want)
		}
	}
}

func TestDigest_SEC_CREDENTIAL_001_SeparatesMasterAndPurpose(t *testing.T) {
	first, err := New([]byte("master-key-one"))
	if err != nil {
		t.Fatalf("first New() error = %v", err)
	}
	second, err := New([]byte("master-key-two"))
	if err != nil {
		t.Fatalf("second New() error = %v", err)
	}

	firstDigest, err := first.Digest(PurposeOperatorAPIKey, []byte("credential"))
	if err != nil {
		t.Fatalf("first Digest() error = %v", err)
	}
	secondDigest, err := second.Digest(PurposeOperatorAPIKey, []byte("credential"))
	if err != nil {
		t.Fatalf("second Digest() error = %v", err)
	}
	otherPurpose, err := first.Digest(PurposeOperatorSession, []byte("credential"))
	if err != nil {
		t.Fatalf("other-purpose Digest() error = %v", err)
	}
	if firstDigest == secondDigest {
		t.Fatal("different master keys produced the same digest")
	}
	if firstDigest == otherPurpose {
		t.Fatal("different purposes produced the same digest")
	}
}

func TestDigest_SEC_CREDENTIAL_001_RejectsInvalidInput(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) error = nil, want error")
	}

	hasher, err := New([]byte("master-key"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := hasher.Digest(Purpose("invalid"), []byte("credential")); err == nil {
		t.Fatal("Digest() invalid purpose error = nil, want error")
	}
	if _, err := hasher.Digest(PurposeOperatorAPIKey, nil); err == nil {
		t.Fatal("Digest() empty raw error = nil, want error")
	}
}

func TestDigest_SEC_CREDENTIAL_001_CopiesCallerMasterBuffer(t *testing.T) {
	master := []byte("master-key")
	hasher, err := New(master)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want, err := hasher.Digest(PurposeEnrollmentToken, []byte("credential"))
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	clear(master)
	got, err := hasher.Digest(PurposeEnrollmentToken, []byte("credential"))
	if err != nil {
		t.Fatalf("Digest() after caller mutation error = %v", err)
	}
	if got != want {
		t.Fatalf("Digest() after caller mutation = %q, want %q", got, want)
	}
}

func TestDigest_SEC_CREDENTIAL_001_DestroyDisablesDigest(t *testing.T) {
	hasher, err := New([]byte("master-key"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rootKey := hasher.rootKey
	hasher.Destroy()
	for index, value := range rootKey {
		if value != 0 {
			t.Fatalf("root key byte %d = %d after Destroy(), want 0", index, value)
		}
	}
	if _, err := hasher.Digest(PurposeMeshImportToken, []byte("credential")); err == nil {
		t.Fatal("Digest() after Destroy() error = nil, want error")
	}
}

func TestDigest_SEC_CREDENTIAL_001_DigestAndDestroyAreRaceFree(t *testing.T) {
	hasher, err := New([]byte("master-key"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_, _ = hasher.Digest(PurposeTOTPRecoveryCode, []byte("credential"))
		})
	}
	wg.Go(hasher.Destroy)
	wg.Wait()
	if _, err := hasher.Digest(PurposeTOTPRecoveryCode, []byte("credential")); err == nil {
		t.Fatal("Digest() after concurrent Destroy() error = nil, want error")
	}
}
