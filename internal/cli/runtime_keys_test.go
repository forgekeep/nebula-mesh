package cli

import (
	"encoding/base64"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
)

func TestLoadRuntimeKeys_SEC_CREDENTIAL_001BuildsCredentialHasher(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	encoded := base64.StdEncoding.EncodeToString(raw)

	master, hasher, err := loadRuntimeKeys(encoded)
	if err != nil {
		t.Fatalf("loadRuntimeKeys() error = %v", err)
	}
	if master == nil {
		t.Fatal("loadRuntimeKeys() master = nil")
	}
	t.Cleanup(hasher.Destroy)

	got, err := hasher.Digest(credentialhash.PurposeOperatorAPIKey, []byte("api-key"))
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	if len(got) != len("hmac-sha256-v1:")+64 {
		t.Fatalf("Digest() length = %d, want %d", len(got), len("hmac-sha256-v1:")+64)
	}
}

func TestLoadRuntimeKeys_SEC_CREDENTIAL_001RejectsInvalidMaterial(t *testing.T) {
	for _, encoded := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, _, err := loadRuntimeKeys(encoded); err == nil {
			t.Fatalf("loadRuntimeKeys(%q) error = nil, want error", encoded)
		}
	}
}
