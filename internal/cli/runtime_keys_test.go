package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
	"github.com/forgekeep/nebula-mesh/internal/pki"
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

func TestCredentialCutoverMasterGuard_SEC_SECRET_001WipesLoadedCAManager(t *testing.T) {
	goodManager, err := pki.NewCA("cutover-guard-success", time.Hour)
	require.NoError(t, err)
	goodKey := goodManager.RawKey()
	err = loadAndWipeCA(context.Background(), "good-ca", func(context.Context, string) (*pki.CAManager, error) {
		return goodManager, nil
	})
	require.NoError(t, err)
	assertZeroized(t, goodKey)

	manager, err := pki.NewCA("cutover-guard", time.Hour)
	require.NoError(t, err)
	t.Cleanup(manager.Wipe)

	key := manager.RawKey()
	loadErr := errors.New("load failed after allocating manager")
	err = loadAndWipeCA(context.Background(), "ca-id", func(context.Context, string) (*pki.CAManager, error) {
		return manager, loadErr
	})
	require.ErrorIs(t, err, loadErr)
	assertZeroized(t, key)
}

func assertZeroized(t *testing.T, b []byte) {
	t.Helper()
	for i, value := range b {
		if value != 0 {
			t.Fatalf("secret byte %d = %d, want zero", i, value)
		}
	}
}
