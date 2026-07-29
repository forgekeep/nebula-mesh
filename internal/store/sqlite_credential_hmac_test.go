package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
)

func TestSQLiteStore_SEC_CREDENTIAL_001_RejectsRawCredentialOperationsWithoutLiveHasher(t *testing.T) {
	ctx := context.Background()
	withoutHasher, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = withoutHasher.Close() })
	if err := withoutHasher.CreateTokenForHost(ctx, "host", "raw-token", time.Now().Add(time.Hour)); !errors.Is(err, ErrCredentialHasherUnavailable) {
		t.Fatalf("CreateTokenForHost() error = %v, want ErrCredentialHasherUnavailable", err)
	}

	hasher, err := credentialhash.New([]byte("store-test-master"))
	if err != nil {
		t.Fatalf("credentialhash.New() error = %v", err)
	}
	withDestroyedHasher, err := NewSQLiteStore(":memory:", WithCredentialHasher(hasher))
	if err != nil {
		t.Fatalf("NewSQLiteStore() with hasher error = %v", err)
	}
	t.Cleanup(func() { _ = withDestroyedHasher.Close() })
	hasher.Destroy()
	if _, err := withDestroyedHasher.GetEnrollmentToken(ctx, "raw-token"); !errors.Is(err, ErrCredentialHasherUnavailable) {
		t.Fatalf("GetEnrollmentToken() after Destroy error = %v, want ErrCredentialHasherUnavailable", err)
	}
}
