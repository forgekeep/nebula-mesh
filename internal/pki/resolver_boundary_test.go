package pki

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// OpenCAForTest is visible only to this package's external envelope tests.
func OpenCAForTest(ctx context.Context, r *CAResolver, id string) (*CAManager, error) {
	return r.openCA(ctx, id)
}

// SEC-SECRET-001: observe the actual owned slice after PKI operations return.
func TestResolvedCAOperationsClearOwnedKey(t *testing.T) {
	sentinel := errors.New("fixture load error")
	valid := SignRequest{Name: "fixture-host", PublicKey: make([]byte, 32), Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, Duration: time.Minute}
	for _, name := range []string{"sign", "sign-error", "verify", "verify-error"} {
		t.Run(name, func(t *testing.T) {
			manager, err := NewCA("fixture-ca", time.Hour)
			require.NoError(t, err)
			t.Cleanup(manager.Wipe)
			key := manager.RawKey()
			require.NotEqual(t, make([]byte, len(key)), []byte(key))
			loaded := loadedCA{manager: manager}
			switch name {
			case "sign":
				c, issuer, err := signWithCA(loaded, valid)
				require.NoError(t, err)
				require.Equal(t, "fixture-host", c.Name())
				require.NotEmpty(t, issuer)
			case "sign-error":
				c, issuer, err := signWithCA(loaded, SignRequest{})
				require.Error(t, err)
				require.Nil(t, c)
				require.Nil(t, issuer)
			case "verify":
				require.NoError(t, verifyLoadedCA(loaded))
			case "verify-error":
				loaded.err = sentinel
				require.ErrorIs(t, verifyLoadedCA(loaded), sentinel)
			}
			require.Equal(t, make([]byte, len(key)), []byte(key))
		})
	}
}

// SEC-SECRET-001: application callers must never obtain decrypted managers
// from the persisted CA resolver.
func TestCAResolverDoesNotExportDecryptedManager(t *testing.T) {
	resolver := reflect.TypeFor[*CAResolver]()
	manager := reflect.TypeFor[*CAManager]()
	for i := range resolver.NumMethod() {
		method := resolver.Method(i)
		for j := range method.Type.NumOut() {
			if method.Type.Out(j) == manager {
				t.Errorf("%s returns a decrypted CA manager", method.Name)
			}
		}
	}
}
