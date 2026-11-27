package store

import (
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConsumeOIDCLoginState_SEC_REPLAY_001_PersistsAndRejectsExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login.db")
	open := func() *SQLiteStore {
		t.Helper()
		s, err := NewSQLiteStore(path, WithCredentialHasher(newTestCredentialHasher(t)))
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		require.NoError(t, s.Migrate(t.Context()))
		return s
	}
	state := sha256.Sum256([]byte("verified login"))
	expiry := time.Now().Add(time.Minute).Unix()
	s := open()
	require.NoError(t, s.ConsumeOIDCLoginState(t.Context(), state, expiry))
	require.NoError(t, s.Close())
	s = open()
	require.ErrorIs(t, s.ConsumeOIDCLoginState(t.Context(), state, expiry), ErrReplayedNonce)
	expired := sha256.Sum256([]byte("expired login"))
	require.ErrorIs(t, s.ConsumeOIDCLoginState(t.Context(), expired, time.Now().Add(-time.Minute).Unix()), ErrReplayedNonce)
}
