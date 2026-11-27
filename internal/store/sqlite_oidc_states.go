package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// ConsumeOIDCLoginState accepts a verified login proof at most once until its expiry.
func (s *SQLiteStore) ConsumeOIDCLoginState(ctx context.Context, digest [32]byte, expiresAt int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin consume OIDC state: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback OIDC state", "error", err)
		}
	}()

	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_login_states WHERE expires_at <= unixepoch()`); err != nil {
		return fmt.Errorf("prune OIDC states: %w", err)
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO oidc_login_states (digest, expires_at)
		 SELECT ?, ? WHERE ? > unixepoch() ON CONFLICT(digest) DO NOTHING`,
		digest[:], expiresAt, expiresAt)
	if err != nil {
		return fmt.Errorf("insert consumed OIDC state: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count consumed OIDC states: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit consumed OIDC state: %w", err)
	}
	if n == 0 {
		return ErrReplayedNonce
	}
	return nil
}
