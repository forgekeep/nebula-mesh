package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// AddPopNonce records a (hostID, nonce) pair valid until expiresAt. Returns
// nil when the row was freshly inserted (or replaced an expired duplicate),
// and ErrReplayedNonce when a live duplicate exists. GHSA-v2jf-442r-6mjh.
//
// The lazy DELETE prune clears any past-expiry rows; the subsequent
// INSERT OR IGNORE either lands fresh (RowsAffected == 1) or is swallowed
// by the (host_id, nonce) UNIQUE constraint (RowsAffected == 0 → replay).
// Both statements run inside a single transaction so the writer lock is
// acquired once per call instead of twice — matching the DELETE+INSERT
// shape used elsewhere in this package (e.g. CreateTokenForHost).
// SQLite's single-writer model linearizes concurrent same-key calls.
// expires_at is stored as unix-epoch INTEGER, so sub-second RFC3339
// precision truncates down — harmless inside the ±5m skew that gates this
// call upstream.
func (s *SQLiteStore) AddPopNonce(ctx context.Context, hostID, nonce string, expiresAt time.Time) error {
	now := time.Now().Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pop_nonces WHERE expires_at < ?`, now,
	); err != nil {
		return fmt.Errorf("prune pop_nonces: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO pop_nonces (host_id, nonce, expires_at) VALUES (?, ?, ?)`,
		hostID, nonce, expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("insert pop_nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("pop_nonce rows affected: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit add pop_nonce: %w", err)
	}

	if n == 0 {
		return ErrReplayedNonce
	}
	return nil
}
