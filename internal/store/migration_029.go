package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
)

// applyMigration029 replaces both enabled and pending plaintext TOTP seeds in
// one transaction. A failed encrypt, SQL write, or marker write rolls back all
// updates and leaves the migration available for a safe retry.
func applyMigration029(ctx context.Context, store *SQLiteStore, conn *sql.Conn, migration string) (err error) {
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("begin migration %s transaction: %w", migration, err)
	}
	defer func() {
		if err == nil {
			return
		}
		if _, rollbackErr := conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`); rollbackErr != nil {
			slog.Error("rollback migration transaction", "migration", migration, "error", rollbackErr)
		}
	}()

	applied, err := migrationApplied(ctx, conn, migration)
	if err != nil {
		return fmt.Errorf("check migration %s in transaction: %w", migration, err)
	}
	if applied {
		return commitMigration029(ctx, conn, migration)
	}

	rows, err := conn.QueryContext(ctx, `SELECT id, totp_secret FROM operators WHERE totp_secret <> ''`)
	if err != nil {
		return fmt.Errorf("list TOTP secrets for %s: %w", migration, err)
	}
	defer rows.Close()
	type existingSecret struct {
		id    string
		value []byte
	}
	var secrets []existingSecret
	defer func() {
		for _, item := range secrets {
			keystore.Zeroize(item.value)
		}
	}()
	for rows.Next() {
		var item existingSecret
		if err := rows.Scan(&item.id, &item.value); err != nil {
			return fmt.Errorf("scan TOTP secret for %s: %w", migration, err)
		}
		secrets = append(secrets, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read TOTP secrets for %s: %w", migration, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close TOTP secret rows for %s: %w", migration, err)
	}

	for _, item := range secrets {
		if bytes.HasPrefix(item.value, []byte(totpSecretPrefix)) {
			if _, err := store.openTOTPSecret(item.id, string(item.value)); err != nil {
				return fmt.Errorf("verify existing TOTP ciphertext for %s: %w", migration, err)
			}
			continue
		}
		sealed, err := store.sealTOTPSecretBytes(item.id, item.value)
		if err != nil {
			return fmt.Errorf("encrypt existing TOTP secret for %s: %w", migration, err)
		}
		if _, err := conn.ExecContext(ctx,
			`UPDATE operators SET totp_secret = ? WHERE id = ?`, sealed, item.id); err != nil {
			return fmt.Errorf("update encrypted TOTP secret for %s: %w", migration, err)
		}
	}

	for _, statement := range []string{
		`CREATE TRIGGER operator_totp_secret_insert BEFORE INSERT ON operators
			WHEN NEW.totp_secret <> '' AND NEW.totp_secret NOT LIKE 'totp-aes256gcm-v1:%'
			BEGIN SELECT RAISE(ABORT, 'SEC-TOTP-001: plaintext TOTP secret'); END`,
		`CREATE TRIGGER operator_totp_secret_update BEFORE UPDATE OF totp_secret ON operators
			WHEN NEW.totp_secret <> '' AND NEW.totp_secret NOT LIKE 'totp-aes256gcm-v1:%'
			BEGIN SELECT RAISE(ABORT, 'SEC-TOTP-001: plaintext TOTP secret'); END`,
	} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("install TOTP format trigger for %s: %w", migration, err)
		}
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations(name) VALUES (?)`, migration); err != nil {
		return fmt.Errorf("record migration %s: %w", migration, err)
	}
	return commitMigration029(ctx, conn, migration)
}

func commitMigration029(ctx context.Context, conn *sql.Conn, migration string) error {
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit migration %s transaction: %w", migration, err)
	}
	return nil
}

func (s *SQLiteStore) validateTOTPSecrets(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, `SELECT id, totp_secret FROM operators WHERE totp_secret <> ''`)
	if err != nil {
		return fmt.Errorf("list encrypted TOTP secrets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var operatorID, sealed string
		if err := rows.Scan(&operatorID, &sealed); err != nil {
			return fmt.Errorf("scan encrypted TOTP secret: %w", err)
		}
		if _, err := s.openTOTPSecret(operatorID, sealed); err != nil {
			return fmt.Errorf("operator %q: %w", operatorID, err)
		}
	}
	return rows.Err()
}
