package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store/migrations"
)

const hostCertificateRevocationMigration = "032_revoked_host_certificates.up.sql"

// revokeHostCertificatesInTx publishes the revocation before any caller
// overwrites the host fingerprints or deletes the certificate history.
func revokeHostCertificatesInTx(ctx context.Context, tx *sql.Tx, host *models.Host, reason string) (bool, error) {
	now := time.Now()
	fingerprints, err := hostRevocationFingerprints(ctx, tx, host, now)
	if err != nil {
		return false, err
	}
	changedCAs := make(map[string]struct{})
	for fingerprint, caID := range fingerprints {
		var previousCA string
		err := tx.QueryRowContext(ctx, `SELECT ca_id FROM blocklist WHERE fingerprint = ?`, fingerprint).Scan(&previousCA)
		if err == nil {
			// A legacy server-wide entry or an entry in the issuing CA
			// already enforces revocation. An imported entry in a different
			// CA must not prevent the actual issuer from revoking this cert.
			if previousCA == "" || previousCA == caID || caID == "" {
				continue
			}
			changedCAs[previousCA] = struct{}{}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("check current certificate revocation scope: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO blocklist (fingerprint, host_id, reason, created_at, ca_id)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(fingerprint) DO UPDATE SET host_id = excluded.host_id,
				reason = excluded.reason, created_at = excluded.created_at, ca_id = excluded.ca_id`,
			fingerprint, host.ID, reason, now, caID); err != nil {
			return false, fmt.Errorf("add host certificate to blocklist: %w", err)
		}
		changedCAs[caID] = struct{}{}
	}

	for caID := range changedCAs {
		var fallbackNetworkID string
		if caID == host.CAID {
			fallbackNetworkID = host.NetworkID
		}
		if err := bumpNetworkConfigVersionsForCA(ctx, tx, caID, fallbackNetworkID); err != nil {
			return false, fmt.Errorf("bump CA network config versions: %w", err)
		}
	}
	_, hostCAChanged := changedCAs[host.CAID]
	return hostCAChanged, nil
}

func hostRevocationFingerprints(ctx context.Context, tx *sql.Tx, host *models.Host, now time.Time) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT fingerprint, ca_id, not_after FROM certificates WHERE host_id = ?`, host.ID)
	if err != nil {
		return nil, fmt.Errorf("list host certificate history: %w", err)
	}
	defer rows.Close()

	// Old databases may have a fingerprint on the host without a
	// corresponding history row. Use that fingerprint and CA as a fallback.
	fingerprints := make(map[string]string)
	if host.CertFingerprint != "" && (host.CertExpiresAt == nil || host.CertExpiresAt.After(now)) {
		fingerprints[host.CertFingerprint] = host.CAID
	}
	if host.PrevCertFingerprint != "" && host.PrevCertFingerprint != host.CertFingerprint {
		fingerprints[host.PrevCertFingerprint] = host.CAID
	}
	for rows.Next() {
		var fingerprint, caID string
		var expires time.Time
		if err := rows.Scan(&fingerprint, &caID, &expires); err != nil {
			return nil, fmt.Errorf("read host certificate history: %w", err)
		}
		if fingerprint == "" || !expires.After(now) {
			delete(fingerprints, fingerprint)
			continue
		}
		if caID == "" {
			caID = host.CAID
		}
		fingerprints[fingerprint] = caID
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read host certificate history: %w", err)
	}
	return fingerprints, nil
}

// applyHostCertificateRevocationMigration records the marker in the same
// transaction as the backfill. The first write serializes concurrent starts.
func (s *SQLiteStore) applyHostCertificateRevocationMigration(ctx context.Context, conn *sql.Conn) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin host revocation backfill: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback host revocation backfill", "error", err)
		}
	}()
	result, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(name) VALUES (?) ON CONFLICT(name) DO NOTHING`,
		hostCertificateRevocationMigration)
	if err != nil {
		return fmt.Errorf("record host revocation backfill: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check host revocation backfill marker: %w", err)
	}
	if inserted == 0 {
		return nil
	}
	indexSQL, err := migrations.FS.ReadFile(hostCertificateRevocationMigration)
	if err != nil {
		return fmt.Errorf("read host revocation migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, string(indexSQL)); err != nil {
		return fmt.Errorf("index host certificate history: %w", err)
	}
	hosts, err := s.getBlockedHostsForRevocationBackfill(ctx, tx)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if _, err := revokeHostCertificatesInTx(ctx, tx, host, "blocked host certificate backfill"); err != nil {
			return fmt.Errorf("backfill revocation for host %s: %w", host.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit host revocation backfill: %w", err)
	}
	return nil
}

func (s *SQLiteStore) getBlockedHostsForRevocationBackfill(ctx context.Context, tx *sql.Tx) ([]*models.Host, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+hostColumns+` FROM hosts WHERE status = ?`, models.HostStatusBlocked)
	if err != nil {
		return nil, fmt.Errorf("list blocked hosts for revocation backfill: %w", err)
	}
	defer rows.Close()
	var hosts []*models.Host
	for rows.Next() {
		host, err := s.scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("read blocked host for revocation backfill: %w", err)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read blocked hosts for revocation backfill: %w", err)
	}
	return hosts, nil
}
