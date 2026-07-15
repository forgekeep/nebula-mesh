package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

const meshImportColumns = `id, network_id, ca_id, owner_operator_id, ca_fingerprint,
	status, expected_hosts, revision, token_hash, token_expires_at,
	captured_network_config_version, terminal_reason, created_at, updated_at,
	finalized_at, canceled_at`

const (
	maxActiveMeshImportChallengesPerFingerprint = 2
	maxActiveMeshImportChallengesPerSession     = 4096
)

func scanMeshImport(scanner interface{ Scan(...any) error }) (*models.MeshImport, error) {
	var item models.MeshImport
	var expected sql.NullInt64
	var finalizedAt, canceledAt sql.NullTime
	if err := scanner.Scan(
		&item.ID, &item.NetworkID, &item.CAID, &item.OwnerOperatorID, &item.CAFingerprint,
		&item.Status, &expected, &item.Revision, &item.TokenHash, &item.TokenExpiresAt,
		&item.CapturedNetworkConfigVersion, &item.TerminalReason, &item.CreatedAt, &item.UpdatedAt,
		&finalizedAt, &canceledAt,
	); err != nil {
		return nil, err
	}
	if expected.Valid {
		value := int(expected.Int64)
		item.ExpectedHosts = &value
	}
	if finalizedAt.Valid {
		item.FinalizedAt = &finalizedAt.Time
	}
	if canceledAt.Valid {
		item.CanceledAt = &canceledAt.Time
	}
	return &item, nil
}

func (s *SQLiteStore) CreateMeshImport(ctx context.Context, item *models.MeshImport) error {
	if item == nil || item.ID == "" || item.NetworkID == "" || item.CAID == "" || item.OwnerOperatorID == "" || item.TokenHash == "" {
		return errors.New("mesh import id, network, CA, owner and token hash are required")
	}
	if item.Status == "" {
		item.Status = models.MeshImportStatusCollecting
	}
	if item.Status != models.MeshImportStatusCollecting {
		return errors.New("new mesh import must be collecting")
	}
	if item.ExpectedHosts != nil && *item.ExpectedHosts <= 0 {
		return errors.New("expected hosts must be positive")
	}
	now := time.Now()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = item.CreatedAt
	}

	result, err := s.db.ExecContext(ctx, `
		INSERT INTO mesh_imports (`+meshImportColumns+`)
		SELECT ?, n.id, c.id, ?, c.fingerprint, ?, ?, 0, ?, ?, n.config_version, '', ?, ?, NULL, NULL
		FROM networks n
		JOIN cas c ON c.id = n.ca_id
		WHERE n.id = ? AND c.id = ? AND c.status = ?
		  AND NOT EXISTS (SELECT 1 FROM hosts h WHERE h.network_id = n.id)
		  AND NOT EXISTS (SELECT 1 FROM blocklist b WHERE b.ca_id = c.id)
		  AND NOT EXISTS (SELECT 1 FROM networks other WHERE other.ca_id = c.id AND other.id <> n.id)
		  AND NOT EXISTS (SELECT 1 FROM cas successor WHERE successor.predecessor_id = c.id AND successor.status = ?)
		  AND NOT EXISTS (SELECT 1 FROM mesh_imports mi WHERE mi.network_id = n.id AND mi.status = ?)`,
		item.ID, item.OwnerOperatorID, item.Status, item.ExpectedHosts, item.TokenHash,
		item.TokenExpiresAt, item.CreatedAt, item.UpdatedAt,
		item.NetworkID, item.CAID, models.CAStatusActive,
		models.CAStatusActive, models.MeshImportStatusCollecting,
	)
	if err != nil {
		if isSQLiteConstraint(err) {
			return fmt.Errorf("create mesh import: %w", ErrDuplicateEntry)
		}
		return fmt.Errorf("create mesh import: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("create mesh import rows: %w", err)
	}
	if rows == 0 {
		var collecting int
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1 FROM mesh_imports WHERE network_id = ? AND status = ?
		)`, item.NetworkID, models.MeshImportStatusCollecting).Scan(&collecting); err != nil {
			return fmt.Errorf("check collecting mesh import: %w", err)
		}
		if collecting != 0 {
			return ErrMeshImportInProgress
		}
		return ErrMeshImportScopeInvalid
	}
	stored, err := s.GetMeshImport(ctx, item.ID)
	if err != nil {
		return err
	}
	*item = *stored
	return nil
}

func (s *SQLiteStore) GetMeshImport(ctx context.Context, id string) (*models.MeshImport, error) {
	item, err := scanMeshImport(s.db.QueryRowContext(ctx, `SELECT `+meshImportColumns+` FROM mesh_imports WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mesh import: %w", err)
	}
	return item, nil
}

func (s *SQLiteStore) GetMeshImportByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*models.MeshImport, error) {
	item, err := scanMeshImport(s.db.QueryRowContext(ctx, `SELECT `+meshImportColumns+` FROM mesh_imports WHERE token_hash = ?`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mesh import by token hash: %w", err)
	}
	if item.Status != models.MeshImportStatusCollecting {
		return nil, ErrMeshImportNotCollecting
	}
	if !now.Before(item.TokenExpiresAt) {
		return nil, ErrMeshImportTokenExpired
	}
	return item, nil
}

func (s *SQLiteStore) ListMeshImportsByOwner(ctx context.Context, ownerID string) ([]*models.MeshImport, error) {
	return s.queryMeshImports(ctx, `WHERE owner_operator_id = ?`, ownerID)
}

func (s *SQLiteStore) ListMeshImports(ctx context.Context) ([]*models.MeshImport, error) {
	return s.queryMeshImports(ctx, "")
}

func (s *SQLiteStore) queryMeshImports(ctx context.Context, where string, args ...any) ([]*models.MeshImport, error) {
	// #nosec G202 -- columns and WHERE fragments are internal constants; values remain bound parameters.
	rows, err := s.db.QueryContext(ctx, `SELECT `+meshImportColumns+` FROM mesh_imports `+where+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list mesh imports: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close mesh import rows", "error", err)
		}
	}()
	items := make([]*models.MeshImport, 0)
	for rows.Next() {
		item, err := scanMeshImport(rows)
		if err != nil {
			return nil, fmt.Errorf("scan mesh import: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) RotateMeshImportToken(ctx context.Context, id, tokenHash string, expiresAt, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rotate mesh import token: %w", err)
	}
	defer rollbackLog(tx)

	result, err := tx.ExecContext(ctx, `UPDATE mesh_imports
		SET token_hash = ?, token_expires_at = ?, updated_at = ?
		WHERE id = ? AND status = ?`,
		tokenHash, expiresAt, now, id, models.MeshImportStatusCollecting)
	if err != nil {
		return fmt.Errorf("rotate mesh import token: %w", err)
	}
	if err := meshImportCollectingRows(ctx, tx, result, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mesh_import_challenges WHERE mesh_import_id = ?`, id); err != nil {
		return fmt.Errorf("delete challenges for rotated mesh import token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit mesh import token rotation: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CancelMeshImport(ctx context.Context, id, reason string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cancel mesh import: %w", err)
	}
	defer rollbackLog(tx)

	result, err := tx.ExecContext(ctx, `UPDATE mesh_imports
		SET status = ?, terminal_reason = ?, canceled_at = ?, updated_at = ?
		WHERE id = ? AND status = ?`,
		models.MeshImportStatusCanceled, reason, now, now, id, models.MeshImportStatusCollecting)
	if err != nil {
		return fmt.Errorf("mark mesh import canceled: %w", err)
	}
	if err := meshImportCollectingRows(ctx, tx, result, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO mesh_import_tombstones (
			certificate_fingerprint, former_host_id, mesh_import_id,
			agent_signing_pub_pem, terminal_reason, created_at, updated_at)
		SELECT snap.certificate_fingerprint, snap.host_id, snap.mesh_import_id,
		       snap.agent_signing_pub_pem, ?, ?, ?
		FROM mesh_import_snapshots snap
		JOIN hosts h ON h.id = snap.host_id
		WHERE snap.mesh_import_id = ? AND h.status = ?
		ON CONFLICT(certificate_fingerprint) DO UPDATE SET
			former_host_id = excluded.former_host_id,
			mesh_import_id = excluded.mesh_import_id,
			agent_signing_pub_pem = excluded.agent_signing_pub_pem,
			terminal_reason = excluded.terminal_reason,
			updated_at = excluded.updated_at`,
		reason, now, now, id, models.HostStatusImporting); err != nil {
		return fmt.Errorf("create mesh import tombstones: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM hosts
		WHERE status = ? AND id IN (
			SELECT host_id FROM mesh_import_snapshots WHERE mesh_import_id = ?
		)`, models.HostStatusImporting, id); err != nil {
		return fmt.Errorf("delete importing hosts: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mesh_import_challenges WHERE mesh_import_id = ?`, id); err != nil {
		return fmt.Errorf("delete mesh import challenges: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cancel mesh import: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CreateMeshImportChallenge(ctx context.Context, challenge *models.MeshImportChallenge, now time.Time) error {
	if challenge == nil || challenge.ID == "" || challenge.MeshImportID == "" ||
		challenge.TokenHash == "" || challenge.CertificateFingerprint == "" || challenge.AgentSigningPubPEM == "" ||
		challenge.PayloadHash == "" || challenge.ServerNonce == "" {
		return errors.New("complete mesh import challenge is required")
	}
	if !now.Before(challenge.ExpiresAt) {
		return ErrMeshImportChallengeExpired
	}
	if challenge.CreatedAt.IsZero() {
		challenge.CreatedAt = now
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin mesh import challenge: %w", err)
	}
	defer rollbackLog(tx)

	locked, err := tx.ExecContext(ctx, `UPDATE mesh_imports SET revision = revision
		WHERE id = ? AND status = ?`, challenge.MeshImportID, models.MeshImportStatusCollecting)
	if err != nil {
		return fmt.Errorf("lock mesh import challenge session: %w", err)
	}
	rows, err := locked.RowsAffected()
	if err != nil {
		return fmt.Errorf("lock mesh import challenge session rows: %w", err)
	}
	if rows != 1 {
		return ErrMeshImportNotCollecting
	}

	var expected sql.NullInt64
	var currentTokenHash string
	if err := tx.QueryRowContext(ctx, `SELECT expected_hosts, token_hash FROM mesh_imports WHERE id = ?`, challenge.MeshImportID).Scan(&expected, &currentTokenHash); err != nil {
		return fmt.Errorf("load mesh import challenge capacity: %w", err)
	}
	if currentTokenHash != challenge.TokenHash {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mesh_import_challenges
		WHERE mesh_import_id = ? AND (consumed_at IS NOT NULL OR expires_at <= ?)`, challenge.MeshImportID, now); err != nil {
		return fmt.Errorf("prune mesh import challenges: %w", err)
	}

	var fingerprintActive int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mesh_import_challenges
		WHERE mesh_import_id = ? AND certificate_fingerprint = ?
		AND consumed_at IS NULL AND expires_at > ?`,
		challenge.MeshImportID, challenge.CertificateFingerprint, now).Scan(&fingerprintActive); err != nil {
		return fmt.Errorf("count mesh import fingerprint challenges: %w", err)
	}
	if fingerprintActive >= maxActiveMeshImportChallengesPerFingerprint {
		return ErrMeshImportChallengeLimit
	}

	var sessionActive int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mesh_import_challenges
		WHERE mesh_import_id = ? AND consumed_at IS NULL AND expires_at > ?`,
		challenge.MeshImportID, now).Scan(&sessionActive); err != nil {
		return fmt.Errorf("count mesh import session challenges: %w", err)
	}
	if sessionActive >= meshImportChallengeSessionLimit(expected) {
		return ErrMeshImportChallengeLimit
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO mesh_import_challenges (
		id, mesh_import_id, certificate_fingerprint, agent_signing_pub_pem,
		payload_hash, server_nonce, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		challenge.ID, challenge.MeshImportID, challenge.CertificateFingerprint,
		challenge.AgentSigningPubPEM, challenge.PayloadHash, challenge.ServerNonce,
		challenge.ExpiresAt, challenge.CreatedAt); err != nil {
		return fmt.Errorf("create mesh import challenge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit mesh import challenge: %w", err)
	}
	return nil
}

func meshImportChallengeSessionLimit(expected sql.NullInt64) int {
	if !expected.Valid || expected.Int64 > int64(maxActiveMeshImportChallengesPerSession/2) {
		return maxActiveMeshImportChallengesPerSession
	}
	return int(expected.Int64 * maxActiveMeshImportChallengesPerFingerprint)
}

func (s *SQLiteStore) GetMeshImportChallenge(ctx context.Context, id string) (*models.MeshImportChallenge, error) {
	var item models.MeshImportChallenge
	var consumedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id, mesh_import_id, certificate_fingerprint,
		agent_signing_pub_pem, payload_hash, server_nonce, expires_at, consumed_at, created_at
		FROM mesh_import_challenges WHERE id = ?`, id).Scan(
		&item.ID, &item.MeshImportID, &item.CertificateFingerprint,
		&item.AgentSigningPubPEM, &item.PayloadHash, &item.ServerNonce,
		&item.ExpiresAt, &consumedAt, &item.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mesh import challenge: %w", err)
	}
	if consumedAt.Valid {
		item.ConsumedAt = &consumedAt.Time
	}
	return &item, nil
}

func (s *SQLiteStore) RegisterImportedHost(ctx context.Context, registration *models.MeshImportRegistration, now time.Time) (*models.MeshImportRegistrationResult, error) {
	if err := validateMeshImportRegistration(registration); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin imported host registration: %w", err)
	}
	defer rollbackLog(tx)

	consume, err := tx.ExecContext(ctx, `UPDATE mesh_import_challenges
		SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL`, now, registration.ChallengeID)
	if err != nil {
		return nil, fmt.Errorf("consume mesh import challenge: %w", err)
	}
	consumed, err := consume.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("consume challenge rows: %w", err)
	}
	if consumed == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mesh_import_challenges WHERE id = ?`, registration.ChallengeID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check mesh import challenge: %w", err)
		}
		if exists == 0 {
			return nil, ErrNotFound
		}
		return nil, ErrMeshImportChallengeUsed
	}

	var challenge models.MeshImportChallenge
	var consumedAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT id, mesh_import_id, certificate_fingerprint,
		agent_signing_pub_pem, payload_hash, server_nonce, expires_at, consumed_at, created_at
		FROM mesh_import_challenges WHERE id = ?`, registration.ChallengeID).Scan(
		&challenge.ID, &challenge.MeshImportID, &challenge.CertificateFingerprint,
		&challenge.AgentSigningPubPEM, &challenge.PayloadHash, &challenge.ServerNonce,
		&challenge.ExpiresAt, &consumedAt, &challenge.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("load mesh import challenge: %w", err)
	}
	if !now.Before(challenge.ExpiresAt) {
		return nil, ErrMeshImportChallengeExpired
	}
	if challenge.MeshImportID != registration.Snapshot.MeshImportID ||
		challenge.CertificateFingerprint != registration.Snapshot.CertificateFingerprint ||
		challenge.AgentSigningPubPEM != registration.Snapshot.AgentSigningPubPEM ||
		challenge.PayloadHash != registration.Snapshot.PayloadHash {
		return nil, ErrMeshImportChallengeMismatch
	}

	var networkID, caID string
	var status models.MeshImportStatus
	var expected sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT network_id, ca_id, status, expected_hosts
		FROM mesh_imports WHERE id = ?`, challenge.MeshImportID).Scan(&networkID, &caID, &status, &expected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load mesh import for registration: %w", err)
	}
	if status != models.MeshImportStatusCollecting {
		return nil, ErrMeshImportNotCollecting
	}
	if registration.Host.NetworkID != networkID || registration.Host.CAID != caID ||
		registration.Host.Status != models.HostStatusImporting ||
		registration.Host.CertFingerprint != challenge.CertificateFingerprint ||
		registration.Host.SigningPubPEM != challenge.AgentSigningPubPEM ||
		registration.Snapshot.HostID != registration.Host.ID ||
		registration.Profile.HostID != registration.Host.ID ||
		registration.Profile.MeshImportID != challenge.MeshImportID {
		return nil, ErrMeshImportScopeInvalid
	}

	var existing models.MeshImportSnapshot
	err = tx.QueryRowContext(ctx, `SELECT id, mesh_import_id, host_id,
		certificate_fingerprint, certificate_pem, agent_signing_pub_pem,
		payload_hash, snapshot_json, created_at, updated_at
		FROM mesh_import_snapshots WHERE certificate_fingerprint = ?`, challenge.CertificateFingerprint).
		Scan(&existing.ID, &existing.MeshImportID, &existing.HostID,
			&existing.CertificateFingerprint, &existing.CertificatePEM, &existing.AgentSigningPubPEM,
			&existing.PayloadHash, &existing.SnapshotJSON, &existing.CreatedAt, &existing.UpdatedAt)
	if err == nil {
		if existing.MeshImportID != challenge.MeshImportID {
			return nil, ErrDuplicateEntry
		}
		if existing.AgentSigningPubPEM != challenge.AgentSigningPubPEM {
			return nil, ErrMeshImportSigningKeyConflict
		}
		if existing.PayloadHash != challenge.PayloadHash {
			return nil, ErrMeshImportPayloadConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit idempotent imported host registration: %w", err)
		}
		host, err := s.GetHost(ctx, existing.HostID)
		if err != nil {
			return nil, err
		}
		return &models.MeshImportRegistrationResult{Host: host, Snapshot: &existing, Created: false}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("find imported certificate fingerprint: %w", err)
	}

	var tombstoneKey string
	err = tx.QueryRowContext(ctx, `SELECT agent_signing_pub_pem FROM mesh_import_tombstones
		WHERE certificate_fingerprint = ?`, challenge.CertificateFingerprint).Scan(&tombstoneKey)
	if err == nil && tombstoneKey != challenge.AgentSigningPubPEM {
		return nil, ErrMeshImportSigningKeyConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("load mesh import tombstone: %w", err)
	}
	if expected.Valid {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mesh_import_snapshots WHERE mesh_import_id = ?`, challenge.MeshImportID).Scan(&count); err != nil {
			return nil, fmt.Errorf("count mesh import hosts: %w", err)
		}
		if count >= expected.Int64 {
			return nil, ErrMeshImportExpectedHostsReached
		}
	}

	if err := insertImportedHost(ctx, tx, registration.Host); err != nil {
		return nil, err
	}
	if err := s.setHostAddresses(ctx, tx, registration.Host.ID, networkID, registration.Host.NebulaIPs); err != nil {
		return nil, err
	}
	if err := s.saveCertificateInTx(ctx, tx, registration.Host.ID, challenge.CertificateFingerprint,
		[]byte(registration.Snapshot.CertificatePEM), registration.CertificateNotBefore, registration.CertificateNotAfter); err != nil {
		return nil, err
	}
	snapshot := registration.Snapshot
	if _, err := tx.ExecContext(ctx, `INSERT INTO mesh_import_snapshots (
		id, mesh_import_id, host_id, certificate_fingerprint, certificate_pem,
		agent_signing_pub_pem, payload_hash, snapshot_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snapshot.ID, snapshot.MeshImportID, snapshot.HostID, snapshot.CertificateFingerprint,
		snapshot.CertificatePEM, snapshot.AgentSigningPubPEM, snapshot.PayloadHash,
		snapshot.SnapshotJSON, snapshot.CreatedAt, snapshot.UpdatedAt); err != nil {
		return nil, fmt.Errorf("insert mesh import snapshot: %w", err)
	}
	profile := registration.Profile
	if _, err := tx.ExecContext(ctx, `INSERT INTO host_agent_profiles (
		host_id, mesh_import_id, nebula_config_path, nebula_ca_path, nebula_cert_path,
		nebula_key_path, config_ack_v1, pending_config_version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		profile.HostID, profile.MeshImportID, profile.NebulaConfigPath, profile.NebulaCAPath,
		profile.NebulaCertPath, profile.NebulaKeyPath, profile.ConfigAckV1,
		profile.PendingConfigVersion, profile.CreatedAt, profile.UpdatedAt); err != nil {
		return nil, fmt.Errorf("insert host agent profile: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mesh_import_tombstones WHERE certificate_fingerprint = ?`, challenge.CertificateFingerprint); err != nil {
		return nil, fmt.Errorf("clear mesh import tombstone: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mesh_imports SET revision = revision + 1, updated_at = ?
		WHERE id = ? AND status = ?`, now, challenge.MeshImportID, models.MeshImportStatusCollecting); err != nil {
		return nil, fmt.Errorf("increment mesh import revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit imported host registration: %w", err)
	}
	return &models.MeshImportRegistrationResult{Host: registration.Host, Snapshot: snapshot, Created: true}, nil
}

func (s *SQLiteStore) ListMeshImportSnapshots(ctx context.Context, meshImportID string) ([]*models.MeshImportSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, mesh_import_id, host_id,
		certificate_fingerprint, certificate_pem, agent_signing_pub_pem,
		payload_hash, snapshot_json, created_at, updated_at
		FROM mesh_import_snapshots WHERE mesh_import_id = ? ORDER BY host_id`, meshImportID)
	if err != nil {
		return nil, fmt.Errorf("list mesh import snapshots: %w", err)
	}
	defer rows.Close()
	items := make([]*models.MeshImportSnapshot, 0)
	for rows.Next() {
		var item models.MeshImportSnapshot
		if err := rows.Scan(&item.ID, &item.MeshImportID, &item.HostID,
			&item.CertificateFingerprint, &item.CertificatePEM, &item.AgentSigningPubPEM,
			&item.PayloadHash, &item.SnapshotJSON, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan mesh import snapshot: %w", err)
		}
		items = append(items, &item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) FinalizeMeshImport(ctx context.Context, input MeshImportFinalizeInput) error {
	if input.ID == "" || input.Revision < 0 || len(input.Hosts) == 0 || !json.Valid([]byte(input.FirewallJSON)) {
		return ErrMeshImportConflict
	}
	if input.Now.IsZero() {
		input.Now = time.Now()
	}
	for _, fingerprint := range input.Blocklist {
		decoded, err := hex.DecodeString(strings.TrimSpace(fingerprint))
		if err != nil || len(decoded) != 32 {
			return ErrMeshImportConflict
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin finalize mesh import: %w", err)
	}
	defer rollbackLog(tx)

	// Take the SQLite write lock before reading the CAS scope. Registration
	// cannot commit a newly arriving host between these checks and commit.
	locked, err := tx.ExecContext(ctx, `UPDATE mesh_imports SET updated_at = updated_at
		WHERE id = ? AND status = ? AND revision = ?`, input.ID, models.MeshImportStatusCollecting, input.Revision)
	if err != nil {
		return fmt.Errorf("lock mesh import finalize: %w", err)
	}
	if rows, err := locked.RowsAffected(); err != nil {
		return fmt.Errorf("lock mesh import finalize rows: %w", err)
	} else if rows != 1 {
		return ErrMeshImportConflict
	}

	var networkID, caID, capturedFingerprint string
	var capturedVersion int
	var expected sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT network_id, ca_id, ca_fingerprint,
		captured_network_config_version, expected_hosts FROM mesh_imports WHERE id = ?`, input.ID).
		Scan(&networkID, &caID, &capturedFingerprint, &capturedVersion, &expected); err != nil {
		return fmt.Errorf("load mesh import finalize scope: %w", err)
	}

	var currentCAID string
	var currentVersion int
	if err := tx.QueryRowContext(ctx, `SELECT ca_id, config_version FROM networks WHERE id = ?`, networkID).
		Scan(&currentCAID, &currentVersion); err != nil {
		return ErrMeshImportConflict
	}
	var currentFingerprint string
	var caStatus models.CAStatus
	if err := tx.QueryRowContext(ctx, `SELECT fingerprint, status FROM cas WHERE id = ?`, caID).
		Scan(&currentFingerprint, &caStatus); err != nil {
		return ErrMeshImportConflict
	}
	var snapshots, networkHosts, importingHosts, networksForCA, successors, existingBlocklist int
	checks := []struct {
		query string
		args  []any
		dest  *int
	}{
		{`SELECT COUNT(*) FROM mesh_import_snapshots WHERE mesh_import_id = ?`, []any{input.ID}, &snapshots},
		{`SELECT COUNT(*) FROM hosts WHERE network_id = ?`, []any{networkID}, &networkHosts},
		{`SELECT COUNT(*) FROM hosts h JOIN mesh_import_snapshots s ON s.host_id = h.id
			WHERE s.mesh_import_id = ? AND h.network_id = ? AND h.status = ?`, []any{input.ID, networkID, models.HostStatusImporting}, &importingHosts},
		{`SELECT COUNT(*) FROM networks WHERE ca_id = ?`, []any{caID}, &networksForCA},
		{`SELECT COUNT(*) FROM cas WHERE predecessor_id = ?`, []any{caID}, &successors},
		{`SELECT COUNT(*) FROM blocklist WHERE ca_id = ?`, []any{caID}, &existingBlocklist},
	}
	for _, check := range checks {
		if err := tx.QueryRowContext(ctx, check.query, check.args...).Scan(check.dest); err != nil {
			return fmt.Errorf("check mesh import finalize scope: %w", err)
		}
	}
	if currentCAID != caID || currentVersion != capturedVersion || currentFingerprint != capturedFingerprint ||
		caStatus != models.CAStatusActive || networksForCA != 1 || successors != 0 || existingBlocklist != 0 ||
		snapshots != len(input.Hosts) || networkHosts != snapshots || importingHosts != snapshots ||
		(expected.Valid && expected.Int64 != int64(snapshots)) {
		return ErrMeshImportConflict
	}

	seenSnapshots := make(map[string]struct{}, len(input.Hosts))
	seenHosts := make(map[string]struct{}, len(input.Hosts))
	for _, proposal := range input.Hosts {
		host := proposal.Host
		if proposal.SnapshotID == "" || host.ID == "" || host.NetworkID != networkID || host.CAID != caID ||
			host.Status != models.HostStatusImporting || !models.ValidRole(host.Role) ||
			models.ValidateRoleReachability(host.Role, host.PublicIP, host.ListenPort) != nil ||
			models.ValidateHostAdvanced(host.Advanced) != nil {
			return ErrMeshImportConflict
		}
		if _, duplicate := seenSnapshots[proposal.SnapshotID]; duplicate {
			return ErrMeshImportConflict
		}
		if _, duplicate := seenHosts[host.ID]; duplicate {
			return ErrMeshImportConflict
		}
		seenSnapshots[proposal.SnapshotID] = struct{}{}
		seenHosts[host.ID] = struct{}{}
		var storedHostID string
		if err := tx.QueryRowContext(ctx, `SELECT host_id FROM mesh_import_snapshots WHERE id = ? AND mesh_import_id = ?`, proposal.SnapshotID, input.ID).
			Scan(&storedHostID); err != nil || storedHostID != host.ID {
			return ErrMeshImportConflict
		}
	}

	for _, fingerprint := range input.Blocklist {
		if _, err := tx.ExecContext(ctx, `INSERT INTO blocklist (fingerprint, host_id, reason, created_at, ca_id)
			VALUES (?, NULL, ?, ?, ?)`, strings.ToLower(strings.TrimSpace(fingerprint)), "imported mesh blocklist", input.Now, caID); err != nil {
			return fmt.Errorf("insert imported blocklist: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO network_config (network_id, key, value) VALUES (?, 'firewall', ?)
		ON CONFLICT(network_id, key) DO UPDATE SET value = excluded.value`, networkID, input.FirewallJSON); err != nil {
		return fmt.Errorf("store imported firewall: %w", err)
	}
	for _, proposal := range input.Hosts {
		host := proposal.Host
		groupsJSON, err := json.Marshal(host.Groups)
		if err != nil {
			return fmt.Errorf("marshal finalized host groups: %w", err)
		}
		advancedJSON, err := marshalAdvanced(host.Advanced)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE hosts SET name = ?, groups_json = ?, role = ?,
			is_lighthouse = ?, is_relay = ?, public_ip = ?, listen_port = ?, advanced_json = ?,
			status = ?, updated_at = ? WHERE id = ? AND network_id = ? AND ca_id = ? AND status = ?
			AND EXISTS (SELECT 1 FROM mesh_import_snapshots s WHERE s.id = ? AND s.host_id = hosts.id AND s.mesh_import_id = ?)`,
			host.Name, string(groupsJSON), host.Role, host.IsLighthouse, host.IsRelay, host.PublicIP,
			host.ListenPort, advancedJSON, models.HostStatusEnrolled, input.Now, host.ID, networkID, caID,
			models.HostStatusImporting, proposal.SnapshotID, input.ID)
		if err != nil {
			return fmt.Errorf("finalize imported host: %w", err)
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return fmt.Errorf("finalize imported host rows: %w", err)
			}
			return ErrMeshImportConflict
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE host_agent_profiles SET mesh_import_id = NULL, updated_at = ?
		WHERE mesh_import_id = ?`, input.Now, input.ID); err != nil {
		return fmt.Errorf("detach finalized agent profiles: %w", err)
	}
	versionResult, err := tx.ExecContext(ctx, `UPDATE networks SET config_version = config_version + 1
		WHERE id = ? AND ca_id = ? AND config_version = ?`, networkID, caID, capturedVersion)
	if err != nil {
		return fmt.Errorf("bump finalized network config version: %w", err)
	}
	if rows, err := versionResult.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return fmt.Errorf("bump finalized network config rows: %w", err)
		}
		return ErrMeshImportConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mesh_import_challenges WHERE mesh_import_id = ?`, input.ID); err != nil {
		return fmt.Errorf("delete finalized mesh import challenges: %w", err)
	}
	finalized, err := tx.ExecContext(ctx, `UPDATE mesh_imports SET status = ?, revision = revision + 1,
		updated_at = ?, finalized_at = ? WHERE id = ? AND status = ? AND revision = ?`,
		models.MeshImportStatusFinalized, input.Now, input.Now, input.ID, models.MeshImportStatusCollecting, input.Revision)
	if err != nil {
		return fmt.Errorf("mark mesh import finalized: %w", err)
	}
	if rows, err := finalized.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return fmt.Errorf("mark mesh import finalized rows: %w", err)
		}
		return ErrMeshImportConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit mesh import finalize: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetHostAgentProfile(ctx context.Context, hostID string) (*models.HostAgentProfile, error) {
	var item models.HostAgentProfile
	var meshImportID sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT host_id, mesh_import_id, nebula_config_path,
		nebula_ca_path, nebula_cert_path, nebula_key_path, config_ack_v1,
		pending_config_version, created_at, updated_at
		FROM host_agent_profiles WHERE host_id = ?`, hostID).Scan(
		&item.HostID, &meshImportID, &item.NebulaConfigPath, &item.NebulaCAPath,
		&item.NebulaCertPath, &item.NebulaKeyPath, &item.ConfigAckV1,
		&item.PendingConfigVersion, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host agent profile: %w", err)
	}
	item.MeshImportID = meshImportID.String
	return &item, nil
}

func (s *SQLiteStore) SetPendingHostConfigVersion(ctx context.Context, hostID string, version int) error {
	if version <= 0 {
		return ErrConfigVersionMismatch
	}
	result, err := s.db.ExecContext(ctx, `UPDATE host_agent_profiles
		SET pending_config_version = ?, updated_at = ?
		WHERE host_id = ? AND config_ack_v1 = 1`, version, time.Now(), hostID)
	if err != nil {
		return fmt.Errorf("set pending host config version: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("set pending host config version rows affected: %w", err)
	}
	if rows == 0 {
		return ErrConfigAckUnsupported
	}
	return nil
}

func (s *SQLiteStore) AcknowledgeHostConfigVersion(ctx context.Context, hostID string, version int) error {
	if version <= 0 {
		return ErrConfigVersionMismatch
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin config ack: %w", err)
	}
	defer rollbackLog(tx)
	var status models.HostStatus
	var applied, pending int
	var capable bool
	if err := tx.QueryRowContext(ctx, `SELECT h.status, h.config_version,
		p.pending_config_version, p.config_ack_v1
		FROM hosts h JOIN host_agent_profiles p ON p.host_id = h.id WHERE h.id = ?`, hostID).
		Scan(&status, &applied, &pending, &capable); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("load config ack state: %w", err)
	}
	if status != models.HostStatusEnrolled {
		return ErrHostNotEnrolled
	}
	if !capable {
		return ErrConfigAckUnsupported
	}
	if pending == 0 && applied == version {
		return tx.Commit()
	}
	if pending != version || version < applied {
		return ErrConfigVersionMismatch
	}
	now := time.Now()
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET config_version = ?, updated_at = ? WHERE id = ?`, version, now, hostID); err != nil {
		return fmt.Errorf("advance applied config version: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE host_agent_profiles SET pending_config_version = 0, updated_at = ?
		WHERE host_id = ? AND pending_config_version = ?`, now, hostID, version)
	if err != nil {
		return fmt.Errorf("clear pending config version: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return fmt.Errorf("clear pending config version rows affected: %w", err)
		}
		return ErrConfigVersionMismatch
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit config ack: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetMeshImportTombstone(ctx context.Context, fingerprint string) (*models.MeshImportTombstone, error) {
	var item models.MeshImportTombstone
	err := s.db.QueryRowContext(ctx, `SELECT certificate_fingerprint, former_host_id,
		mesh_import_id, agent_signing_pub_pem, terminal_reason, created_at, updated_at
		FROM mesh_import_tombstones WHERE certificate_fingerprint = ?`, fingerprint).Scan(
		&item.CertificateFingerprint, &item.FormerHostID, &item.MeshImportID,
		&item.AgentSigningPubPEM, &item.TerminalReason, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mesh import tombstone: %w", err)
	}
	return &item, nil
}

func validateMeshImportRegistration(registration *models.MeshImportRegistration) error {
	if registration == nil || registration.ChallengeID == "" || registration.Host == nil ||
		registration.Snapshot == nil || registration.Profile == nil ||
		registration.CertificateNotBefore.IsZero() || !registration.CertificateNotBefore.Before(registration.CertificateNotAfter) {
		return errors.New("complete mesh import registration is required")
	}
	return nil
}

func insertImportedHost(ctx context.Context, tx *sql.Tx, host *models.Host) error {
	groupsJSON, err := json.Marshal(host.Groups)
	if err != nil {
		return fmt.Errorf("marshal imported host groups: %w", err)
	}
	advancedJSON, err := marshalAdvanced(host.Advanced)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO hosts (
		id, network_id, name, groups_json, role, is_lighthouse, is_relay,
		public_ip, listen_port, status, cert_fingerprint, cert_expires_at,
		created_at, updated_at, advanced_json, ca_id, signing_pub_pem, kind, variant)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		host.ID, host.NetworkID, host.Name, string(groupsJSON), host.Role,
		host.IsLighthouse, host.IsRelay, host.PublicIP, host.ListenPort, host.Status,
		host.CertFingerprint, host.CertExpiresAt, host.CreatedAt, host.UpdatedAt,
		advancedJSON, host.CAID, host.SigningPubPEM, host.Kind, host.Variant)
	if err != nil {
		return fmt.Errorf("insert imported host: %w", err)
	}
	return nil
}

type meshImportQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func meshImportNetworkMutationError(ctx context.Context, queryer meshImportQueryer, networkID string) error {
	var collecting int
	if err := queryer.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM mesh_imports WHERE network_id = ? AND status = ?
	)`, networkID, models.MeshImportStatusCollecting).Scan(&collecting); err != nil {
		return fmt.Errorf("check collecting mesh import: %w", err)
	}
	if collecting != 0 {
		return ErrMeshImportInProgress
	}
	return ErrNotFound
}

func meshImportNetworkOrCAUpdateError(ctx context.Context, queryer meshImportQueryer, networkID, caID string) error {
	var collecting int
	if err := queryer.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM mesh_imports
		WHERE status = ? AND (network_id = ? OR ca_id = ?)
	)`, models.MeshImportStatusCollecting, networkID, caID).Scan(&collecting); err != nil {
		return fmt.Errorf("check collecting mesh import for network update: %w", err)
	}
	if collecting != 0 {
		return ErrMeshImportInProgress
	}
	return ErrNotFound
}

func meshImportCollectingRows(ctx context.Context, queryer meshImportQueryer, result sql.Result, id string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("mesh import rows affected: %w", err)
	}
	if rows > 0 {
		return nil
	}
	var status models.MeshImportStatus
	err = queryer.QueryRowContext(ctx, `SELECT status FROM mesh_imports WHERE id = ?`, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("check mesh import status: %w", err)
	}
	return ErrMeshImportNotCollecting
}

func rollbackLog(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		slog.Error("rollback mesh import transaction", "error", err)
	}
}

func isSQLiteConstraint(err error) bool {
	var sqliteErr interface{ Code() int }
	return errors.As(err, &sqliteErr) && (sqliteErr.Code() == sqliteConstraintUnique || sqliteErr.Code() == sqliteConstraintPrimaryKey)
}
