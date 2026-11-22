package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// ErrHostAccessDenied means the current operator cannot access a host.
var ErrHostAccessDenied = errors.New("host access denied")

// ErrHostImportInProgress means the mesh import owns the host's lifecycle.
var ErrHostImportInProgress = errors.New("host is managed by an active mesh import")

// BlockHostForOperator checks policy in the same transaction as revocation.
func (s *SQLiteStore) BlockHostForOperator(ctx context.Context, operatorID, hostID, reason string) (*models.Host, error) {
	return s.blockHostWithLoader(ctx, reason, func(tx *sql.Tx) (*models.Host, error) {
		h, err := s.loadHostForOperator(ctx, tx, operatorID, hostID)
		if err != nil {
			return nil, err
		}
		if h.Status == models.HostStatusImporting {
			return nil, ErrHostImportInProgress
		}
		return h, nil
	})
}

// GetHostForOperator reads the host and its addresses in the same snapshot
// as the active-operator and CA-ownership check.
func (s *SQLiteStore) GetHostForOperator(ctx context.Context, operatorID, hostID string) (*models.Host, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin scoped host read: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // read-only snapshot
	h, err := s.loadHostForOperator(ctx, tx, operatorID, hostID)
	if err != nil {
		return nil, err
	}
	h.NebulaIPs, err = queryHostAddresses(ctx, tx, h.ID)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (s *SQLiteStore) loadHostForOperator(ctx context.Context, tx *sql.Tx, operatorID, hostID string) (*models.Host, error) {
	if operatorID == "" {
		return nil, ErrHostAccessDenied
	}
	row := tx.QueryRowContext(ctx, `SELECT `+hostColumns+` FROM hosts
		WHERE id = ? AND EXISTS (
			SELECT 1 FROM operators o WHERE o.id = ? AND o.status = ?
			AND (o.role = ? OR (o.role = ? AND hosts.ca_id <> '' AND EXISTS (
				SELECT 1 FROM cas c WHERE c.id = hosts.ca_id AND c.owner_operator_id = o.id
			)))
		)`, hostID, operatorID, models.OperatorStatusActive, models.OperatorRoleAdmin, models.OperatorRoleUser)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		// Preserve the existing 403/404 distinction without reading foreign
		// host data into the application or leaving this transaction.
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM hosts WHERE id = ?)`, hostID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check host existence: %w", err)
		}
		if exists {
			return nil, ErrHostAccessDenied
		}
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load scoped host: %w", err)
	}
	return h, nil
}
