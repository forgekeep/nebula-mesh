package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

const webhookSubColumns = `id, owner_operator_id, url, events, active, allow_private, ` +
	`encrypted_secret_dek, nonce_dek, encrypted_secret, nonce_secret, ` +
	`last_delivery_at, last_status, last_error, consecutive_failures, created_at, updated_at`

func joinEvents(events []string) string { return strings.Join(events, ",") }

func splitEvents(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func scanWebhookSubscription(scanner interface{ Scan(dest ...any) error }) (*models.WebhookSubscription, error) {
	var (
		sub          models.WebhookSubscription
		eventsCSV    string
		lastDelivery sql.NullTime
	)
	if err := scanner.Scan(
		&sub.ID, &sub.OwnerOperatorID, &sub.URL, &eventsCSV, &sub.Active, &sub.AllowPrivate,
		&sub.EncryptedSecretDEK, &sub.NonceDEK, &sub.EncryptedSecret, &sub.NonceSecret,
		&lastDelivery, &sub.LastStatus, &sub.LastError, &sub.ConsecutiveFailures,
		&sub.CreatedAt, &sub.UpdatedAt,
	); err != nil {
		return nil, err
	}
	sub.Events = splitEvents(eventsCSV)
	sub.HasSecret = len(sub.EncryptedSecret) > 0
	if lastDelivery.Valid {
		sub.LastDeliveryAt = &lastDelivery.Time
	}
	return &sub, nil
}

// CreateWebhookSubscription inserts a new subscription.
func (s *SQLiteStore) CreateWebhookSubscription(ctx context.Context, sub *models.WebhookSubscription) error {
	if sub.ID == "" || sub.OwnerOperatorID == "" || sub.URL == "" {
		return fmt.Errorf("webhook subscription id, owner_operator_id, url are required")
	}
	now := time.Now()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	if sub.UpdatedAt.IsZero() {
		sub.UpdatedAt = now
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webhook_subscriptions (`+webhookSubColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sub.ID, sub.OwnerOperatorID, sub.URL, joinEvents(sub.Events), sub.Active, sub.AllowPrivate,
		sub.EncryptedSecretDEK, sub.NonceDEK, sub.EncryptedSecret, sub.NonceSecret,
		nil, "", "", 0, sub.CreatedAt, sub.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert webhook subscription: %w", err)
	}
	return nil
}

// GetWebhookSubscription returns one subscription by id.
func (s *SQLiteStore) GetWebhookSubscription(ctx context.Context, id string) (*models.WebhookSubscription, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+webhookSubColumns+` FROM webhook_subscriptions WHERE id = ?`, id)
	sub, err := scanWebhookSubscription(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get webhook subscription: %w", err)
	}
	return sub, nil
}

func (s *SQLiteStore) queryWebhookSubscriptions(ctx context.Context, query string, args ...any) ([]*models.WebhookSubscription, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query webhook subscriptions: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()
	var out []*models.WebhookSubscription
	for rows.Next() {
		sub, err := scanWebhookSubscription(rows)
		if err != nil {
			return nil, fmt.Errorf("scan webhook subscription: %w", err)
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// ListWebhookSubscriptions returns every subscription (admin view).
func (s *SQLiteStore) ListWebhookSubscriptions(ctx context.Context) ([]*models.WebhookSubscription, error) {
	return s.queryWebhookSubscriptions(ctx, `SELECT `+webhookSubColumns+` FROM webhook_subscriptions ORDER BY created_at`)
}

// ListWebhookSubscriptionsByOwner returns subscriptions owned by ownerID.
func (s *SQLiteStore) ListWebhookSubscriptionsByOwner(ctx context.Context, ownerID string) ([]*models.WebhookSubscription, error) {
	return s.queryWebhookSubscriptions(ctx, `SELECT `+webhookSubColumns+` FROM webhook_subscriptions WHERE owner_operator_id = ? ORDER BY created_at`, ownerID)
}

// ListActiveWebhookSubscriptionsForCA returns active subscriptions owned by
// the operator that owns caID. An unknown or empty CA id matches no owner.
func (s *SQLiteStore) ListActiveWebhookSubscriptionsForCA(ctx context.Context, caID string) ([]*models.WebhookSubscription, error) {
	return s.queryWebhookSubscriptions(ctx, `SELECT `+webhookSubColumns+`
		FROM webhook_subscriptions
		WHERE active = 1
		AND owner_operator_id = (SELECT owner_operator_id FROM cas WHERE id = ?)
		ORDER BY created_at, id`, caID)
}

// UpdateWebhookSubscription writes the mutable fields (url, events, active,
// allow_private, secret envelope) and bumps updated_at. Delivery-status columns
// are left to RecordWebhookDelivery.
func (s *SQLiteStore) UpdateWebhookSubscription(ctx context.Context, sub *models.WebhookSubscription) error {
	sub.UpdatedAt = time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE webhook_subscriptions SET url = ?, events = ?, active = ?, allow_private = ?,
		 encrypted_secret_dek = ?, nonce_dek = ?, encrypted_secret = ?, nonce_secret = ?, updated_at = ?
		 WHERE id = ?`,
		sub.URL, joinEvents(sub.Events), sub.Active, sub.AllowPrivate,
		sub.EncryptedSecretDEK, sub.NonceDEK, sub.EncryptedSecret, sub.NonceSecret, sub.UpdatedAt,
		sub.ID,
	)
	if err != nil {
		return fmt.Errorf("update webhook subscription: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// DeleteWebhookSubscription removes a subscription.
func (s *SQLiteStore) DeleteWebhookSubscription(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webhook_subscriptions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete webhook subscription: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// RecordWebhookDelivery updates a subscription's delivery-status columns after
// an attempt. On success it clears the failure counter and error; on failure it
// increments the counter and stores the (truncated) error.
func (s *SQLiteStore) RecordWebhookDelivery(ctx context.Context, id string, ok bool, errMsg string, at time.Time) error {
	var query string
	var args []any
	if ok {
		query = `UPDATE webhook_subscriptions SET last_delivery_at = ?, last_status = 'ok', last_error = '', consecutive_failures = 0 WHERE id = ?`
		args = []any{at, id}
	} else {
		if len(errMsg) > 500 {
			errMsg = errMsg[:500]
		}
		query = `UPDATE webhook_subscriptions SET last_delivery_at = ?, last_status = 'failed', last_error = ?, consecutive_failures = consecutive_failures + 1 WHERE id = ?`
		args = []any{at, errMsg, id}
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("record webhook delivery: %w", err)
	}
	return nil
}

func rowsAffectedOrNotFound(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
