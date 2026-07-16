package webhook

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

// errMasterRequired is returned when a subscription has an encrypted secret but
// no master key is configured to decrypt it.
var errMasterRequired = errors.New("webhook secret is encrypted but master key is not configured")

// SubStore is the store surface a StoreSource needs.
type SubStore interface {
	ListActiveWebhookSubscriptionsForCA(ctx context.Context, caID string) ([]*models.WebhookSubscription, error)
	RecordWebhookDelivery(ctx context.Context, id string, ok bool, errMsg string, at time.Time) error
}

// StoreSource resolves managed subscriptions from the store, decrypting each
// subscription's HMAC secret under the master key at delivery time. It
// satisfies SubscriptionSource.
type StoreSource struct {
	store  SubStore
	master *keystore.Master
	logger *slog.Logger
	now    func() time.Time
}

// NewStoreSource builds a store-backed subscription source. master may be nil
// (subscriptions with secrets are then skipped with a logged error).
func NewStoreSource(s SubStore, master *keystore.Master, logger *slog.Logger) *StoreSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &StoreSource{store: s, master: master, logger: logger, now: time.Now}
}

// TargetsFor returns active subscriptions wanting eventType, secrets decrypted.
func (s *StoreSource) TargetsFor(ctx context.Context, scope Scope, eventType string) ([]Target, error) {
	subs, err := s.store.ListActiveWebhookSubscriptionsForCA(ctx, scope.CAID)
	if err != nil {
		return nil, err
	}
	var out []Target
	for _, sub := range subs {
		if !wantsEvent(sub.Events, eventType) {
			continue
		}
		secret, err := s.decryptSecret(sub)
		if err != nil {
			// A configured-but-undecryptable secret is a misconfiguration;
			// skip rather than deliver unsigned when the operator expects a
			// signature. RecordDelivery on the next live attempt would surface
			// it, but here we just log and move on.
			s.logger.Error("decrypt webhook secret", "subscription", sub.ID, "error", err)
			continue
		}
		out = append(out, Target{ID: sub.ID, URL: sub.URL, Secret: secret, AllowPrivate: sub.AllowPrivate})
	}
	return out, nil
}

// RecordDelivery persists a delivery outcome against the subscription.
func (s *StoreSource) RecordDelivery(ctx context.Context, id string, ok bool, errMsg string) {
	if err := s.store.RecordWebhookDelivery(ctx, id, ok, errMsg, s.now()); err != nil {
		s.logger.Error("record webhook delivery", "subscription", id, "error", err)
	}
}

func wantsEvent(events []string, eventType string) bool {
	if len(events) == 0 {
		return true
	}
	for _, e := range events {
		if e == eventType {
			return true
		}
	}
	return false
}

func (s *StoreSource) decryptSecret(sub *models.WebhookSubscription) ([]byte, error) {
	if len(sub.EncryptedSecret) == 0 {
		return nil, nil // unsigned subscription
	}
	if s.master == nil {
		return nil, errMasterRequired
	}
	aad := []byte(sub.ID)
	dek, err := s.master.UnwrapDEK(keystore.WrappedKey{Ciphertext: sub.EncryptedSecretDEK, Nonce: sub.NonceDEK}, aad)
	if err != nil {
		return nil, err
	}
	defer keystore.Zeroize(dek)
	secret, err := keystore.OpenWithDEK(dek, keystore.WrappedBlob{Ciphertext: sub.EncryptedSecret, Nonce: sub.NonceSecret}, aad)
	if err != nil {
		return nil, err
	}
	return secret, nil
}
