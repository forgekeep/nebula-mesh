package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func seedWebhookOwner(t *testing.T, s *SQLiteStore, id string) {
	t.Helper()
	op := &models.Operator{ID: id, Username: id, DisplayName: id, PasswordHash: "x", Role: "admin"}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}
}

func seedWebhookCA(t *testing.T, s *SQLiteStore, id, ownerID string) {
	t.Helper()
	now := time.Now()
	ca := &models.CA{
		ID: id, Name: id, OwnerOperatorID: ownerID, CertPEM: "pem-" + id,
		Fingerprint: "fp-" + id, NotBefore: now, NotAfter: now.Add(time.Hour),
		Status: models.CAStatusActive, EncryptedKeyDEK: []byte{1}, NonceDEK: []byte{1},
		EncryptedKeyMaterial: []byte{1}, NonceKey: []byte{1},
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookSubscription_ListActiveForCAIsOwnerScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedWebhookOwner(t, s, "op-a")
	seedWebhookOwner(t, s, "op-b")
	seedWebhookCA(t, s, "ca-a", "op-a")
	seedWebhookCA(t, s, "ca-a-second", "op-a")
	seedWebhookCA(t, s, "ca-b", "op-b")

	for _, sub := range []*models.WebhookSubscription{
		{ID: "wh-a", OwnerOperatorID: "op-a", URL: "https://a.example/hook", Active: true},
		{ID: "wh-a-second", OwnerOperatorID: "op-a", URL: "https://a2.example/hook", Active: true},
		{ID: "wh-a-inactive", OwnerOperatorID: "op-a", URL: "https://inactive.example/hook", Active: false},
		{ID: "wh-b", OwnerOperatorID: "op-b", URL: "https://b.example/hook", Active: true},
	} {
		if err := s.CreateWebhookSubscription(ctx, sub); err != nil {
			t.Fatalf("create subscription %s: %v", sub.ID, err)
		}
	}

	for _, caID := range []string{"ca-a", "ca-a-second"} {
		got, err := s.ListActiveWebhookSubscriptionsForCA(ctx, caID)
		if err != nil {
			t.Fatalf("list subscriptions for %s: %v", caID, err)
		}
		if len(got) != 2 || got[0].ID != "wh-a" || got[1].ID != "wh-a-second" {
			t.Errorf("subscriptions for %s = %#v, want wh-a and wh-a-second", caID, got)
		}
	}

	got, err := s.ListActiveWebhookSubscriptionsForCA(ctx, "ca-b")
	if err != nil {
		t.Fatalf("list subscriptions for ca-b: %v", err)
	}
	if len(got) != 1 || got[0].ID != "wh-b" {
		t.Errorf("subscriptions for ca-b = %#v, want wh-b", got)
	}

	for _, caID := range []string{"", "missing"} {
		got, err := s.ListActiveWebhookSubscriptionsForCA(ctx, caID)
		if err != nil {
			t.Fatalf("list subscriptions for %q: %v", caID, err)
		}
		if len(got) != 0 {
			t.Errorf("subscriptions for %q = %#v, want none", caID, got)
		}
	}
}

func TestWebhookSubscription_CRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedWebhookOwner(t, s, "op1")
	seedWebhookCA(t, s, "ca1", "op1")

	sub := &models.WebhookSubscription{
		ID:                 "wh1",
		OwnerOperatorID:    "op1",
		URL:                "https://hooks.example.com/a",
		Events:             []string{"host.enrolled", "host.blocked"},
		Active:             true,
		AllowPrivate:       false,
		EncryptedSecretDEK: []byte("dek"),
		NonceDEK:           []byte("nd"),
		EncryptedSecret:    []byte("sec"),
		NonceSecret:        []byte("ns"),
	}
	if err := s.CreateWebhookSubscription(ctx, sub); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.GetWebhookSubscription(ctx, "wh1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.URL != sub.URL || len(got.Events) != 2 || got.Events[0] != "host.enrolled" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if !got.HasSecret {
		t.Error("HasSecret should be true when secret present")
	}
	if string(got.EncryptedSecret) != "sec" {
		t.Errorf("secret blob = %q", got.EncryptedSecret)
	}

	// Update: change url, deactivate, drop secret.
	got.URL = "https://hooks.example.com/b"
	got.Active = false
	got.Events = nil // all events
	got.EncryptedSecretDEK, got.NonceDEK, got.EncryptedSecret, got.NonceSecret = nil, nil, nil, nil
	if err := s.UpdateWebhookSubscription(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, _ := s.GetWebhookSubscription(ctx, "wh1")
	if got2.URL != "https://hooks.example.com/b" || got2.Active || got2.HasSecret || len(got2.Events) != 0 {
		t.Errorf("update not applied: %+v", got2)
	}

	// ListActive excludes the now-inactive sub.
	active, _ := s.ListActiveWebhookSubscriptionsForCA(ctx, "ca1")
	if len(active) != 0 {
		t.Errorf("active list = %d, want 0", len(active))
	}

	// Owner scoping.
	owned, _ := s.ListWebhookSubscriptionsByOwner(ctx, "op1")
	if len(owned) != 1 {
		t.Errorf("owned = %d, want 1", len(owned))
	}
	none, _ := s.ListWebhookSubscriptionsByOwner(ctx, "op-other")
	if len(none) != 0 {
		t.Errorf("other-owner = %d, want 0", len(none))
	}

	// Delete.
	if err := s.DeleteWebhookSubscription(ctx, "wh1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetWebhookSubscription(ctx, "wh1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteWebhookSubscription(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v, want ErrNotFound", err)
	}
}

func TestWebhookSubscription_RecordDelivery(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedWebhookOwner(t, s, "op1")
	sub := &models.WebhookSubscription{ID: "wh1", OwnerOperatorID: "op1", URL: "https://x/y", Active: true}
	if err := s.CreateWebhookSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := s.RecordWebhookDelivery(ctx, "wh1", false, "boom", now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetWebhookSubscription(ctx, "wh1")
	if got.LastStatus != "failed" || got.ConsecutiveFailures != 1 || got.LastError != "boom" {
		t.Errorf("after failure: %+v", got)
	}
	if got.LastDeliveryAt == nil {
		t.Error("last_delivery_at not set")
	}

	if err := s.RecordWebhookDelivery(ctx, "wh1", true, "", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.GetWebhookSubscription(ctx, "wh1")
	if got2.LastStatus != "ok" || got2.ConsecutiveFailures != 0 || got2.LastError != "" {
		t.Errorf("after success: %+v", got2)
	}
}
