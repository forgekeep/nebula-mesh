package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type recordedDelivery struct {
	id string
	ok bool
}

type fakeSource struct {
	targets  []Target
	mu       sync.Mutex
	recorded []recordedDelivery
	scopes   []Scope
}

func (f *fakeSource) TargetsFor(_ context.Context, scope Scope, _ string) ([]Target, error) {
	f.mu.Lock()
	f.scopes = append(f.scopes, scope)
	f.mu.Unlock()
	return f.targets, nil
}

func (f *fakeSource) RecordDelivery(_ context.Context, id string, ok bool, _ string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, recordedDelivery{id, ok})
}

func (f *fakeSource) outcomes() []recordedDelivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedDelivery(nil), f.recorded...)
}

func TestDispatcher_FanOutToSourceTargets(t *testing.T) {
	var hitsA, hitsB sync.WaitGroup
	hitsA.Add(1)
	hitsB.Add(1)
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hitsA.Done() }))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hitsB.Done() }))
	defer srvB.Close()

	src := &fakeSource{targets: []Target{
		{ID: "sub-a", URL: srvA.URL, AllowPrivate: true},
		{ID: "sub-b", URL: srvB.URL, AllowPrivate: true},
	}}
	d := New(Config{Source: src}, testLogger())
	defer d.Close()

	d.Emit(Scope{CAID: "ca-a"}, "host.enrolled", map[string]any{"host_id": "h1"})

	doneA := make(chan struct{})
	go func() { hitsA.Wait(); close(doneA) }()
	doneB := make(chan struct{})
	go func() { hitsB.Wait(); close(doneB) }()
	for _, ch := range []chan struct{}{doneA, doneB} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("a fan-out target did not receive the event")
		}
	}

	// Delivery status recorded ok for both subscriptions.
	d.Close()
	got := src.outcomes()
	if len(got) != 2 {
		t.Fatalf("recorded %d outcomes, want 2: %+v", len(got), got)
	}
	for _, o := range got {
		if !o.ok {
			t.Errorf("subscription %s recorded failure, want ok", o.id)
		}
	}
	if len(src.scopes) != 1 || src.scopes[0].CAID != "ca-a" {
		t.Fatalf("source scopes = %#v, want ca-a", src.scopes)
	}
}

func TestDispatcher_ManagedTargetsAreCAOwnerScopedAndStaticTargetIsGlobal(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, op := range []*models.Operator{
		{ID: "op-a", Username: "op-a", DisplayName: "op-a", PasswordHash: "x", Role: "admin"},
		{ID: "op-b", Username: "op-b", DisplayName: "op-b", PasswordHash: "x", Role: "admin"},
	} {
		if err := s.CreateOperator(ctx, op); err != nil {
			t.Fatal(err)
		}
	}
	for _, ca := range []*models.CA{
		{ID: "ca-a", Name: "ca-a", OwnerOperatorID: "op-a", CertPEM: "pem-a", Fingerprint: "fp-a", NotBefore: now, NotAfter: now.Add(time.Hour), Status: models.CAStatusActive, EncryptedKeyDEK: []byte{1}, NonceDEK: []byte{1}, EncryptedKeyMaterial: []byte{1}, NonceKey: []byte{1}},
		{ID: "ca-b", Name: "ca-b", OwnerOperatorID: "op-b", CertPEM: "pem-b", Fingerprint: "fp-b", NotBefore: now, NotAfter: now.Add(time.Hour), Status: models.CAStatusActive, EncryptedKeyDEK: []byte{1}, NonceDEK: []byte{1}, EncryptedKeyMaterial: []byte{1}, NonceKey: []byte{1}},
	} {
		if err := s.CreateCA(ctx, ca); err != nil {
			t.Fatal(err)
		}
	}

	managedA := make(chan received, 2)
	managedB := make(chan received, 2)
	static := make(chan received, 3)
	managedAServer := recvServer(t, managedA, http.StatusOK)
	managedBServer := recvServer(t, managedB, http.StatusOK)
	staticServer := recvServer(t, static, http.StatusOK)
	for _, sub := range []*models.WebhookSubscription{
		{ID: "sub-a", OwnerOperatorID: "op-a", URL: managedAServer.URL, Events: []string{"host.enrolled"}, Active: true, AllowPrivate: true},
		{ID: "sub-b", OwnerOperatorID: "op-b", URL: managedBServer.URL, Events: []string{"host.enrolled"}, Active: true, AllowPrivate: true},
	} {
		if err := s.CreateWebhookSubscription(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}

	d := New(Config{
		URL: staticServer.URL, Events: []string{"host.enrolled"}, AllowPrivate: true,
		Source: NewStoreSource(s, nil, testLogger()),
	}, testLogger())
	d.Emit(Scope{CAID: "ca-a"}, "host.enrolled", map[string]any{"host_id": "host-a", "ca_id": "ca-a"})
	d.Emit(Scope{CAID: "ca-b"}, "host.enrolled", map[string]any{"host_id": "host-b", "ca_id": "ca-b"})
	d.Close()

	if got := receivedCAID(t, waitRecv(t, managedA)); got != "ca-a" {
		t.Errorf("managed A received CA %q, want ca-a", got)
	}
	if got := receivedCAID(t, waitRecv(t, managedB)); got != "ca-b" {
		t.Errorf("managed B received CA %q, want ca-b", got)
	}
	expectNoRecv(t, managedA)
	expectNoRecv(t, managedB)
	for _, want := range []string{"ca-a", "ca-b"} {
		if got := receivedCAID(t, waitRecv(t, static)); got != want {
			t.Errorf("static target received CA %q, want %q", got, want)
		}
	}
}

func receivedCAID(t *testing.T, delivery received) string {
	t.Helper()
	var event Event
	if err := json.Unmarshal(delivery.body, &event); err != nil {
		t.Fatalf("unmarshal webhook event: %v", err)
	}
	caID, _ := event.Data["ca_id"].(string)
	return caID
}

func TestStoreSource_DecryptsAndFilters(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperator(ctx, &models.Operator{ID: "op1", Username: "op1", DisplayName: "op1", PasswordHash: "x", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperator(ctx, &models.Operator{ID: "op2", Username: "op2", DisplayName: "op2", PasswordHash: "x", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, ca := range []*models.CA{
		{ID: "ca1", Name: "ca1", OwnerOperatorID: "op1", CertPEM: "pem1", Fingerprint: "fp1", NotBefore: now, NotAfter: now.Add(time.Hour), Status: models.CAStatusActive, EncryptedKeyDEK: []byte{1}, NonceDEK: []byte{1}, EncryptedKeyMaterial: []byte{1}, NonceKey: []byte{1}},
		{ID: "ca2", Name: "ca2", OwnerOperatorID: "op2", CertPEM: "pem2", Fingerprint: "fp2", NotBefore: now, NotAfter: now.Add(time.Hour), Status: models.CAStatusActive, EncryptedKeyDEK: []byte{1}, NonceDEK: []byte{1}, EncryptedKeyMaterial: []byte{1}, NonceKey: []byte{1}},
	} {
		if err := s.CreateCA(ctx, ca); err != nil {
			t.Fatal(err)
		}
	}

	master, err := keystore.NewMaster(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	// Seal a secret for sub "wh1" the way the API handler will.
	const subID, secret = "wh1", "topsecret"
	dek, wrappedDEK, err := master.GenerateDEK([]byte(subID))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := keystore.SealWithDEK(dek, []byte(secret), []byte(subID))
	if err != nil {
		t.Fatal(err)
	}
	keystore.Zeroize(dek)

	sub := &models.WebhookSubscription{
		ID: subID, OwnerOperatorID: "op1", URL: "https://x/y", Active: true,
		Events:             []string{"host.blocked"},
		EncryptedSecretDEK: wrappedDEK.Ciphertext, NonceDEK: wrappedDEK.Nonce,
		EncryptedSecret: blob.Ciphertext, NonceSecret: blob.Nonce,
	}
	if err := s.CreateWebhookSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateWebhookSubscription(ctx, &models.WebhookSubscription{
		ID: "wh2", OwnerOperatorID: "op2", URL: "https://other/y", Active: true,
		Events: []string{"host.blocked"},
	}); err != nil {
		t.Fatal(err)
	}

	src := NewStoreSource(s, master, testLogger())

	// Event filter: not subscribed -> no targets.
	if tgts, _ := src.TargetsFor(ctx, Scope{CAID: "ca1"}, "host.enrolled"); len(tgts) != 0 {
		t.Errorf("host.enrolled targets = %d, want 0", len(tgts))
	}
	// Subscribed -> one target with the decrypted secret.
	tgts, err := src.TargetsFor(ctx, Scope{CAID: "ca1"}, "host.blocked")
	if err != nil {
		t.Fatal(err)
	}
	if len(tgts) != 1 {
		t.Fatalf("host.blocked targets = %d, want 1", len(tgts))
	}
	if string(tgts[0].Secret) != secret {
		t.Errorf("decrypted secret = %q, want %q", tgts[0].Secret, secret)
	}
	if tgts[0].ID != subID || tgts[0].URL != "https://x/y" {
		t.Errorf("target = %+v", tgts[0])
	}
	for _, scope := range []Scope{{CAID: ""}, {CAID: "missing"}} {
		tgts, err := src.TargetsFor(ctx, scope, "host.blocked")
		if err != nil {
			t.Fatal(err)
		}
		if len(tgts) != 0 {
			t.Errorf("targets for scope %#v = %+v, want none", scope, tgts)
		}
	}
}
