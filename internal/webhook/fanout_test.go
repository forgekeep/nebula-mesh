package webhook

import (
	"context"
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
}

func (f *fakeSource) TargetsFor(_ context.Context, _ string) ([]Target, error) {
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

	d.Emit("host.enrolled", map[string]any{"host_id": "h1"})

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

	src := NewStoreSource(s, master, testLogger())

	// Event filter: not subscribed -> no targets.
	if tgts, _ := src.TargetsFor(ctx, "host.enrolled"); len(tgts) != 0 {
		t.Errorf("host.enrolled targets = %d, want 0", len(tgts))
	}
	// Subscribed -> one target with the decrypted secret.
	tgts, err := src.TargetsFor(ctx, "host.blocked")
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
}
