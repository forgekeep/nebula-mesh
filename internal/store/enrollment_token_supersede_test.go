package store

import (
	"context"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestCreateTokenForHost_SupersedesPreviousUnused pins the property the rekey
// re-offer depends on.
//
// While a rekey is outstanding the poll handler mints a fresh token on every
// poll — only the hash is stored, so the previous one cannot be re-sent. That
// is only safe because minting deletes the host's other unused tokens: the
// rows cannot pile up once per poll, and no superseded credential stays
// usable.
func TestCreateTokenForHost_SupersedesPreviousUnused(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-1", Name: "net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(ctx, &models.Host{
		ID: "h-1", NetworkID: "n-1", Name: "web-1",
		NebulaIPs: []string{"10.0.0.1"}, Role: models.HostRoleHost,
		Status: models.HostStatusPending, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	expires := time.Now().Add(time.Hour)
	for i, tok := range []string{"tok-a", "tok-b", "tok-c"} {
		if err := s.CreateTokenForHost(ctx, "h-1", tok, expires); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}

	var live int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM enrollment_tokens WHERE host_id = ? AND used = 0`, "h-1").Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("live unused tokens = %d, want 1 — repeated rekey offers would accumulate rows", live)
	}

	// Only the newest is redeemable.
	for _, superseded := range []string{"tok-a", "tok-b"} {
		if _, err := s.ConsumeToken(ctx, superseded); err == nil {
			t.Errorf("superseded token %q is still redeemable", superseded)
		}
	}
	if _, err := s.ConsumeToken(ctx, "tok-c"); err != nil {
		t.Errorf("newest token should be redeemable: %v", err)
	}
}
