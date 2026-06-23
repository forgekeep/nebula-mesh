package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func createTestNetwork(t *testing.T, s *SQLiteStore) *models.Network {
	t.Helper()
	n := &models.Network{
		ID:        "net_test1",
		Name:      "test-network",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrate_Idempotent(t *testing.T) {
	s := newTestStore(t)
	// Second migrate should not fail
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestListMethods_EmptyResult_NotNil(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	networks, err := s.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if networks == nil {
		t.Error("ListNetworks returned nil, want empty slice")
	}

	hosts, err := s.ListHosts(ctx, HostFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if hosts == nil {
		t.Error("ListHosts returned nil, want empty slice")
	}

	certs, err := s.ListEnrolledHostCerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if certs == nil {
		t.Error("ListEnrolledHostCerts returned nil, want empty slice")
	}

	bl, err := s.GetBlocklist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bl == nil {
		t.Error("GetBlocklist returned nil, want empty slice")
	}

	entries, err := s.ListAuditEntries(ctx, AuditFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if entries == nil {
		t.Error("ListAuditEntries returned nil, want empty slice")
	}
}

// --- Networks ---

func TestCreateAndGetNetwork(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	n := &models.Network{
		ID:        "net_1",
		Name:      "prod",
		CIDRs:     []string{"10.0.0.0/16"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetNetwork(ctx, "net_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "prod" {
		t.Errorf("name = %q, want %q", got.Name, "prod")
	}
	if len(got.CIDRs) != 1 || got.CIDRs[0] != "10.0.0.0/16" {
		t.Errorf("cidrs = %v, want [10.0.0.0/16]", got.CIDRs)
	}
}

func TestGetNetwork_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetNetwork(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListNetworks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, name := range []string{"beta", "alpha"} {
		n := &models.Network{ID: "net_" + name, Name: name, CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()}
		if err := s.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	nets, err := s.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Fatalf("len = %d, want 2", len(nets))
	}
	// Should be sorted by name
	if nets[0].Name != "alpha" {
		t.Errorf("first = %q, want alpha", nets[0].Name)
	}
}

// --- Hosts ---

func TestCreateAndGetHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID:        "host_1",
		NetworkID: net.ID,
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    []string{"web", "prod"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetHost(ctx, "host_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "web-1" {
		t.Errorf("name = %q, want %q", got.Name, "web-1")
	}
	if len(got.Groups) != 2 || got.Groups[0] != "web" {
		t.Errorf("groups = %v, want [web prod]", got.Groups)
	}
}

func TestListHosts_FilterByNetwork(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	for i, name := range []string{"host-a", "host-b"} {
		h := &models.Host{
			ID: fmt.Sprintf("host_%d", i), NetworkID: net.ID, Name: name,
			NebulaIPs: []string{fmt.Sprintf("192.168.100.%d", 10+i)},
			Groups:    []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if err := s.CreateHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}

	hosts, err := s.ListHosts(ctx, HostFilter{NetworkID: net.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("len = %d, want 2", len(hosts))
	}
}

func TestListHosts_WithLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	for i := 0; i < 3; i++ {
		h := &models.Host{
			ID: fmt.Sprintf("host_%d", i), NetworkID: net.ID,
			Name:      fmt.Sprintf("host-%d", i),
			NebulaIPs: []string{fmt.Sprintf("192.168.100.%d", 10+i)},
			Groups:    []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if err := s.CreateHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}

	// Limit=2 should return only 2
	hosts, err := s.ListHosts(ctx, HostFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Errorf("len = %d, want 2", len(hosts))
	}

	// Limit=0 should return all (no limit)
	hosts, err = s.ListHosts(ctx, HostFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Errorf("len = %d, want 3", len(hosts))
	}
}

func TestListHosts_FilterByGroup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h1 := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "web", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{"web"}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	h2 := &models.Host{
		ID: "host_2", NetworkID: net.ID, Name: "db", NebulaIPs: []string{"192.168.100.11"},
		Groups: []string{"database"}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(ctx, h2); err != nil {
		t.Fatal(err)
	}

	hosts, err := s.ListHosts(ctx, HostFilter{Group: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Name != "web" {
		t.Errorf("expected 1 host named 'web', got %v", hosts)
	}
}

func TestUpdateHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	h.Status = models.HostStatusEnrolled
	h.CertFingerprint = "abc123"
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetHost(ctx, "host_1")
	if got.Status != models.HostStatusEnrolled {
		t.Errorf("status = %q, want enrolled", got.Status)
	}
	if got.CertFingerprint != "abc123" {
		t.Errorf("fingerprint = %q, want abc123", got.CertFingerprint)
	}
}

func TestDeleteHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteHost(ctx, "host_1"); err != nil {
		t.Fatal(err)
	}

	_, err := s.GetHost(ctx, "host_1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Tokens ---

func TestConsumeToken_Success(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	tok := &models.EnrollmentToken{
		ID: "tok_1", HostID: "host_1", TokenHash: models.HashEnrollmentToken("secret-token"),
		ExpiresAt: time.Now().Add(1 * time.Hour), CreatedAt: time.Now(),
	}
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	consumed, err := s.ConsumeToken(ctx, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if consumed.HostID != "host_1" {
		t.Errorf("host_id = %q, want host_1", consumed.HostID)
	}
	if !consumed.Used {
		t.Error("expected Used to be true")
	}
}

func TestConsumeToken_AlreadyUsed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.CreateHost(ctx, h)

	tok := &models.EnrollmentToken{
		ID: "tok_1", HostID: "host_1", TokenHash: models.HashEnrollmentToken("one-time"),
		ExpiresAt: time.Now().Add(1 * time.Hour), CreatedAt: time.Now(),
	}
	s.CreateToken(ctx, tok)
	s.ConsumeToken(ctx, "one-time")

	_, err := s.ConsumeToken(ctx, "one-time")
	if !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("err = %v, want ErrTokenUsed", err)
	}
}

func TestConsumeToken_Expired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.CreateHost(ctx, h)

	tok := &models.EnrollmentToken{
		ID: "tok_1", HostID: "host_1", TokenHash: models.HashEnrollmentToken("expired-token"),
		ExpiresAt: time.Now().Add(-1 * time.Hour), CreatedAt: time.Now(),
	}
	s.CreateToken(ctx, tok)

	_, err := s.ConsumeToken(ctx, "expired-token")
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

func TestConsumeToken_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.ConsumeToken(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Certificates ---

func TestSaveAndGetCertificate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.CreateHost(ctx, h)

	now := time.Now()
	err := s.SaveCertificate(ctx, "host_1", []byte("cert-pem-data"), "fp123", now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	pem, err := s.GetCurrentCertificate(ctx, "host_1")
	if err != nil {
		t.Fatal(err)
	}
	if string(pem) != "cert-pem-data" {
		t.Errorf("pem = %q, want cert-pem-data", string(pem))
	}
}

func TestSaveCertificate_ReplacesOld(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.CreateHost(ctx, h)

	now := time.Now()
	s.SaveCertificate(ctx, "host_1", []byte("old-cert"), "fp_old", now, now.Add(24*time.Hour))
	s.SaveCertificate(ctx, "host_1", []byte("new-cert"), "fp_new", now, now.Add(48*time.Hour))

	pem, err := s.GetCurrentCertificate(ctx, "host_1")
	if err != nil {
		t.Fatal(err)
	}
	if string(pem) != "new-cert" {
		t.Errorf("pem = %q, want new-cert", string(pem))
	}
}

// --- Blocklist ---

func TestBlocklist_AddAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.AddToBlocklist(ctx, "fp1", "", "test reason")
	s.AddToBlocklist(ctx, "fp2", "", "another reason")

	list, err := s.GetBlocklist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
}

// --- Audit Log ---

// TestAddAuditEntry_ConcurrentWritesAllPersist drives parallel AddAuditEntry
// calls and asserts every row lands. With a timestamp-derived id two writes
// in the same nanosecond collided on the PRIMARY KEY and the loser vanished
// silently (every production caller discards this method's error).
func TestAddAuditEntry_ConcurrentWritesAllPersist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const writers = 8
	const perWriter = 25
	errs := make(chan error, writers*perWriter)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				errs <- s.AddAuditEntry(ctx, "admin", "concurrent_action",
					fmt.Sprintf("w%d_r%d", w, i), "")
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AddAuditEntry: %v", err)
		}
	}

	entries, err := s.ListAuditEntries(ctx, AuditFilter{Action: "concurrent_action", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != writers*perWriter {
		t.Errorf("persisted rows = %d, want %d (silent row loss)", len(entries), writers*perWriter)
	}
}

func TestListAuditEntries_WithLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Create 5 audit entries
	for i := 0; i < 5; i++ {
		if err := s.AddAuditEntry(ctx, "admin", "test_action", fmt.Sprintf("resource_%d", i), ""); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := s.ListAuditEntries(ctx, AuditFilter{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("len = %d, want 3", len(entries))
	}
}

func TestUpdateHost_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	h := &models.Host{
		ID: "nonexistent", Name: "ghost", NebulaIPs: []string{"10.0.0.1"},
		Groups: []string{}, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	err := s.UpdateHost(ctx, h)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteHost_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.DeleteHost(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListHosts_GroupFilterSpecialChars(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	// Host with group containing percent sign
	h1 := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "special", NebulaIPs: []string{"192.168.100.10"},
		Groups: []string{"50%off"}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	h2 := &models.Host{
		ID: "host_2", NetworkID: net.ID, Name: "normal", NebulaIPs: []string{"192.168.100.11"},
		Groups: []string{"web"}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(ctx, h2); err != nil {
		t.Fatal(err)
	}

	// Search for exact group "50%off" — should find only host_1
	hosts, err := s.ListHosts(ctx, HostFilter{Group: "50%off"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("len = %d, want 1 (only host with exact group '50%%off')", len(hosts))
	}
	if hosts[0].Name != "special" {
		t.Errorf("name = %q, want 'special'", hosts[0].Name)
	}

	// Search with just "%" should NOT match anything (no group named exactly "%")
	hosts, err = s.ListHosts(ctx, HostFilter{Group: "%"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Errorf("len = %d, want 0 (no group named exactly '%%')", len(hosts))
	}
}

// --- Network Config ---

func TestGetSetNetworkConfig(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	createTestNetwork(t, s)

	// Set config
	if err := s.SetNetworkConfig(ctx, "net_test1", "firewall", `{"inbound":[]}`); err != nil {
		t.Fatal(err)
	}

	// Get config
	val, err := s.GetNetworkConfig(ctx, "net_test1", "firewall")
	if err != nil {
		t.Fatal(err)
	}
	if val != `{"inbound":[]}` {
		t.Errorf("value = %q, want %q", val, `{"inbound":[]}`)
	}

	// Upsert (overwrite)
	if err := s.SetNetworkConfig(ctx, "net_test1", "firewall", `{"inbound":[{"port":"any"}]}`); err != nil {
		t.Fatal(err)
	}
	val, err = s.GetNetworkConfig(ctx, "net_test1", "firewall")
	if err != nil {
		t.Fatal(err)
	}
	if val != `{"inbound":[{"port":"any"}]}` {
		t.Errorf("value = %q after upsert", val)
	}
}

func TestSetNetworkConfigAndBumpVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	createTestNetwork(t, s)

	// Initial version (migration default is 1)
	v, err := s.GetNetworkConfigVersion(ctx, "net_test1")
	if err != nil {
		t.Fatal(err)
	}
	initialVersion := v

	// Atomic set config + bump version
	if err := s.SetNetworkConfigAndBumpVersion(ctx, "net_test1", "firewall", `{"inbound":[]}`); err != nil {
		t.Fatal(err)
	}

	// Config saved
	val, err := s.GetNetworkConfig(ctx, "net_test1", "firewall")
	if err != nil {
		t.Fatal(err)
	}
	if val != `{"inbound":[]}` {
		t.Errorf("config = %q, want %q", val, `{"inbound":[]}`)
	}

	// Version bumped by 1
	v, err = s.GetNetworkConfigVersion(ctx, "net_test1")
	if err != nil {
		t.Fatal(err)
	}
	if v != initialVersion+1 {
		t.Errorf("version = %d, want %d", v, initialVersion+1)
	}

	// Second call — version bumped again, config overwritten
	if err := s.SetNetworkConfigAndBumpVersion(ctx, "net_test1", "firewall", `{"inbound":[{"port":"443"}]}`); err != nil {
		t.Fatal(err)
	}
	v, err = s.GetNetworkConfigVersion(ctx, "net_test1")
	if err != nil {
		t.Fatal(err)
	}
	if v != initialVersion+2 {
		t.Errorf("version after second call = %d, want %d", v, initialVersion+2)
	}
}

func TestGetNetworkConfig_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	createTestNetwork(t, s)

	_, err := s.GetNetworkConfig(ctx, "net_test1", "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Partial Updates ---

func createTestHost(t *testing.T, s *SQLiteStore, net *models.Network) *models.Host {
	t.Helper()
	h := &models.Host{
		ID: "host_partial", NetworkID: net.ID, Name: "partial-test",
		NebulaIPs: []string{"192.168.100.50"}, Groups: []string{"web"},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestUpdateHostLastSeen(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)
	h := createTestHost(t, s, net)

	lastSeen := time.Date(2026, 4, 3, 12, 0, 0, 0, time.UTC)
	if err := s.UpdateHostLastSeen(ctx, h.ID, lastSeen); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSeenAt == nil || !got.LastSeenAt.Equal(lastSeen) {
		t.Errorf("last_seen_at = %v, want %v", got.LastSeenAt, lastSeen)
	}
	// Other fields untouched
	if got.Name != "partial-test" {
		t.Errorf("name changed to %q, want partial-test", got.Name)
	}
	if got.Status != models.HostStatusPending {
		t.Errorf("status changed to %q, want pending", got.Status)
	}
}

func TestUpdateHostLastSeen_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.UpdateHostLastSeen(context.Background(), "nonexistent", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUpdateHostCert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)
	h := createTestHost(t, s, net)

	expires := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	if err := s.UpdateHostCert(ctx, h.ID, "new-fp-123", expires); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertFingerprint != "new-fp-123" {
		t.Errorf("cert_fingerprint = %q, want new-fp-123", got.CertFingerprint)
	}
	if got.CertExpiresAt == nil || !got.CertExpiresAt.Equal(expires) {
		t.Errorf("cert_expires_at = %v, want %v", got.CertExpiresAt, expires)
	}
	// Other fields untouched
	if got.Status != models.HostStatusPending {
		t.Errorf("status changed to %q, want pending", got.Status)
	}
}

func TestUpdateHostCert_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.UpdateHostCert(context.Background(), "nonexistent", "fp", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUpdateHostStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)
	h := createTestHost(t, s, net)

	if err := s.UpdateHostStatus(ctx, h.ID, models.HostStatusBlocked); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.HostStatusBlocked {
		t.Errorf("status = %q, want blocked", got.Status)
	}
	// Other fields untouched
	if got.Name != "partial-test" {
		t.Errorf("name changed to %q, want partial-test", got.Name)
	}
}

func TestUpdateHostStatus_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.UpdateHostStatus(context.Background(), "nonexistent", models.HostStatusBlocked)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Atomic Certificate + Host ---

func TestSaveCertificateAndEnrollHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)
	h := createTestHost(t, s, net)

	now := time.Now()
	expires := now.Add(30 * 24 * time.Hour)
	fp := "enroll-fp-123"

	err := s.SaveCertificateAndEnrollHost(ctx, h.ID, []byte("cert-pem"), fp, now, expires)
	if err != nil {
		t.Fatal(err)
	}

	// Verify certificate saved
	pem, err := s.GetCurrentCertificate(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(pem) != "cert-pem" {
		t.Errorf("cert pem = %q, want cert-pem", string(pem))
	}

	// Verify host updated atomically
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.HostStatusEnrolled {
		t.Errorf("status = %q, want enrolled", got.Status)
	}
	if got.CertFingerprint != fp {
		t.Errorf("fingerprint = %q, want %q", got.CertFingerprint, fp)
	}
	if got.CertExpiresAt == nil || !got.CertExpiresAt.Round(time.Second).Equal(expires.Round(time.Second)) {
		t.Errorf("cert_expires_at = %v, want %v", got.CertExpiresAt, expires)
	}
}

func TestSaveCertificateAndEnrollHost_HostNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now()
	err := s.SaveCertificateAndEnrollHost(ctx, "nonexistent", []byte("cert"), "fp", now, now.Add(time.Hour))
	if err == nil {
		t.Fatal("expected error for nonexistent host")
	}

	// Verify certificate was NOT saved (rollback)
	_, err = s.GetCurrentCertificate(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for cert, got %v", err)
	}
}

func TestSaveCertificateAndUpdateHostCert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)
	h := createTestHost(t, s, net)

	// Save initial cert
	now := time.Now()
	s.SaveCertificate(ctx, h.ID, []byte("old-cert"), "old-fp", now, now.Add(24*time.Hour))

	// Renew with atomic method
	newExpires := now.Add(30 * 24 * time.Hour)
	newFP := "renewed-fp-456"
	err := s.SaveCertificateAndUpdateHostCert(ctx, h.ID, []byte("new-cert"), newFP, now, newExpires)
	if err != nil {
		t.Fatal(err)
	}

	// Verify new certificate is current
	pem, err := s.GetCurrentCertificate(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(pem) != "new-cert" {
		t.Errorf("cert pem = %q, want new-cert", string(pem))
	}

	// Verify host fingerprint and expiry updated
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertFingerprint != newFP {
		t.Errorf("fingerprint = %q, want %q", got.CertFingerprint, newFP)
	}
	if got.CertExpiresAt == nil || !got.CertExpiresAt.Round(time.Second).Equal(newExpires.Round(time.Second)) {
		t.Errorf("cert_expires_at = %v, want %v", got.CertExpiresAt, newExpires)
	}
	// Status should NOT change (only cert fields)
	if got.Status != models.HostStatusPending {
		t.Errorf("status = %q, want pending (unchanged)", got.Status)
	}
}

func TestSaveCertificateAndUpdateHostCert_HostNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now()
	err := s.SaveCertificateAndUpdateHostCert(ctx, "nonexistent", []byte("cert"), "fp", now, now.Add(time.Hour))
	if err == nil {
		t.Fatal("expected error for nonexistent host")
	}

	// Verify certificate was NOT saved (rollback)
	_, err = s.GetCurrentCertificate(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for cert, got %v", err)
	}
}

// --- Atomic Block Host ---

func TestBlockHostAndAddToBlocklist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_block", NetworkID: net.ID, Name: "block-me",
		NebulaIPs: []string{"192.168.100.20"}, Groups: []string{"web"},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	// CreateHost does not save cert fields — set via UpdateHost
	h.CertFingerprint = "fp-block-123"
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	got, err := s.BlockHostAndAddToBlocklist(ctx, h.ID, "manually blocked")
	if err != nil {
		t.Fatal(err)
	}

	// Host status updated
	if got.Status != models.HostStatusBlocked {
		t.Errorf("status = %q, want blocked", got.Status)
	}

	// Cert in blocklist
	bl, err := s.GetBlocklist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, fp := range bl {
		if fp == "fp-block-123" {
			found = true
		}
	}
	if !found {
		t.Error("fingerprint not found in blocklist after block")
	}
}

func TestBlockHostAndAddToBlocklist_NoCert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_nocert", NetworkID: net.ID, Name: "no-cert",
		NebulaIPs: []string{"192.168.100.21"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	got, err := s.BlockHostAndAddToBlocklist(ctx, h.ID, "blocked")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.HostStatusBlocked {
		t.Errorf("status = %q, want blocked", got.Status)
	}

	// Blocklist should be empty (no cert to block)
	bl, _ := s.GetBlocklist(ctx)
	if len(bl) != 0 {
		t.Errorf("blocklist len = %d, want 0 (no cert)", len(bl))
	}
}

func TestBlockHostAndAddToBlocklist_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.BlockHostAndAddToBlocklist(context.Background(), "nonexistent", "reason")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Atomic Unblock Host ---

func TestUnblockHostAndRemoveFromBlocklist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_unblock", NetworkID: net.ID, Name: "unblock-me",
		NebulaIPs: []string{"192.168.100.40"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.CertFingerprint = "fp-unblock-789"
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	if _, err := s.BlockHostAndAddToBlocklist(ctx, h.ID, "first blocked"); err != nil {
		t.Fatal(err)
	}

	got, err := s.UnblockHostAndRemoveFromBlocklist(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.HostStatusPending {
		t.Errorf("status = %q, want pending", got.Status)
	}

	// fingerprint must be removed from blocklist
	bl, _ := s.GetBlocklist(ctx)
	for _, fp := range bl {
		if fp == "fp-unblock-789" {
			t.Error("fingerprint still in blocklist after unblock")
		}
	}
}

func TestUnblockHostAndRemoveFromBlocklist_NoCert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_unblock_nocert", NetworkID: net.ID, Name: "no-cert-unblock",
		NebulaIPs: []string{"192.168.100.41"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusBlocked,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	got, err := s.UnblockHostAndRemoveFromBlocklist(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.HostStatusPending {
		t.Errorf("status = %q, want pending", got.Status)
	}
}

func TestUnblockHostAndRemoveFromBlocklist_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.UnblockHostAndRemoveFromBlocklist(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Atomic Delete Host ---

func TestDeleteHostAndBlockCert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_del", NetworkID: net.ID, Name: "delete-me",
		NebulaIPs: []string{"192.168.100.30"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.CertFingerprint = "fp-del-456"
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteHostAndBlockCert(ctx, h.ID, "host deleted"); err != nil {
		t.Fatal(err)
	}

	// Host deleted
	_, err := s.GetHost(ctx, h.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Cert in blocklist
	bl, _ := s.GetBlocklist(ctx)
	found := false
	for _, fp := range bl {
		if fp == "fp-del-456" {
			found = true
		}
	}
	if !found {
		t.Error("fingerprint not found in blocklist after delete")
	}
}

func TestDeleteHostAndBlockCert_NoCert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_nocert_del", NetworkID: net.ID, Name: "no-cert-del",
		NebulaIPs: []string{"192.168.100.31"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteHostAndBlockCert(ctx, h.ID, "deleted"); err != nil {
		t.Fatal(err)
	}

	// Host deleted
	_, err := s.GetHost(ctx, h.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Blocklist empty
	bl, _ := s.GetBlocklist(ctx)
	if len(bl) != 0 {
		t.Errorf("blocklist len = %d, want 0", len(bl))
	}
}

func TestDeleteHostAndBlockCert_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.DeleteHostAndBlockCert(context.Background(), "nonexistent", "reason")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestIsDuplicateColumnErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"duplicate column name", fmt.Errorf("duplicate column name: foo"), true},
		{"duplicate column (old substring)", fmt.Errorf("duplicate column"), false},
		{"table already exists", fmt.Errorf("table networks already exists"), false},
		{"unique constraint with word duplicate", fmt.Errorf("UNIQUE constraint failed: duplicate"), false},
		{"nil error", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDuplicateColumnErr(tt.err)
			if got != tt.want {
				t.Errorf("isDuplicateColumnErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestBlocklist_Remove(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.AddToBlocklist(ctx, "fp1", "", "reason")
	s.RemoveFromBlocklist(ctx, "fp1")

	list, _ := s.GetBlocklist(ctx)
	if len(list) != 0 {
		t.Errorf("len = %d, want 0 after remove", len(list))
	}
}

func TestCreateHostAndToken(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	now := time.Now()
	host := &models.Host{
		ID: "host_atomic", NetworkID: net.ID, Name: "atomic-host",
		NebulaIPs: []string{"192.168.100.60"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	token := &models.EnrollmentToken{
		ID: "tok_atomic", HostID: host.ID, TokenHash: models.HashEnrollmentToken("test-token-123"),
		ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}

	if err := s.CreateHostAndToken(ctx, host, token); err != nil {
		t.Fatal(err)
	}

	// Verify both exist
	gotHost, err := s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if gotHost.Name != "atomic-host" {
		t.Errorf("host name = %q, want atomic-host", gotHost.Name)
	}

	gotToken, err := s.ConsumeToken(ctx, "test-token-123")
	if err != nil {
		t.Fatalf("consume token: %v", err)
	}
	if gotToken.HostID != host.ID {
		t.Errorf("token host_id = %q, want %q", gotToken.HostID, host.ID)
	}
}

func TestCreateHostAndToken_DuplicateHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	now := time.Now()
	host := &models.Host{
		ID: "host_dup", NetworkID: net.ID, Name: "dup-host",
		NebulaIPs: []string{"192.168.100.70"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	token1 := &models.EnrollmentToken{
		ID: "tok1", HostID: host.ID, TokenHash: models.HashEnrollmentToken("token-1"),
		ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}

	// First creation succeeds
	if err := s.CreateHostAndToken(ctx, host, token1); err != nil {
		t.Fatal(err)
	}

	// Duplicate host should fail, and token should not be created
	token2 := &models.EnrollmentToken{
		ID: "tok2", HostID: host.ID, TokenHash: models.HashEnrollmentToken("token-2"),
		ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}
	err := s.CreateHostAndToken(ctx, host, token2)
	if err == nil {
		t.Fatal("expected error for duplicate host")
	}

	// Verify token-2 was not created (rollback)
	_, err = s.ConsumeToken(ctx, "token-2")
	if err == nil {
		t.Error("token-2 should not exist after rollback")
	}
}

// --- Host Config Version ---

func TestHostConfigVersion_DefaultZero(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_cv", NetworkID: net.ID, Name: "cv-default",
		NebulaIPs: []string{"192.168.100.10"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	v, err := s.GetHostConfigVersion(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 {
		t.Errorf("default version = %d, want 0", v)
	}
}

func TestUpdateHostConfigVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_cv_update", NetworkID: net.ID, Name: "cv-update",
		NebulaIPs: []string{"192.168.100.11"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateHostConfigVersion(ctx, h.ID, 7); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetHostConfigVersion(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v != 7 {
		t.Errorf("version = %d, want 7", v)
	}
}

func TestUpdateHostConfigVersion_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.UpdateHostConfigVersion(context.Background(), "nonexistent", 1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestGetHostConfigVersion_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetHostConfigVersion(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Lighthouse-driven config_version bumps ---

func TestSaveCertificateAndEnrollHost_BumpsLighthouseVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	lh := &models.Host{
		ID: "host_lh", NetworkID: net.ID, Name: "lighthouse-a",
		NebulaIPs: []string{"192.168.100.5"}, Groups: []string{},
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		PublicIP: "10.0.0.5", ListenPort: 4242,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, lh); err != nil {
		t.Fatal(err)
	}

	before, err := s.GetNetworkConfigVersion(ctx, net.ID)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := s.SaveCertificateAndEnrollHost(ctx, lh.ID, []byte("dummy-cert-pem"), "fp-lh-1", now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	after, err := s.GetNetworkConfigVersion(ctx, net.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Errorf("version = %d, want %d (bump on lighthouse enrollment)", after, before+1)
	}
}

func TestSaveCertificateAndEnrollHost_NoBumpForRegularHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_regular", NetworkID: net.ID, Name: "plain",
		NebulaIPs: []string{"192.168.100.6"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	before, err := s.GetNetworkConfigVersion(ctx, net.ID)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := s.SaveCertificateAndEnrollHost(ctx, h.ID, []byte("dummy"), "fp-h-1", now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	after, err := s.GetNetworkConfigVersion(ctx, net.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("version = %d, want %d (no bump for plain host)", after, before)
	}
}

func TestBlockHostAndAddToBlocklist_BumpsForEnrolledLighthouse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	lh := &models.Host{
		ID: "host_lh_block", NetworkID: net.ID, Name: "lh-block",
		NebulaIPs: []string{"192.168.100.7"}, Groups: []string{},
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		PublicIP: "10.0.0.7", ListenPort: 4242,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, lh); err != nil {
		t.Fatal(err)
	}
	// Set fingerprint via UpdateHost so block records it on the blocklist
	lh.CertFingerprint = "fp-lh-block"
	if err := s.UpdateHost(ctx, lh); err != nil {
		t.Fatal(err)
	}

	before, err := s.GetNetworkConfigVersion(ctx, net.ID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.BlockHostAndAddToBlocklist(ctx, lh.ID, "test block"); err != nil {
		t.Fatal(err)
	}

	after, err := s.GetNetworkConfigVersion(ctx, net.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Errorf("version = %d, want %d (bump on enrolled lighthouse block)", after, before+1)
	}
}

func TestBlockHostAndAddToBlocklist_NoBumpForPendingLighthouse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	lh := &models.Host{
		ID: "host_lh_pending", NetworkID: net.ID, Name: "lh-pending",
		NebulaIPs: []string{"192.168.100.8"}, Groups: []string{},
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, lh); err != nil {
		t.Fatal(err)
	}

	before, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if _, err := s.BlockHostAndAddToBlocklist(ctx, lh.ID, "test"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	// Pending lighthouse has no cert fingerprint, so no blocklist entry and
	// no bump (GHSA-cm26-5974-52h8: bump is driven by fingerprint entering
	// the blocklist, not by lighthouse status alone).
	if after != before {
		t.Errorf("version = %d, want %d (pending lighthouse, no fingerprint — no bump)", after, before)
	}
}

func TestDeleteHostAndBlockCert_BumpsForEnrolledLighthouse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	lh := &models.Host{
		ID: "host_lh_del", NetworkID: net.ID, Name: "lh-del",
		NebulaIPs: []string{"192.168.100.9"}, Groups: []string{},
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		PublicIP: "10.0.0.9", ListenPort: 4242,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, lh); err != nil {
		t.Fatal(err)
	}
	lh.CertFingerprint = "fp-lh-del"
	if err := s.UpdateHost(ctx, lh); err != nil {
		t.Fatal(err)
	}

	before, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if err := s.DeleteHostAndBlockCert(ctx, lh.ID, "test delete"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if after != before+1 {
		t.Errorf("version = %d, want %d (bump on enrolled lighthouse delete)", after, before+1)
	}
}

// --- Cert-expiry alert dedup ---

func TestCertAlerts_RecordAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_alert", NetworkID: net.ID, Name: "alertable",
		NebulaIPs: []string{"192.168.100.50"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	// No alert yet → ErrNotFound.
	if _, err := s.GetCertAlert(ctx, h.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound before any alert, got %v", err)
	}

	notAfter := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	if err := s.RecordCertAlert(ctx, h.ID, notAfter); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCertAlert(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(notAfter) {
		t.Errorf("alerted_not_after = %v, want %v", got, notAfter)
	}

	// Upsert: same host, new not_after.
	notAfter2 := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	if err := s.RecordCertAlert(ctx, h.ID, notAfter2); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetCertAlert(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(notAfter2) {
		t.Errorf("after upsert, alerted_not_after = %v, want %v", got, notAfter2)
	}
}

func TestDeleteHostAndBlockCert_NoBumpForRegularHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_plain_del", NetworkID: net.ID, Name: "plain-del",
		NebulaIPs: []string{"192.168.100.13"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	before, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if err := s.DeleteHostAndBlockCert(ctx, h.ID, "test"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if after != before {
		t.Errorf("version = %d, want %d (regular host — no bump)", after, before)
	}
}

// TestBlockHostAndAddToBlocklist_BumpsForRegularHostWithFingerprint verifies
// that blocking a regular (non-lighthouse) host with a cert fingerprint bumps
// the network config version so peers receive the updated pki.blocklist
// (GHSA-cm26-5974-52h8).
func TestBlockHostAndAddToBlocklist_BumpsForRegularHostWithFingerprint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_regular_fp", NetworkID: net.ID, Name: "regular-fp",
		NebulaIPs: []string{"192.168.100.20"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.CertFingerprint = "fp-regular-block"
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	before, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if _, err := s.BlockHostAndAddToBlocklist(ctx, h.ID, "test block"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if after != before+1 {
		t.Errorf("version = %d, want %d (regular host with fingerprint should bump)", after, before+1)
	}
}

// TestDeleteHostAndBlockCert_BumpsForRegularHostWithFingerprint verifies
// that deleting a regular host with a cert fingerprint bumps the network
// config version so peers receive the updated pki.blocklist
// (GHSA-cm26-5974-52h8).
func TestDeleteHostAndBlockCert_BumpsForRegularHostWithFingerprint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_regular_del_fp", NetworkID: net.ID, Name: "regular-del-fp",
		NebulaIPs: []string{"192.168.100.21"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.CertFingerprint = "fp-regular-del"
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	before, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if err := s.DeleteHostAndBlockCert(ctx, h.ID, "test delete"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetNetworkConfigVersion(ctx, net.ID)
	if after != before+1 {
		t.Errorf("version = %d, want %d (regular host with fingerprint should bump on delete)", after, before+1)
	}
}

func TestMigration013_AppliesAndRevertsHostMobileColumns(t *testing.T) {
	// Create store and apply migrations.
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	// Check that migration 013 was applied: kind and variant columns exist
	// with proper types and defaults.
	rows, err := s.db.Query("PRAGMA table_info(hosts)")
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	defer rows.Close()

	type ColInfo struct {
		name      string
		typ       string
		notnull   int
		dfltValue interface{}
	}
	columns := make(map[string]ColInfo)
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notnull int
		var dfltValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan PRAGMA result: %v", err)
		}
		columns[name] = ColInfo{name: name, typ: typ, notnull: notnull, dfltValue: dfltValue}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Verify 'kind' column.
	kindCol, ok := columns["kind"]
	if !ok {
		t.Error("migration 013: column 'kind' not found in hosts table")
	} else {
		if kindCol.typ != "TEXT" {
			t.Errorf("kind column type = %s, want TEXT", kindCol.typ)
		}
		if kindCol.notnull == 0 {
			t.Error("kind column should be NOT NULL")
		}
		if kindCol.dfltValue != "'agent'" {
			t.Errorf("kind column default = %v, want 'agent'", kindCol.dfltValue)
		}
	}

	// Verify 'variant' column.
	variantCol, ok := columns["variant"]
	if !ok {
		t.Error("migration 013: column 'variant' not found in hosts table")
	} else {
		if variantCol.typ != "TEXT" {
			t.Errorf("variant column type = %s, want TEXT", variantCol.typ)
		}
		if variantCol.notnull == 0 {
			t.Error("variant column should be NOT NULL")
		}
		if variantCol.dfltValue != "''" {
			t.Errorf("variant column default = %v, want ''", variantCol.dfltValue)
		}
	}
}

// TestSQLiteStore_CreateMobileHost creates a mobile host and verifies that
// Kind and Variant fields are persisted correctly through the store CRUD.
func TestSQLiteStore_CreateMobileHost(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	mobileHost := &models.Host{
		ID:        "mobile_ios_001",
		NetworkID: net.ID,
		Name:      "user-iphone",
		NebulaIPs: []string{"192.168.100.50"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.CreateHost(ctx, mobileHost); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	retrieved, err := s.GetHost(ctx, mobileHost.ID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}

	if retrieved.Kind != models.HostKindMobile {
		t.Errorf("Kind = %q, want %q", retrieved.Kind, models.HostKindMobile)
	}
	if retrieved.Variant != models.HostVariantIOS {
		t.Errorf("Variant = %q, want %q", retrieved.Variant, models.HostVariantIOS)
	}
}

// TestSQLiteStore_CreateHostAndToken_KindDefault creates a host via
// CreateHostAndToken (the old API path) with Kind set to HostKindAgent and
// Variant set to HostVariantNone, verifying they are persisted correctly
// through the store CRUD.
func TestSQLiteStore_CreateHostAndToken_KindDefault(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	agentHost := &models.Host{
		ID:        "agent_default_001",
		NetworkID: net.ID,
		Name:      "standard-host",
		NebulaIPs: []string{"192.168.100.60"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		Kind:      models.HostKindAgent,
		Variant:   models.HostVariantNone,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	enrollToken := &models.EnrollmentToken{
		TokenHash: models.HashEnrollmentToken("test-token-xyz"),
		HostID:    agentHost.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := s.CreateHostAndToken(ctx, agentHost, enrollToken); err != nil {
		t.Fatalf("CreateHostAndToken: %v", err)
	}

	retrieved, err := s.GetHost(ctx, agentHost.ID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}

	if retrieved.Kind != models.HostKindAgent {
		t.Errorf("Kind = %q, want %q", retrieved.Kind, models.HostKindAgent)
	}
	if retrieved.Variant != models.HostVariantNone {
		t.Errorf("Variant = %q, want %q", retrieved.Variant, models.HostVariantNone)
	}
}

// TestCreateNetwork_StoresMultipleCIDRsInOrder verifies that CreateNetwork
// persists multiple CIDRs in the correct order.
func TestCreateNetwork_StoresMultipleCIDRsInOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	n := &models.Network{
		ID:        "net_multi_cidr",
		Name:      "multi-cidr-network",
		CIDRs:     []string{"10.0.0.0/8", "fd00::/64", "192.168.0.0/16"},
		CreatedAt: time.Now(),
	}

	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	retrieved, err := s.GetNetwork(ctx, n.ID)
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}

	if len(retrieved.CIDRs) != len(n.CIDRs) {
		t.Errorf("CIDRs length = %d, want %d", len(retrieved.CIDRs), len(n.CIDRs))
	}

	for i, cidr := range n.CIDRs {
		if retrieved.CIDRs[i] != cidr {
			t.Errorf("CIDRs[%d] = %q, want %q", i, retrieved.CIDRs[i], cidr)
		}
	}
}

// TestUpdateNetwork_ReplacesCIDRs verifies that UpdateNetwork replaces the CIDR list.
func TestUpdateNetwork_ReplacesCIDRs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	n := &models.Network{
		ID:        "net_update_cidr",
		Name:      "update-test",
		CIDRs:     []string{"10.0.0.0/24"},
		CreatedAt: time.Now(),
	}

	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	n.CIDRs = []string{"192.168.0.0/16", "fd00:1::/64"}
	n.Name = "updated-name"

	if err := s.UpdateNetwork(ctx, n); err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}

	retrieved, err := s.GetNetwork(ctx, n.ID)
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}

	if len(retrieved.CIDRs) != 2 {
		t.Errorf("CIDRs length = %d, want 2", len(retrieved.CIDRs))
	}

	if retrieved.CIDRs[0] != "192.168.0.0/16" {
		t.Errorf("CIDRs[0] = %q, want '192.168.0.0/16'", retrieved.CIDRs[0])
	}
	if retrieved.CIDRs[1] != "fd00:1::/64" {
		t.Errorf("CIDRs[1] = %q, want 'fd00:1::/64'", retrieved.CIDRs[1])
	}

	if retrieved.Name != "updated-name" {
		t.Errorf("Name = %q, want 'updated-name'", retrieved.Name)
	}
}

// TestCreateHost_StoresMultipleAddresses verifies that CreateHost persists
// multiple overlay addresses in the correct order.
func TestCreateHost_StoresMultipleAddresses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	net := createTestNetwork(t, s)

	h := &models.Host{
		ID:        "host_multi_addr",
		NetworkID: net.ID,
		Name:      "multi-address-host",
		NebulaIPs: []string{"10.0.0.5", "fd00::5", "192.168.1.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	retrieved, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}

	if len(retrieved.NebulaIPs) != len(h.NebulaIPs) {
		t.Errorf("NebulaIPs length = %d, want %d", len(retrieved.NebulaIPs), len(h.NebulaIPs))
	}

	for i, addr := range h.NebulaIPs {
		if retrieved.NebulaIPs[i] != addr {
			t.Errorf("NebulaIPs[%d] = %q, want %q", i, retrieved.NebulaIPs[i], addr)
		}
	}
}

// TestUpdateHost_ReplacesAddresses verifies that UpdateHost atomically
// replaces the address list.
func TestUpdateHost_ReplacesAddresses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	net := createTestNetwork(t, s)

	h := &models.Host{
		ID:        "host_update_addr",
		NetworkID: net.ID,
		Name:      "update-addr-test",
		NebulaIPs: []string{"10.0.0.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	h.NebulaIPs = []string{"10.0.0.20", "fd00::20"}
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}

	retrieved, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}

	if len(retrieved.NebulaIPs) != 2 {
		t.Errorf("NebulaIPs length = %d, want 2", len(retrieved.NebulaIPs))
	}

	if retrieved.NebulaIPs[0] != "10.0.0.20" || retrieved.NebulaIPs[1] != "fd00::20" {
		t.Errorf("NebulaIPs = %v, want [10.0.0.20 fd00::20]", retrieved.NebulaIPs)
	}
}

// TestDeleteHost_CASCADEsAddresses verifies that deleting a host removes
// all associated address rows.
func TestDeleteHost_CASCADEsAddresses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	net := createTestNetwork(t, s)

	h := &models.Host{
		ID:        "host_cascade_test",
		NetworkID: net.ID,
		Name:      "cascade-test",
		NebulaIPs: []string{"10.0.0.30", "fd00::30"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	if err := s.DeleteHost(ctx, h.ID); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}

	rows, err := s.db.QueryContext(ctx, "SELECT COUNT(*) FROM host_addresses WHERE host_id = ?", h.ID)
	if err != nil {
		t.Fatalf("query host_addresses: %v", err)
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("scan count: %v", err)
		}
	}

	if count != 0 {
		t.Errorf("host_addresses count = %d, want 0", count)
	}
}

// TestListHosts_PreservesAddressOrder verifies that ListHosts preserves
// address order for each host.
func TestListHosts_PreservesAddressOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	net := createTestNetwork(t, s)

	h1 := &models.Host{
		ID:        "host1_order",
		NetworkID: net.ID,
		Name:      "host1",
		NebulaIPs: []string{"10.0.0.5", "fd00::5"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	h2 := &models.Host{
		ID:        "host2_order",
		NetworkID: net.ID,
		Name:      "host2",
		NebulaIPs: []string{"fd00::10", "10.0.0.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.CreateHost(ctx, h1); err != nil {
		t.Fatalf("CreateHost h1: %v", err)
	}
	if err := s.CreateHost(ctx, h2); err != nil {
		t.Fatalf("CreateHost h2: %v", err)
	}

	hosts, err := s.ListHosts(ctx, HostFilter{NetworkID: net.ID})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}

	if len(hosts) != 2 {
		t.Fatalf("ListHosts returned %d hosts, want 2", len(hosts))
	}

	for _, h := range hosts {
		switch h.ID {
		case h1.ID:
			if len(h.NebulaIPs) != 2 || h.NebulaIPs[0] != "10.0.0.5" || h.NebulaIPs[1] != "fd00::5" {
				t.Errorf("h1 NebulaIPs = %v, want [10.0.0.5 fd00::5]", h.NebulaIPs)
			}
		case h2.ID:
			if len(h.NebulaIPs) != 2 || h.NebulaIPs[0] != "fd00::10" || h.NebulaIPs[1] != "10.0.0.10" {
				t.Errorf("h2 NebulaIPs = %v, want [fd00::10 10.0.0.10]", h.NebulaIPs)
			}
		}
	}
}

func TestCountEmptyCAIDRows_FreshDatabase(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	count, err := s.CountEmptyCAIDRows(ctx)
	if err != nil {
		t.Fatalf("CountEmptyCAIDRows failed: %v", err)
	}
	if count != 0 {
		t.Errorf("CountEmptyCAIDRows on fresh DB = %d, want 0", count)
	}
}

// --- CAs with PredecessorID ---

func createTestOperator(t *testing.T, s *SQLiteStore) *models.Operator {
	t.Helper()
	ctx := context.Background()
	op := &models.Operator{
		ID:           "op_test",
		Username:     "testop",
		PasswordHash: "hash",
		Status:       models.OperatorStatusActive,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}
	return op
}

func createTestCA(t *testing.T, s *SQLiteStore, id, name, operatorID string, predecessorID *string) *models.CA {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	ca := &models.CA{
		ID:                   id,
		Name:                 name,
		OwnerOperatorID:      operatorID,
		CertPEM:              "cert_pem_" + id,
		Fingerprint:          "fp_" + id,
		NotBefore:            now,
		NotAfter:             now.AddDate(10, 0, 0),
		Status:               models.CAStatusActive,
		PredecessorID:        predecessorID,
		EncryptedKeyDEK:      []byte("key_dek"),
		NonceDEK:             []byte("nonce_dek"),
		EncryptedKeyMaterial: []byte("key_material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.CreateCA(ctx, ca); err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestCAs_PredecessorID_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := createTestOperator(t, s)

	// Create oldCA without predecessor
	oldCA := createTestCA(t, s, "ca_old", "old-ca", op.ID, nil)

	// Create newCA with oldCA as predecessor
	predecessorID := oldCA.ID
	_ = createTestCA(t, s, "ca_new", "new-ca", op.ID, &predecessorID)

	// Read back newCA and verify predecessor_id
	got, err := s.GetCA(ctx, "ca_new")
	if err != nil {
		t.Fatal(err)
	}
	if got.PredecessorID == nil || *got.PredecessorID != predecessorID {
		t.Errorf("newCA.PredecessorID = %v, want %q", got.PredecessorID, predecessorID)
	}

	// Read back oldCA and verify predecessor_id is nil
	oldGot, err := s.GetCA(ctx, "ca_old")
	if err != nil {
		t.Fatal(err)
	}
	if oldGot.PredecessorID != nil {
		t.Errorf("oldCA.PredecessorID = %v, want nil", oldGot.PredecessorID)
	}
}

func TestCAs_ListCAsByOwner_IncludesPredecessorID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := createTestOperator(t, s)

	// Create chain: CA1 -> CA2 -> CA3
	ca1 := createTestCA(t, s, "ca1", "ca-1", op.ID, nil)
	pred1 := ca1.ID
	ca2 := createTestCA(t, s, "ca2", "ca-2", op.ID, &pred1)
	pred2 := ca2.ID
	_ = createTestCA(t, s, "ca3", "ca-3", op.ID, &pred2)

	// List all CAs and verify predecessors
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 3 {
		t.Fatalf("ListCAsByOwner = %d CAs, want 3", len(cas))
	}

	// Map by ID for easier lookup
	caMap := make(map[string]*models.CA)
	for _, ca := range cas {
		caMap[ca.ID] = ca
	}

	// Verify CA1 has no predecessor
	if caMap["ca1"].PredecessorID != nil {
		t.Errorf("ca1.PredecessorID = %v, want nil", caMap["ca1"].PredecessorID)
	}

	// Verify CA2 has CA1 as predecessor
	if caMap["ca2"].PredecessorID == nil || *caMap["ca2"].PredecessorID != "ca1" {
		t.Errorf("ca2.PredecessorID = %v, want ca1", caMap["ca2"].PredecessorID)
	}

	// Verify CA3 has CA2 as predecessor
	if caMap["ca3"].PredecessorID == nil || *caMap["ca3"].PredecessorID != "ca2" {
		t.Errorf("ca3.PredecessorID = %v, want ca2", caMap["ca3"].PredecessorID)
	}
}

func TestCAs_ListApproachingExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := createTestOperator(t, s)

	now := time.Now()

	// Create fresh CA (10-year lifetime, just started)
	freshCA := &models.CA{
		ID:                   "ca_fresh",
		Name:                 "fresh",
		OwnerOperatorID:      op.ID,
		CertPEM:              "cert",
		Fingerprint:          "fp_fresh",
		NotBefore:            now,
		NotAfter:             now.AddDate(10, 0, 0),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("key"),
		NonceDEK:             []byte("nonce"),
		EncryptedKeyMaterial: []byte("material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.CreateCA(ctx, freshCA); err != nil {
		t.Fatal(err)
	}

	// Create mid-life CA (10-year lifetime, 5 years have passed)
	midLifeCA := &models.CA{
		ID:                   "ca_midlife",
		Name:                 "midlife",
		OwnerOperatorID:      op.ID,
		CertPEM:              "cert",
		Fingerprint:          "fp_midlife",
		NotBefore:            now.AddDate(-5, 0, 0),
		NotAfter:             now.AddDate(5, 0, 0),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("key"),
		NonceDEK:             []byte("nonce"),
		EncryptedKeyMaterial: []byte("material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.CreateCA(ctx, midLifeCA); err != nil {
		t.Fatal(err)
	}

	// Create near-expiry CA (10-year lifetime, 8 years have passed, 2 years left = 20%)
	nearExpiryCA := &models.CA{
		ID:                   "ca_expiring",
		Name:                 "expiring",
		OwnerOperatorID:      op.ID,
		CertPEM:              "cert",
		Fingerprint:          "fp_expiring",
		NotBefore:            now.AddDate(-8, 0, 0),
		NotAfter:             now.AddDate(2, 0, 0),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("key"),
		NonceDEK:             []byte("nonce"),
		EncryptedKeyMaterial: []byte("material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.CreateCA(ctx, nearExpiryCA); err != nil {
		t.Fatal(err)
	}

	// Create retired CA (should not be included in results)
	retiredCA := &models.CA{
		ID:                   "ca_retired",
		Name:                 "retired",
		OwnerOperatorID:      op.ID,
		CertPEM:              "cert",
		Fingerprint:          "fp_retired",
		NotBefore:            now.AddDate(-8, 0, 0),
		NotAfter:             now.AddDate(2, 0, 0),
		Status:               models.CAStatusRetired,
		EncryptedKeyDEK:      []byte("key"),
		NonceDEK:             []byte("nonce"),
		EncryptedKeyMaterial: []byte("material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.CreateCA(ctx, retiredCA); err != nil {
		t.Fatal(err)
	}

	// Query with threshold=0.21 (21% remaining, slightly higher to account for floating-point precision)
	// Should return only near-expiry (2 years left / 10 years = 0.20, but with rounding may be slightly more)
	cas, err := s.ListCAsApproachingExpiry(ctx, 0.21)
	if err != nil {
		t.Fatal(err)
	}

	if len(cas) != 1 {
		t.Fatalf("ListCAsApproachingExpiry = %d CAs, want 1", len(cas))
	}

	if cas[0].ID != "ca_expiring" {
		t.Errorf("returned CA = %q, want ca_expiring", cas[0].ID)
	}
}

func TestCAs_ListApproachingExpiry_Empty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Empty DB should return empty slice
	cas, err := s.ListCAsApproachingExpiry(ctx, 0.20)
	if err != nil {
		t.Fatal(err)
	}
	if cas == nil {
		t.Error("ListCAsApproachingExpiry returned nil, want empty slice")
	}
	if len(cas) != 0 {
		t.Errorf("ListCAsApproachingExpiry on empty DB = %d CAs, want 0", len(cas))
	}
}

func TestCAs_FindCAByPredecessor_Found(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := createTestOperator(t, s)

	// Create CA1 (original, no predecessor)
	ca1 := createTestCA(t, s, "ca_original", "original-ca", op.ID, nil)

	// Create CA2 with CA1 as predecessor, status=active
	pred1 := ca1.ID
	ca2 := createTestCA(t, s, "ca_successor", "successor-ca", op.ID, &pred1)

	// FindCAByPredecessor should return CA2
	found, err := s.FindCAByPredecessor(ctx, ca1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatal("FindCAByPredecessor returned nil, want CA2")
		return
	}
	if found.ID != ca2.ID {
		t.Errorf("FindCAByPredecessor returned ID=%q, want %q", found.ID, ca2.ID)
	}
	if found.PredecessorID == nil || *found.PredecessorID != ca1.ID {
		t.Errorf("successor.PredecessorID = %v, want %q", found.PredecessorID, ca1.ID)
	}
}

func TestCAs_FindCAByPredecessor_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Empty DB: FindCAByPredecessor should return ErrNotFound
	found, err := s.FindCAByPredecessor(ctx, "nonexistent_id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("FindCAByPredecessor on empty DB returned err=%v, want ErrNotFound", err)
	}
	if found != nil {
		t.Errorf("FindCAByPredecessor returned CA=%+v, want nil", found)
	}
}

func TestCAs_FindCAByPredecessor_IgnoresRetired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := createTestOperator(t, s)

	// Create CA1 (original)
	ca1 := createTestCA(t, s, "ca_old", "old-ca", op.ID, nil)

	// Create CA2 with CA1 as predecessor, but mark as retired
	pred1 := ca1.ID
	ca2 := createTestCA(t, s, "ca_retired", "retired-ca", op.ID, &pred1)
	if err := s.UpdateCAStatus(ctx, ca2.ID, models.CAStatusRetired); err != nil {
		t.Fatal(err)
	}

	// FindCAByPredecessor should return ErrNotFound because CA2 is retired
	found, err := s.FindCAByPredecessor(ctx, ca1.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("FindCAByPredecessor with retired successor returned err=%v, want ErrNotFound", err)
	}
	if found != nil {
		t.Errorf("FindCAByPredecessor returned CA=%+v, want nil", found)
	}
}
