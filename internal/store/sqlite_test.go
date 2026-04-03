package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/juev/nebula-mgmt/internal/models"
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
		CIDR:      "192.168.100.0/24",
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
		CIDR:      "10.0.0.0/16",
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
	if got.CIDR != "10.0.0.0/16" {
		t.Errorf("cidr = %q, want %q", got.CIDR, "10.0.0.0/16")
	}
}

func TestGetNetwork_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetNetwork(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListNetworks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, name := range []string{"beta", "alpha"} {
		n := &models.Network{ID: "net_" + name, Name: name, CIDR: "10.0.0.0/24", CreatedAt: time.Now()}
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
		NebulaIP:  "192.168.100.10",
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
			NebulaIP: fmt.Sprintf("192.168.100.%d", 10+i),
			Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
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
			Name:     fmt.Sprintf("host-%d", i),
			NebulaIP: fmt.Sprintf("192.168.100.%d", 10+i),
			Groups:   []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
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
		ID: "host_1", NetworkID: net.ID, Name: "web", NebulaIP: "192.168.100.10",
		Groups: []string{"web"}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	h2 := &models.Host{
		ID: "host_2", NetworkID: net.ID, Name: "db", NebulaIP: "192.168.100.11",
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
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIP: "192.168.100.10",
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
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIP: "192.168.100.10",
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
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Tokens ---

func TestConsumeToken_Success(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIP: "192.168.100.10",
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	tok := &models.EnrollmentToken{
		ID: "tok_1", HostID: "host_1", Token: "secret-token",
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
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIP: "192.168.100.10",
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.CreateHost(ctx, h)

	tok := &models.EnrollmentToken{
		ID: "tok_1", HostID: "host_1", Token: "one-time",
		ExpiresAt: time.Now().Add(1 * time.Hour), CreatedAt: time.Now(),
	}
	s.CreateToken(ctx, tok)
	s.ConsumeToken(ctx, "one-time")

	_, err := s.ConsumeToken(ctx, "one-time")
	if err != ErrTokenUsed {
		t.Fatalf("err = %v, want ErrTokenUsed", err)
	}
}

func TestConsumeToken_Expired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIP: "192.168.100.10",
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.CreateHost(ctx, h)

	tok := &models.EnrollmentToken{
		ID: "tok_1", HostID: "host_1", Token: "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour), CreatedAt: time.Now(),
	}
	s.CreateToken(ctx, tok)

	_, err := s.ConsumeToken(ctx, "expired-token")
	if err != ErrTokenExpired {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

func TestConsumeToken_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.ConsumeToken(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Certificates ---

func TestSaveAndGetCertificate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIP: "192.168.100.10",
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
		ID: "host_1", NetworkID: net.ID, Name: "test", NebulaIP: "192.168.100.10",
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
		ID: "nonexistent", Name: "ghost", NebulaIP: "10.0.0.1",
		Groups: []string{}, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	err := s.UpdateHost(ctx, h)
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteHost_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.DeleteHost(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListHosts_GroupFilterSpecialChars(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	// Host with group containing percent sign
	h1 := &models.Host{
		ID: "host_1", NetworkID: net.ID, Name: "special", NebulaIP: "192.168.100.10",
		Groups: []string{"50%off"}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	h2 := &models.Host{
		ID: "host_2", NetworkID: net.ID, Name: "normal", NebulaIP: "192.168.100.11",
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
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- Partial Updates ---

func createTestHost(t *testing.T, s *SQLiteStore, net *models.Network) *models.Host {
	t.Helper()
	h := &models.Host{
		ID: "host_partial", NetworkID: net.ID, Name: "partial-test",
		NebulaIP: "192.168.100.50", Groups: []string{"web"},
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
	if err != ErrNotFound {
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
	if err != ErrNotFound {
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
	if err != ErrNotFound {
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
	if err != ErrNotFound {
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
	if err != ErrNotFound {
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
		NebulaIP: "192.168.100.20", Groups: []string{"web"},
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
		NebulaIP: "192.168.100.21", Groups: []string{},
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
	if err != ErrNotFound {
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
		NebulaIP: "192.168.100.30", Groups: []string{},
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
	if err != ErrNotFound {
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
		NebulaIP: "192.168.100.31", Groups: []string{},
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
	if err != ErrNotFound {
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
	if err != ErrNotFound {
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
		NebulaIP: "192.168.100.60", Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	token := &models.EnrollmentToken{
		ID: "tok_atomic", HostID: host.ID, Token: "test-token-123",
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
		NebulaIP: "192.168.100.70", Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	token1 := &models.EnrollmentToken{
		ID: "tok1", HostID: host.ID, Token: "token-1",
		ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}

	// First creation succeeds
	if err := s.CreateHostAndToken(ctx, host, token1); err != nil {
		t.Fatal(err)
	}

	// Duplicate host should fail, and token should not be created
	token2 := &models.EnrollmentToken{
		ID: "tok2", HostID: host.ID, Token: "token-2",
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
