package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// EnrollmentResult holds the response from enrolling a host.
type EnrollmentResult struct {
	CertificatePEM   string
	CACertificatePEM string
	ConfigYAML       string
}

// enrollHostForPoll is a helper that creates a host, enrolls it, and returns the host,
// enrollment response, and signing private key needed for polling.
func enrollHostForPoll(t *testing.T, ts *httptest.Server, s *store.SQLiteStore, networkID, hostName, nebulaIP string) (*models.Host, EnrollmentResult, ed25519.PrivateKey) {
	t.Helper()

	// Create host
	resp := apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id": networkID,
		"name":       hostName,
		"nebula_ips": []string{nebulaIP},
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create host: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var hostResp struct {
		Host            *models.Host `json:"host"`
		EnrollmentToken string       `json:"enrollment_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hostResp); err != nil {
		t.Fatalf("decode host: %v", err)
	}
	resp.Body.Close()

	// Enroll host
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)
	_, signingPriv, signingPubPEM := signingKeypair(t)

	enrollReq := map[string]string{
		"token":                  hostResp.EnrollmentToken,
		"public_key_pem":         string(pubKeyPEM),
		"signing_public_key_pem": signingPubPEM,
	}
	data, _ := json.Marshal(enrollReq)
	enrollResp, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if enrollResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(enrollResp.Body)
		t.Fatalf("enroll: HTTP %d: %s", enrollResp.StatusCode, string(body))
	}
	var enrollResult struct {
		CertificatePEM   string `json:"certificate_pem"`
		CACertificatePEM string `json:"ca_certificate_pem"`
		ConfigYAML       string `json:"config_yaml"`
	}
	if err := json.NewDecoder(enrollResp.Body).Decode(&enrollResult); err != nil {
		t.Fatalf("decode enrollment: %v", err)
	}
	enrollResp.Body.Close()

	return hostResp.Host, EnrollmentResult{
		CertificatePEM:   enrollResult.CertificatePEM,
		CACertificatePEM: enrollResult.CACertificatePEM,
		ConfigYAML:       enrollResult.ConfigYAML,
	}, signingPriv
}

// TestE2E_EditHostAdvanced_TriggersConfigUpdate tests that editing host advanced
// settings (MTU) triggers a config update in the next agent poll.
func TestE2E_EditHostAdvanced_TriggersConfigUpdate(t *testing.T) {
	ts, s, _ := setupE2E(t)

	// 1. Create network
	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]any{
		"name":  "e2e-edit-net",
		"cidrs": []string{"192.168.100.0/24"},
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create network: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var network models.Network
	if err := json.NewDecoder(resp.Body).Decode(&network); err != nil {
		t.Fatalf("decode network: %v", err)
	}
	resp.Body.Close()

	// 2. Enroll a host
	host, enrollResult, signingPriv := enrollHostForPoll(t, ts, s, network.ID, "test-host", "192.168.100.10")
	t.Logf("host enrolled: %s (ID: %s)", host.Name, host.ID)

	// Parse cert to get fingerprint
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResult.CertificatePEM))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	fp, _ := hostCert.Fingerprint()

	// 3. First poll (sanity check) — should have HasUpdates=false (config is synced at enrollment)
	t.Log("First poll (sanity check)")
	pollResp := signedGetUpdates(t, ts, fp, signingPriv)
	defer pollResp.Body.Close()

	var poll1 struct {
		HasUpdates bool    `json:"has_updates"`
		ConfigYAML *string `json:"config_yaml"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&poll1); err != nil {
		t.Fatalf("decode poll1: %v", err)
	}
	if poll1.HasUpdates {
		t.Errorf("poll1: HasUpdates should be false after enrollment, got true")
	}
	t.Logf("poll1: HasUpdates=%v", poll1.HasUpdates)

	// 4. PATCH host to change MTU (this triggers UpdateHostConfigVersion=0)
	t.Log("PATCH host MTU to 1280")
	updateBody := map[string]any{
		"advanced": map[string]any{
			"mtu": 1280,
		},
	}
	resp = apiCall(t, ts, "PATCH", "/api/v1/hosts/"+host.ID, updateBody)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH host: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var patchedHost models.Host
	if err := json.NewDecoder(resp.Body).Decode(&patchedHost); err != nil {
		t.Fatalf("decode patched host: %v", err)
	}
	resp.Body.Close()
	t.Logf("host updated: MTU=%d", patchedHost.Advanced.MTU)

	// 5. Second poll (after PATCH) — should have HasUpdates=true with new ConfigYAML
	t.Log("Second poll (after MTU change)")
	pollResp = signedGetUpdates(t, ts, fp, signingPriv)
	defer pollResp.Body.Close()

	var poll2 struct {
		HasUpdates bool    `json:"has_updates"`
		ConfigYAML *string `json:"config_yaml"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&poll2); err != nil {
		t.Fatalf("decode poll2: %v", err)
	}
	if !poll2.HasUpdates {
		t.Error("poll2: HasUpdates should be true after MTU change")
	}
	if poll2.ConfigYAML == nil || *poll2.ConfigYAML == "" {
		t.Error("poll2: ConfigYAML should not be empty")
	}
	if !strings.Contains(*poll2.ConfigYAML, "mtu: 1280") {
		t.Errorf("poll2: ConfigYAML should contain 'mtu: 1280', got:\n%s", *poll2.ConfigYAML)
	}
	t.Logf("poll2: HasUpdates=%v, ConfigYAML contains mtu: 1280", poll2.HasUpdates)

	// 6. Verify audit entry was created
	t.Log("Verify audit entry")
	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "host.update", Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(entries))
	} else {
		if !strings.Contains(entries[0].Details, "advanced.mtu") {
			t.Errorf("audit entry should contain 'advanced.mtu', got: %s", entries[0].Details)
		}
		t.Logf("audit entry created: action=%s", entries[0].Action)
	}
}

// TestE2E_RenameHost_TriggersRekey tests that renaming a host sets PendingRekey
// and the next poll returns RekeyRequired=true with a fresh enrollment token.
func TestE2E_RenameHost_TriggersRekey(t *testing.T) {
	ts, s, _ := setupE2E(t)

	// 1. Create network
	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]any{
		"name":  "e2e-rename-net",
		"cidrs": []string{"192.168.100.0/24"},
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create network: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var network models.Network
	if err := json.NewDecoder(resp.Body).Decode(&network); err != nil {
		t.Fatalf("decode network: %v", err)
	}
	resp.Body.Close()

	// 2. Enroll a host
	host, enrollResult, signingPriv := enrollHostForPoll(t, ts, s, network.ID, "original-name", "192.168.100.10")
	t.Logf("host enrolled: %s (ID: %s)", host.Name, host.ID)

	// Parse cert to get fingerprint
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResult.CertificatePEM))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	fp, _ := hostCert.Fingerprint()

	// 3. First poll (initial config)
	t.Log("First poll (initial config)")
	pollResp := signedGetUpdates(t, ts, fp, signingPriv)
	defer pollResp.Body.Close()

	var poll1 struct {
		HasUpdates bool `json:"has_updates"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&poll1); err != nil {
		t.Fatalf("decode poll1: %v", err)
	}

	// 4. PATCH host to rename
	t.Log("PATCH host name")
	updateBody := map[string]any{
		"name": "renamed-host",
	}
	resp = apiCall(t, ts, "PATCH", "/api/v1/hosts/"+host.ID, updateBody)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH host: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var patchedHost models.Host
	if err := json.NewDecoder(resp.Body).Decode(&patchedHost); err != nil {
		t.Fatalf("decode patched host: %v", err)
	}
	resp.Body.Close()
	t.Logf("host renamed: %s -> %s", host.Name, patchedHost.Name)

	// 5. Second poll (after PATCH) — should have RekeyRequired=true and EnrollmentToken
	t.Log("Second poll (after rename)")
	pollResp = signedGetUpdates(t, ts, fp, signingPriv)
	defer pollResp.Body.Close()

	var poll2 struct {
		RekeyRequired   bool   `json:"rekey_required"`
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&poll2); err != nil {
		t.Fatalf("decode poll2: %v", err)
	}
	if !poll2.RekeyRequired {
		t.Error("poll2: RekeyRequired should be true after name change")
	}
	if poll2.EnrollmentToken == "" {
		t.Error("poll2: EnrollmentToken should not be empty")
	}
	t.Logf("poll2: RekeyRequired=%v, EnrollmentToken=%s", poll2.RekeyRequired, poll2.EnrollmentToken[:8]+"...")

	// 6. Verify PendingRekey was cleared after poll
	hostAfterPoll, err := s.GetHost(context.Background(), host.ID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if hostAfterPoll.PendingRekey {
		t.Error("host.PendingRekey should be cleared after poll")
	}
	t.Logf("host after poll: PendingRekey=%v", hostAfterPoll.PendingRekey)

	// 7. Verify audit entry was created with "name" in details
	t.Log("Verify audit entry")
	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "host.update", Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(entries))
	} else {
		if !strings.Contains(entries[0].Details, "name") {
			t.Errorf("audit entry should contain 'name' field, got: %s", entries[0].Details)
		}
		t.Logf("audit entry created: action=%s", entries[0].Action)
	}
}
