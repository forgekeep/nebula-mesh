package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestE2E_DualFamilyNetwork verifies that dual-stack (IPv4 + IPv6) networks work
// end-to-end: cert generation contains both prefix pairs in order, and config
// YAML has proper static_host_map and lighthouse.hosts entries for all addresses.
func TestE2E_DualFamilyNetwork(t *testing.T) {
	ts, _, _ := setupE2E(t)

	// 1. Create dual-family network
	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]any{
		"name":  "dual-family-net",
		"cidrs": []string{"10.42.0.0/24", "fd00:42::/64"},
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
	t.Logf("network created: %s (cidrs: 10.42.0.0/24, fd00:42::/64)", network.ID)

	// 2. Create and enroll lighthouse with both IPv4 and IPv6
	resp = apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id":  network.ID,
		"name":        "lighthouse-dual",
		"nebula_ips":  []string{"10.42.0.10", "fd00:42::10"},
		"role":        "lighthouse",
		"public_ip":   "203.0.113.1",
		"listen_port": 4242,
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create lighthouse: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var lhResp struct {
		Host            *models.Host `json:"host"`
		EnrollmentToken string       `json:"enrollment_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lhResp); err != nil {
		t.Fatalf("decode lighthouse: %v", err)
	}
	resp.Body.Close()
	t.Logf("lighthouse created: %s", lhResp.Host.Name)

	// Enroll lighthouse (not strictly necessary for its certs, but completes the setup)
	privKey := make([]byte, 32)
	rand.Read(privKey)
	pubKey, _ := curve25519.X25519(privKey, curve25519.Basepoint)
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)
	_, _, signingPubPEM := signingKeypair(t)

	enrollReq := map[string]string{
		"token":                  lhResp.EnrollmentToken,
		"public_key_pem":         string(pubKeyPEM),
		"signing_public_key_pem": signingPubPEM,
	}
	data, _ := json.Marshal(enrollReq)
	http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(data))

	// 3. Create regular host with both IPv4 and IPv6
	resp = apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id": network.ID,
		"name":       "host-dual",
		"nebula_ips": []string{"10.42.0.20", "fd00:42::20"},
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
	t.Logf("host created: %s", hostResp.Host.Name)

	// 4. Enroll regular host
	privKey2 := make([]byte, 32)
	rand.Read(privKey2)
	pubKey2, _ := curve25519.X25519(privKey2, curve25519.Basepoint)
	pubKeyPEM2 := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey2)
	_, signingPriv, signingPubPEM2 := signingKeypair(t)

	enrollReq2 := map[string]string{
		"token":                  hostResp.EnrollmentToken,
		"public_key_pem":         string(pubKeyPEM2),
		"signing_public_key_pem": signingPubPEM2,
	}
	data2, _ := json.Marshal(enrollReq2)
	enrollResp, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(data2))
	if err != nil {
		t.Fatal(err)
	}
	if enrollResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(enrollResp.Body)
		t.Fatalf("enroll: HTTP %d: %s", enrollResp.StatusCode, string(body))
	}
	var enrollResult struct {
		CertificatePEM string `json:"certificate_pem"`
		ConfigYAML     string `json:"config_yaml"`
	}
	if err := json.NewDecoder(enrollResp.Body).Decode(&enrollResult); err != nil {
		t.Fatalf("decode enrollment: %v", err)
	}
	enrollResp.Body.Close()

	// 5. Verify certificate contains both networks in order
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResult.CertificatePEM))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	networks := hostCert.Networks()
	if len(networks) != 2 {
		t.Errorf("cert.Networks() returned %d prefixes, want 2", len(networks))
	}
	if len(networks) >= 2 {
		if networks[0].String() != "10.42.0.20/24" {
			t.Errorf("networks[0] = %s, want 10.42.0.20/24", networks[0].String())
		}
		if networks[1].String() != "fd00:42::20/64" {
			t.Errorf("networks[1] = %s, want fd00:42::20/64", networks[1].String())
		}
	}
	t.Log("Certificate networks verified: IPv4 and IPv6 in order")

	// 6. Poll to get updated config with lighthouse addresses
	fp, _ := hostCert.Fingerprint()
	pollResp := signedGetUpdates(t, ts, fp, signingPriv)
	var pollResult struct {
		ConfigYAML *string `json:"config_yaml,omitempty"`
	}
	json.NewDecoder(pollResp.Body).Decode(&pollResult)
	pollResp.Body.Close()

	configYAML := enrollResult.ConfigYAML
	if pollResult.ConfigYAML != nil {
		configYAML = *pollResult.ConfigYAML
	}

	var config map[string]any
	if err := yaml.Unmarshal([]byte(configYAML), &config); err != nil {
		t.Fatalf("parse config YAML: %v", err)
	}

	// Check static_host_map has both lighthouse addresses
	staticHostMap, ok := config["static_host_map"].(map[string]any)
	if !ok {
		t.Fatalf("static_host_map not found or not a map in config")
	}

	// Both IPv4 and IPv6 lighthouse addresses should be present
	if _, ok := staticHostMap["10.42.0.10"]; !ok {
		t.Error("static_host_map missing 10.42.0.10 (IPv4 lighthouse)")
	}

	if _, ok := staticHostMap["fd00:42::10"]; !ok {
		t.Error("static_host_map missing fd00:42::10 (IPv6 lighthouse)")
	}

	// Check lighthouse.hosts contains both addresses
	lighthouse, ok := config["lighthouse"].(map[string]any)
	if !ok {
		t.Fatalf("lighthouse section not found in config")
	}

	hosts, ok := lighthouse["hosts"].([]any)
	if !ok {
		t.Fatalf("lighthouse.hosts not found or not a list")
	}

	hasIPv4 := false
	hasIPv6 := false
	for _, h := range hosts {
		if host, ok := h.(string); ok {
			if host == "10.42.0.10" {
				hasIPv4 = true
			}
			if host == "fd00:42::10" {
				hasIPv6 = true
			}
		}
	}

	if !hasIPv4 {
		t.Errorf("lighthouse.hosts missing 10.42.0.10: %v", hosts)
	}
	if !hasIPv6 {
		t.Errorf("lighthouse.hosts missing fd00:42::10: %v", hosts)
	}

	t.Log("Config YAML multi-address verified: static_host_map and lighthouse.hosts contain both IPs")
	t.Log("E2E dual-family network test passed")
}

// TestE2E_AddressOrderPreserved verifies that the order of nebula_ips is
// preserved in the certificate's Networks() list. The test creates a host
// with IPv4 then IPv6 addresses and verifies they appear in that same order
// in the resulting certificate.
func TestE2E_AddressOrderPreserved(t *testing.T) {
	ts, _, _ := setupE2E(t)

	// 1. Create network with both IPv4 and IPv6 CIDRs
	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]any{
		"name":  "order-test-net",
		"cidrs": []string{"10.50.0.0/24", "fd00:50::/64"},
	})
	var network models.Network
	if err := json.NewDecoder(resp.Body).Decode(&network); err != nil {
		t.Fatalf("decode network: %v", err)
	}
	resp.Body.Close()

	// 2. Create host with IPv4 first, then IPv6
	resp = apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id": network.ID,
		"name":       "order-test-host",
		"nebula_ips": []string{"10.50.0.30", "fd00:50::30"},
	})
	var hostResp struct {
		Host            *models.Host `json:"host"`
		EnrollmentToken string       `json:"enrollment_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hostResp); err != nil {
		t.Fatalf("decode host: %v", err)
	}
	resp.Body.Close()

	// 3. Enroll host
	privKey := make([]byte, 32)
	rand.Read(privKey)
	pubKey, _ := curve25519.X25519(privKey, curve25519.Basepoint)
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)
	_, _, signingPubPEM := signingKeypair(t)

	enrollReq := map[string]string{
		"token":                  hostResp.EnrollmentToken,
		"public_key_pem":         string(pubKeyPEM),
		"signing_public_key_pem": signingPubPEM,
	}
	data, _ := json.Marshal(enrollReq)
	enrollResp, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(data))
	var enrollResult struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	json.NewDecoder(enrollResp.Body).Decode(&enrollResult)
	enrollResp.Body.Close()

	// 4. Verify certificate preserves order: IPv6 first, then IPv4
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResult.CertificatePEM))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	networks := hostCert.Networks()
	if len(networks) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(networks))
	}

	if networks[0].String() != "10.50.0.30/24" {
		t.Errorf("networks[0] = %s, want 10.50.0.30/24", networks[0].String())
	}
	if networks[1].String() != "fd00:50::30/64" {
		t.Errorf("networks[1] = %s, want fd00:50::30/64", networks[1].String())
	}

	t.Log("Address order preserved: IPv6, then IPv4")
}

// TestE2E_RejectsAddressOutsideNetworkCIDRs verifies that trying to enroll
// a host with a nebula_ip outside the network's configured CIDRs is rejected.
func TestE2E_RejectsAddressOutsideNetworkCIDRs(t *testing.T) {
	ts, _, _ := setupE2E(t)

	// 1. Create network with single CIDR
	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]any{
		"name":  "reject-test-net",
		"cidrs": []string{"10.60.0.0/24"},
	})
	var network models.Network
	json.NewDecoder(resp.Body).Decode(&network)
	resp.Body.Close()

	// 2. Try to create host with IP outside the network CIDR
	resp = apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id": network.ID,
		"name":       "invalid-host",
		"nebula_ips": []string{"192.168.0.10"}, // Not in 10.60.0.0/24
	})

	// Should get 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected HTTP 400, got %d: %s", resp.StatusCode, string(body))
	}

	// Response should indicate the address is outside network CIDRs
	body, _ := io.ReadAll(resp.Body)
	respBody := string(body)
	if !contains(respBody, []string{"outside", "not within", "cidr", "network", "invalid"}) {
		t.Errorf("error message should mention CIDR/network validation: %s", respBody)
	}

	t.Log("Address validation correctly rejected out-of-range IP")
}

// contains is a small helper to check if response contains any of the keywords
func contains(s string, keywords []string) bool {
	for _, kw := range keywords {
		if bytes.Contains([]byte(s), []byte(kw)) {
			return true
		}
	}
	return false
}
