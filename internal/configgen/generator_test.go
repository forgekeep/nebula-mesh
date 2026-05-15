package configgen

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/slackhq/nebula/cert"
	"gopkg.in/yaml.v3"
)

func TestGenerate_RegularHost(t *testing.T) {
	input := GeneratorInput{
		HostName:    "web-1",
		NebulaIPs:   []string{"192.168.100.10"},
		IsLighthouse: false,
		IsRelay:     false,
		CACertPath:  "/etc/nebula/ca.crt",
		CertPath:    "/etc/nebula/host.crt",
		KeyPath:     "/etc/nebula/host.key",
		ListenPort:  0,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
			{Port: "22", Proto: "tcp", Group: "admin"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Validate it's valid YAML
	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	if !strings.Contains(s, "/etc/nebula/ca.crt") {
		t.Error("missing ca cert path")
	}
	if !strings.Contains(s, "203.0.113.10:4242") {
		t.Error("missing lighthouse public address")
	}
	if !strings.Contains(s, "192.168.100.1") {
		t.Error("missing lighthouse nebula IP")
	}
	// Regular host should not be a lighthouse
	if strings.Contains(s, "am_lighthouse: true") {
		t.Error("regular host should not be am_lighthouse")
	}
}

func TestGenerate_Lighthouse(t *testing.T) {
	input := GeneratorInput{
		HostName:     "lighthouse-1",
		NebulaIPs:    []string{"192.168.100.1"},
		IsLighthouse: true,
		CACertPath:   "/etc/nebula/ca.crt",
		CertPath:     "/etc/nebula/host.crt",
		KeyPath:      "/etc/nebula/host.key",
		ListenPort:   4242,
		Lighthouses:  nil,
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	if !strings.Contains(s, "am_lighthouse: true") {
		t.Error("lighthouse should have am_lighthouse: true")
	}
	if !strings.Contains(s, "4242") {
		t.Error("lighthouse should have listen port")
	}
}

func TestGenerate_Relay(t *testing.T) {
	input := GeneratorInput{
		HostName:    "relay-1",
		NebulaIPs:   []string{"192.168.100.2"},
		IsRelay:     true,
		CACertPath:  "/etc/nebula/ca.crt",
		CertPath:    "/etc/nebula/host.crt",
		KeyPath:     "/etc/nebula/host.key",
		ListenPort:  4242,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"},
		},
		Relays: []string{"192.168.100.2"},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	if !strings.Contains(s, "am_relay: true") {
		t.Error("relay should have am_relay: true")
	}
}

func TestGenerate_FallbackToPaths(t *testing.T) {
	input := GeneratorInput{
		HostName:     "web-1",
		NebulaIPs:    []string{"192.168.100.10"},
		IsLighthouse: false,
		IsRelay:      false,
		CACertPath:   "/etc/nebula/ca.crt",
		CertPath:     "/etc/nebula/host.crt",
		KeyPath:      "/etc/nebula/host.key",
		ListenPort:   0,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		// Inline PEM fields are empty - should use path-based fallback
		CACertPEM: "",
		CertPEM:   "",
		KeyPEM:    "",
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	// Backwards compat: should contain path-based pki section
	if !strings.Contains(s, "ca: /etc/nebula/ca.crt") {
		t.Error("expected path-based ca cert path")
	}
	if !strings.Contains(s, "cert: /etc/nebula/host.crt") {
		t.Error("expected path-based cert path")
	}
	if !strings.Contains(s, "key: /etc/nebula/host.key") {
		t.Error("expected path-based key path")
	}
	// Should NOT contain inline PEM literal blocks
	if strings.Contains(s, "ca: |") {
		t.Error("should not contain inline PEM when PEM fields are empty")
	}
}

func TestGenerate_InlinePEM(t *testing.T) {
	caPEM := `-----BEGIN NEBULA CERTIFICATE-----
CACA...CA...CACA
-----END NEBULA CERTIFICATE-----`
	certPEM := `-----BEGIN NEBULA CERTIFICATE-----
CERT...CERT...CERT
-----END NEBULA CERTIFICATE-----`
	keyPEM := `-----BEGIN NEBULA X25519 PRIVATE KEY-----
KEY...KEY...KEY
-----END NEBULA X25519 PRIVATE KEY-----`

	input := GeneratorInput{
		HostName:     "mobile-1",
		NebulaIPs:    []string{"192.168.100.50"},
		IsLighthouse: false,
		IsRelay:      false,
		ListenPort:   0,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		// Use inline PEM
		CACertPEM: caPEM,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		// Path-based fields should be ignored
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	// Should contain inline PEM literal blocks
	if !strings.Contains(s, "ca: |") {
		t.Error("expected inline PEM literal block for ca")
	}
	if !strings.Contains(s, "-----BEGIN NEBULA CERTIFICATE-----") {
		t.Error("expected inline CA certificate content")
	}
	// Should NOT contain path-based pki section
	if strings.Contains(s, "ca: /etc/nebula/ca.crt") {
		t.Error("should not contain path-based ca when PEM is set")
	}
	if strings.Contains(s, "cert: /etc/nebula/host.crt") {
		t.Error("should not contain path-based cert when PEM is set")
	}
	if strings.Contains(s, "key: /etc/nebula/host.key") {
		t.Error("should not contain path-based key when PEM is set")
	}
}

// Task 2.3 tests: multi-address lighthouses

func TestGenerate_StaticHostMap_PerAddress(t *testing.T) {
	input := GeneratorInput{
		HostName:    "web-1",
		NebulaIPs:   []string{"10.0.0.5", "fd00::5"},
		IsLighthouse: false,
		IsRelay:     false,
		CACertPath:  "/etc/nebula/ca.crt",
		CertPath:    "/etc/nebula/host.crt",
		KeyPath:     "/etc/nebula/host.key",
		ListenPort:  0,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"10.0.0.1", "fd00::1"}, PublicAddr: "1.2.3.4:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	s := string(data)
	// Should have one static_host_map entry per lighthouse IP
	if !strings.Contains(s, `"10.0.0.1": ["1.2.3.4:4242"]`) {
		t.Error("missing IPv4 lighthouse in static_host_map")
	}
	if !strings.Contains(s, `"fd00::1": ["1.2.3.4:4242"]`) {
		t.Error("missing IPv6 lighthouse in static_host_map")
	}
}

func TestGenerate_LighthouseHosts_AllAddresses(t *testing.T) {
	input := GeneratorInput{
		HostName:    "web-1",
		NebulaIPs:   []string{"10.0.0.5"},
		IsLighthouse: false,
		IsRelay:     false,
		CACertPath:  "/etc/nebula/ca.crt",
		CertPath:    "/etc/nebula/host.crt",
		KeyPath:     "/etc/nebula/host.key",
		ListenPort:  0,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"10.0.0.1", "fd00::1"}, PublicAddr: "1.2.3.4:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	s := string(data)
	// lighthouse.hosts should contain both addresses
	if !strings.Contains(s, `- "10.0.0.1"`) {
		t.Error("missing IPv4 lighthouse in lighthouse.hosts")
	}
	if !strings.Contains(s, `- "fd00::1"`) {
		t.Error("missing IPv6 lighthouse in lighthouse.hosts")
	}
}

func TestGenerate_MultipleLighthousesEachMulti(t *testing.T) {
	input := GeneratorInput{
		HostName:    "web-1",
		NebulaIPs:   []string{"10.0.0.5"},
		IsLighthouse: false,
		IsRelay:     false,
		CACertPath:  "/etc/nebula/ca.crt",
		CertPath:    "/etc/nebula/host.crt",
		KeyPath:     "/etc/nebula/host.key",
		ListenPort:  0,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"10.0.0.1", "fd00::1"}, PublicAddr: "1.2.3.4:4242"},
			{NebulaIPs: []string{"10.0.0.2", "fd00::2"}, PublicAddr: "5.6.7.8:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	s := string(data)
	// Should have 4 entries in static_host_map (2 lighthouses × 2 IPs each)
	if !strings.Contains(s, `"10.0.0.1": ["1.2.3.4:4242"]`) {
		t.Error("missing first lighthouse IPv4")
	}
	if !strings.Contains(s, `"fd00::1": ["1.2.3.4:4242"]`) {
		t.Error("missing first lighthouse IPv6")
	}
	if !strings.Contains(s, `"10.0.0.2": ["5.6.7.8:4242"]`) {
		t.Error("missing second lighthouse IPv4")
	}
	if !strings.Contains(s, `"fd00::2": ["5.6.7.8:4242"]`) {
		t.Error("missing second lighthouse IPv6")
	}

	// Parse to ensure valid YAML
	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}
}

func TestGenerate_InlinePEM_RoundTrip(t *testing.T) {
	// Generate real CA and host certificates
	caMgr, err := pki.NewCA("test-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	caPEM, err := caMgr.CACertPEM()
	if err != nil {
		t.Fatalf("CACertPEM error: %v", err)
	}

	// Generate host certificate with network prefix
	var prefixAddr [4]byte
	prefixAddr[0] = 192
	prefixAddr[1] = 168
	prefixAddr[2] = 100
	prefixAddr[3] = 50
	hostPrefix := netip.PrefixFrom(netip.AddrFrom4(prefixAddr), 32)

	hostCert, err := caMgr.Sign(pki.SignRequest{
		Name:      "mobile-test",
		PublicKey: []byte("test-public-key-32-bytes-buffer"),
		Networks:  []netip.Prefix{hostPrefix},
		Duration:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	certPEM, err := hostCert.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}

	keyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, []byte("test-private-key-32-bytes-buffer"))

	input := GeneratorInput{
		HostName:     "mobile-test",
		NebulaIPs:    []string{"192.168.100.50"},
		IsLighthouse: false,
		IsRelay:      false,
		ListenPort:   0,
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		CACertPEM: string(caPEM),
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Parse generated YAML
	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	// Extract pki section
	pkiMap, ok := parsed["pki"].(map[string]any)
	if !ok {
		t.Fatalf("pki section not found in parsed YAML")
	}

	// Check CA cert
	pkiCA, ok := pkiMap["ca"].(string)
	if !ok {
		t.Fatalf("ca should be a string, got %T", pkiMap["ca"])
	}
	if !strings.Contains(pkiCA, "-----BEGIN NEBULA CERTIFICATE") {
		t.Error("ca does not contain PEM header")
	}

	// Verify CA cert can be unmarshalled
	caCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(pkiCA))
	if err != nil {
		t.Errorf("UnmarshalCertificateFromPEM for CA: %v", err)
	}
	if caCert.Name() != "test-ca" {
		t.Errorf("expected CA name 'test-ca', got %q", caCert.Name())
	}

	// Check host cert
	pkiCert, ok := pkiMap["cert"].(string)
	if !ok {
		t.Fatalf("cert should be a string, got %T", pkiMap["cert"])
	}
	hostCertUnmarshalled, _, err := cert.UnmarshalCertificateFromPEM([]byte(pkiCert))
	if err != nil {
		t.Errorf("UnmarshalCertificateFromPEM for host cert: %v", err)
	}
	if hostCertUnmarshalled.Name() != "mobile-test" {
		t.Errorf("expected host name 'mobile-test', got %q", hostCertUnmarshalled.Name())
	}

	// Check private key
	pkiKey, ok := pkiMap["key"].(string)
	if !ok {
		t.Fatalf("key should be a string, got %T", pkiMap["key"])
	}
	if !strings.Contains(pkiKey, "-----BEGIN NEBULA X25519 PRIVATE KEY-----") {
		t.Error("key does not contain X25519 private key PEM header")
	}
}
