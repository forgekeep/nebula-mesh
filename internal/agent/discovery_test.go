package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/pki"
)

func TestDiscoverExistingCompleteSanitizesSecrets(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	sshCanary := "SSH_PRIVATE_CANARY_DO_NOT_UPLOAD"
	blocklisted := strings.Repeat("a", 64)
	fixture.writeConfig(t, fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
  blocklist: [%s]
static_host_map:
  "10.42.0.1": ["198.51.100.1:4242"]
lighthouse:
  am_lighthouse: true
  hosts: ["10.42.0.1"]
relay:
  am_relay: true
  relays: ["10.42.0.2"]
listen: {host: "0.0.0.0", port: 4242}
punchy: {punch: true}
tun:
  dev: nebula9
  mtu: 1400
  unsafe_routes:
    - {route: "172.16.0.0/16", via: "10.42.0.2"}
firewall:
  inbound:
    - {port: "22", proto: tcp, group: ops}
  outbound:
    - {port: any, proto: any, host: any}
sshd:
  host_key: %s
logging:
  level: debug
`, fixture.caPath, fixture.certPath, fixture.keyPath, blocklisted, sshCanary))

	discovery, err := DiscoverExisting(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Wipe()
	if discovery.State != DiscoveryComplete {
		t.Fatalf("state = %q, issues = %v", discovery.State, discovery.Issues)
	}
	if discovery.PayloadHash == "" || len(discovery.HostPrivateKey) != curve25519.ScalarSize {
		t.Fatalf("missing proof material: %#v", discovery)
	}
	snapshot := discovery.Snapshot
	if snapshot.Profile.NebulaConfigPath != fixture.configPath || snapshot.Profile.NebulaCAPath != fixture.caPath ||
		snapshot.Profile.NebulaCertPath != fixture.certPath || snapshot.Profile.NebulaKeyPath != fixture.keyPath || !snapshot.Profile.ConfigAckV1 {
		t.Fatalf("profile = %#v", snapshot.Profile)
	}
	config := snapshot.Config
	if !config.AmLighthouse || !config.AmRelay || config.ListenPort != 4242 || config.MTU != 1400 || config.TunDevice != "nebula9" ||
		config.Punchy == nil || !*config.Punchy || len(config.UnsafeRoutes) != 1 || len(config.Firewall.Inbound) != 1 ||
		len(config.Firewall.Outbound) != 1 || config.Firewall.Outbound[0].Group != "any" || len(config.CARootFingerprints) != 1 {
		t.Fatalf("sanitized config = %#v", config)
	}
	for _, key := range []string{"sshd.host_key", "logging.level"} {
		if !containsString(config.UnsupportedKeys, key) {
			t.Errorf("unsupported keys %v missing %q", config.UnsupportedKeys, key)
		}
	}
	serialized, err := json.Marshal(discovery)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(fixture.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte(sshCanary)) || bytes.Contains(serialized, keyPEM) ||
		bytes.Contains(serialized, discovery.HostPrivateKey) {
		t.Fatalf("serialized discovery leaked private material: %s", serialized)
	}
}

func TestDiscoverExistingClassifiesNonePartialAndMalformed(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		discovery, err := DiscoverExisting(filepath.Join(t.TempDir(), "config.yml"))
		if err != nil || discovery.State != DiscoveryNone {
			t.Fatalf("discovery = %#v, err = %v", discovery, err)
		}
	})
	t.Run("partial default files", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "host.crt"), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		discovery, err := DiscoverExisting(filepath.Join(dir, "config.yml"))
		if err != nil || discovery.State != DiscoveryUnsafe || len(discovery.Issues) == 0 {
			t.Fatalf("discovery = %#v, err = %v", discovery, err)
		}
	})
	t.Run("malformed yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		if err := os.WriteFile(path, []byte("pki: ["), 0o600); err != nil {
			t.Fatal(err)
		}
		discovery, err := DiscoverExisting(path)
		if err != nil || discovery.State != DiscoveryUnsafe || !strings.Contains(strings.Join(discovery.Issues, " "), "parse") {
			t.Fatalf("discovery = %#v, err = %v", discovery, err)
		}
	})
}

func TestDiscoverExistingRejectsUnsafePKI(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *discoveryFixture)
	}{
		{
			name: "key certificate mismatch",
			mutate: func(t *testing.T, fixture *discoveryFixture) {
				other := make([]byte, curve25519.ScalarSize)
				if _, err := rand.Read(other); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fixture.keyPath, cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, other), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "additional CA root",
			mutate: func(t *testing.T, fixture *discoveryFixture) {
				other, err := pki.NewCA("other", time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Wipe()
				otherPEM, err := other.CACertPEM()
				if err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(fixture.caPath, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(otherPEM); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong CA",
			mutate: func(t *testing.T, fixture *discoveryFixture) {
				other, err := pki.NewCA("other", time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Wipe()
				otherPEM, err := other.CACertPEM()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fixture.caPath, otherPEM, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t)
			fixture.writeDefaultConfig(t)
			test.mutate(t, &fixture)
			discovery, err := DiscoverExisting(fixture.configPath)
			if err != nil || discovery.State != DiscoveryUnsafe || len(discovery.Issues) == 0 {
				t.Fatalf("discovery = %#v, err = %v", discovery, err)
			}
			if len(discovery.HostPrivateKey) != 0 {
				t.Fatal("unsafe discovery retained host private key")
			}
		})
	}
}

func TestDiscoverExistingRejectsInlineRelativeAndDirectoryConfig(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	keyPEM, err := os.ReadFile(fixture.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		path   string
		config string
	}{
		{"relative", fixture.configPath, "pki:\n  ca: ca.crt\n  cert: host.crt\n  key: host.key\n"},
		{"inline", fixture.configPath, fmt.Sprintf("pki:\n  ca: %s\n  cert: %s\n  key: |\n%s", fixture.caPath, fixture.certPath, indentYAML(string(keyPEM)))},
		{"directory", filepath.Dir(fixture.configPath), ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.config != "" {
				fixture.writeConfig(t, test.config)
			}
			discovery, err := DiscoverExisting(test.path)
			if err != nil || discovery.State != DiscoveryUnsafe {
				t.Fatalf("discovery = %#v, err = %v", discovery, err)
			}
		})
	}
}

type discoveryFixture struct {
	configPath string
	caPath     string
	certPath   string
	keyPath    string
}

func newDiscoveryFixture(t *testing.T) discoveryFixture {
	t.Helper()
	dir := t.TempDir()
	fixture := discoveryFixture{
		configPath: filepath.Join(dir, "config.yml"), caPath: filepath.Join(dir, "ca.crt"),
		certPath: filepath.Join(dir, "host.crt"), keyPath: filepath.Join(dir, "host.key"),
	}
	caManager, err := pki.NewCA("discovery-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer caManager.Wipe()
	caPEM, err := caManager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	hostCertificate, err := caManager.Sign(pki.SignRequest{
		Name: "existing-host", PublicKey: publicKey,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.42.0.10/16")}, Groups: []string{"ops"}, Duration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string][]byte{
		fixture.caPath: caPEM, fixture.certPath: hostPEM,
		fixture.keyPath: cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privateKey),
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clear(privateKey)
	return fixture
}

func (fixture discoveryFixture) writeDefaultConfig(t *testing.T) {
	t.Helper()
	fixture.writeConfig(t, fmt.Sprintf("pki:\n  ca: %s\n  cert: %s\n  key: %s\nfirewall:\n  inbound: []\n  outbound: []\n", fixture.caPath, fixture.certPath, fixture.keyPath))
}

func (fixture discoveryFixture) writeConfig(t *testing.T, contents string) {
	t.Helper()
	if err := os.WriteFile(fixture.configPath, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func indentYAML(value string) string {
	lines := strings.Split(value, "\n")
	for index := range lines {
		lines[index] = "    " + lines[index]
	}
	return strings.Join(lines, "\n")
}

// TestDiscoverExistingCapturesFirewallCIDRFields checks that an existing
// deployment's cidr / local_cidr rules survive discovery: they must be carried
// into the snapshot rather than dropped, and must not be reported as
// unsupported config keys (which would block the import).
func TestDiscoverExistingCapturesFirewallCIDRFields(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.writeConfig(t, fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
static_host_map:
  "10.42.0.1": ["198.51.100.1:4242"]
lighthouse:
  am_lighthouse: true
  hosts: ["10.42.0.1"]
listen: {host: "0.0.0.0", port: 4242}
firewall:
  inbound:
    - {port: "22", proto: tcp, group: ops, local_cidr: "192.0.2.0/24"}
    - {port: "443", proto: tcp, cidr: "10.42.0.0/24"}
  outbound:
    - {port: any, proto: any, host: any, local_cidr: any}
`, fixture.caPath, fixture.certPath, fixture.keyPath))

	discovery, err := DiscoverExisting(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Wipe()
	if discovery.State != DiscoveryComplete {
		t.Fatalf("state = %q, issues = %v", discovery.State, discovery.Issues)
	}

	config := discovery.Snapshot.Config
	if len(config.Firewall.Inbound) != 2 {
		t.Fatalf("inbound = %#v", config.Firewall.Inbound)
	}
	if got := config.Firewall.Inbound[0]; got.Group != "ops" || got.LocalCidr != "192.0.2.0/24" || got.Cidr != "" {
		t.Errorf("inbound[0] = %#v, want group ops with local_cidr 192.0.2.0/24", got)
	}
	// A cidr-selected rule has a principal, so it must not be rewritten to
	// group "any" the way a rule with no selector at all is.
	if got := config.Firewall.Inbound[1]; got.Cidr != "10.42.0.0/24" || got.Group != "" {
		t.Errorf("inbound[1] = %#v, want cidr 10.42.0.0/24 and no group", got)
	}
	if got := config.Firewall.Outbound[0]; got.Group != "any" || got.LocalCidr != "any" {
		t.Errorf("outbound[0] = %#v, want group any with local_cidr any", got)
	}
	for _, key := range config.UnsupportedKeys {
		if strings.Contains(key, "cidr") || strings.Contains(key, "principal") {
			t.Errorf("unsupported keys %v should not flag cidr fields", config.UnsupportedKeys)
			break
		}
	}
}
