package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	nebulaconfig "github.com/slackhq/nebula/config"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/meshimport"
)

type DiscoveryState string

const (
	DiscoveryNone     DiscoveryState = "none"
	DiscoveryComplete DiscoveryState = "complete"
	DiscoveryUnsafe   DiscoveryState = "unsafe"
)

const (
	discoveryMaxFileBytes     = 4 << 20
	discoveryMaxSnapshotBytes = 768 << 10
)

// ExistingDiscovery contains only public upload material plus the local host
// key needed for the one-time X25519 challenge. HostPrivateKey is excluded from
// serialization and must be wiped as soon as the challenge proof is computed.
type ExistingDiscovery struct {
	State            DiscoveryState      `json:"state"`
	Manifest         []string            `json:"manifest,omitempty"`
	Issues           []string            `json:"issues,omitempty"`
	Snapshot         meshimport.Snapshot `json:"snapshot"`
	CACertificatePEM string              `json:"ca_certificate_pem,omitempty"`
	PayloadHash      string              `json:"payload_hash,omitempty"`
	HostPrivateKey   []byte              `json:"-"`
}

func (d *ExistingDiscovery) Wipe() {
	if d == nil {
		return
	}
	clear(d.HostPrivateKey)
	d.HostPrivateKey = nil
}

// DiscoverExisting inspects one file-backed Nebula installation. Unsafe and
// partial local states are returned as data so the CLI can explain remediation
// without making a management-server request.
func DiscoverExisting(configPath string) (*ExistingDiscovery, error) {
	result := &ExistingDiscovery{State: DiscoveryUnsafe}
	configPath = filepath.Clean(configPath)
	info, err := os.Stat(configPath)
	if errorsIsNotExist(err) {
		if hasDefaultNebulaArtifacts(filepath.Dir(configPath)) {
			result.Issues = []string{"Nebula config is missing while PKI files are present"}
			return result, nil
		}
		result.State = DiscoveryNone
		return result, nil
	}
	if err != nil {
		result.Issues = []string{"cannot inspect Nebula config file"}
		return unsafeDiscovery(result)
	}
	if info.IsDir() || !filepath.IsAbs(configPath) {
		result.Issues = []string{"Nebula config must be one absolute file path"}
		return result, nil
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	configuration := nebulaconfig.NewC(logger)
	if err := configuration.Load(configPath); err != nil {
		result.Issues = []string{"cannot parse Nebula config"}
		return unsafeDiscovery(result)
	}

	caPath, certPath, keyPath, issues := discoverPKIPaths(configuration)
	if len(issues) != 0 {
		result.Issues = issues
		return result, nil
	}
	result.Manifest = []string{
		"config: " + configPath,
		"ca certificate: " + caPath,
		"host certificate: " + certPath,
		"host key: " + keyPath + " (local proof only; never uploaded)",
	}

	caPEM, err := readDiscoveryFile(caPath)
	if err != nil {
		result.Issues = []string{"cannot read configured Nebula CA certificate"}
		return unsafeDiscovery(result)
	}
	caCertificate, remainder, err := cert.UnmarshalCertificateFromPEM(caPEM)
	if err != nil || strings.TrimSpace(string(remainder)) != "" || !caCertificate.IsCA() ||
		caCertificate.Curve() != cert.Curve_CURVE25519 || caCertificate.Expired(time.Now()) {
		result.Issues = []string{"configured Nebula CA must contain exactly one current Curve25519 root"}
		return unsafeDiscovery(result)
	}
	caFingerprint, err := caCertificate.Fingerprint()
	if err != nil {
		result.Issues = []string{"cannot fingerprint configured Nebula CA"}
		return unsafeDiscovery(result)
	}

	hostPEM, err := readDiscoveryFile(certPath)
	if err != nil {
		result.Issues = []string{"cannot read configured Nebula host certificate"}
		return unsafeDiscovery(result)
	}
	hostCertificate, remainder, err := cert.UnmarshalCertificateFromPEM(hostPEM)
	if err != nil || strings.TrimSpace(string(remainder)) != "" || hostCertificate.IsCA() ||
		hostCertificate.Curve() != cert.Curve_CURVE25519 || hostCertificate.Expired(time.Now()) {
		result.Issues = []string{"configured Nebula host certificate is invalid or expired"}
		return unsafeDiscovery(result)
	}
	pool := cert.NewCAPool()
	if err := pool.AddCA(caCertificate); err != nil {
		result.Issues = []string{"configured Nebula CA cannot verify certificates"}
		return unsafeDiscovery(result)
	}
	if _, err := pool.VerifyCertificate(time.Now(), hostCertificate); err != nil {
		result.Issues = []string{"configured Nebula host certificate is not signed by the configured CA"}
		return unsafeDiscovery(result)
	}

	keyPEM, err := readDiscoveryFile(keyPath)
	if err != nil {
		result.Issues = []string{"cannot read configured Nebula host key"}
		return unsafeDiscovery(result)
	}
	privateKey, remainder, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	clear(keyPEM)
	if err != nil || curve != cert.Curve_CURVE25519 || strings.TrimSpace(string(remainder)) != "" {
		clear(privateKey)
		result.Issues = []string{"configured Nebula host key is not one file-backed X25519 private key"}
		return unsafeDiscovery(result)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil || !bytes.Equal(publicKey, hostCertificate.PublicKey()) {
		clear(privateKey)
		result.Issues = []string{"configured Nebula host key does not match the host certificate"}
		return unsafeDiscovery(result)
	}

	hostFingerprint, err := hostCertificate.Fingerprint()
	if err != nil {
		clear(privateKey)
		result.Issues = []string{"cannot fingerprint configured Nebula host certificate"}
		return unsafeDiscovery(result)
	}
	snapshot := meshimport.Snapshot{
		ID: "local-" + hostFingerprint, HostID: "local-" + hostFingerprint,
		CertificatePEM: string(hostPEM),
		Profile: meshimport.AgentProfile{
			NebulaConfigPath: configPath, NebulaCAPath: caPath, NebulaCertPath: certPath,
			NebulaKeyPath: keyPath, ConfigAckV1: true,
		},
		Config: sanitizeNebulaConfig(configuration, caFingerprint),
	}
	if err := meshimport.ValidateSnapshot(snapshot, meshimport.Limits{MaxSnapshotBytes: discoveryMaxSnapshotBytes}); err != nil {
		clear(privateKey)
		result.Issues = []string{"sanitized Nebula snapshot exceeds safe import limits"}
		return unsafeDiscovery(result)
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		clear(privateKey)
		return nil, fmt.Errorf("marshal sanitized Nebula snapshot: %w", err)
	}
	sum := sha256.Sum256(payload)
	result.State = DiscoveryComplete
	result.Snapshot = snapshot
	result.CACertificatePEM = string(caPEM)
	result.PayloadHash = hex.EncodeToString(sum[:])
	result.HostPrivateKey = privateKey
	return result, nil
}

// unsafeDiscovery makes intentional parse/read failures part of the discovery
// state instead of transport errors so callers can present remediation safely.
func unsafeDiscovery(result *ExistingDiscovery) (*ExistingDiscovery, error) {
	return result, nil
}

func discoverPKIPaths(configuration *nebulaconfig.C) (caPath, certPath, keyPath string, issues []string) {
	values := []struct {
		name string
		path string
	}{
		{"pki.ca", configuration.GetString("pki.ca", "")},
		{"pki.cert", configuration.GetString("pki.cert", "")},
		{"pki.key", configuration.GetString("pki.key", "")},
	}
	issues = make([]string, 0)
	for index := range values {
		value := &values[index]
		if value.path == "" || strings.Contains(value.path, "-----BEGIN") || strings.HasPrefix(value.path, "pkcs11:") ||
			!filepath.IsAbs(value.path) || filepath.Clean(value.path) != value.path {
			issues = append(issues, value.name+" must be a clean absolute file path")
		}
	}
	return values[0].path, values[1].path, values[2].path, issues
}

func sanitizeNebulaConfig(configuration *nebulaconfig.C, caFingerprint string) meshimport.ConfigSnapshot {
	unsupported := collectUnsupportedConfigKeys(configuration.Settings)
	config := meshimport.ConfigSnapshot{
		CARootFingerprints: []string{caFingerprint},
		Blocklist:          stringSlice(configuration.Get("pki.blocklist")),
		StaticHostMap:      stringSliceMap(configuration.Get("static_host_map")),
		LighthouseHosts:    stringSlice(configuration.Get("lighthouse.hosts")),
		Relays:             stringSlice(configuration.Get("relay.relays")),
		AmLighthouse:       configuration.GetBool("lighthouse.am_lighthouse", false),
		AmRelay:            configuration.GetBool("relay.am_relay", false),
		ListenHost:         configuration.GetString("listen.host", ""),
		ListenPort:         configuration.GetInt("listen.port", 0),
		MTU:                configuration.GetInt("tun.mtu", 0),
		TunDevice:          configuration.GetString("tun.dev", ""),
		UnsafeRoutes:       sanitizeUnsafeRoutes(configuration.Get("tun.unsafe_routes"), &unsupported),
		Firewall: meshimport.FirewallPolicy{
			Inbound:  sanitizeFirewallRules("firewall.inbound", configuration.Get("firewall.inbound"), &unsupported),
			Outbound: sanitizeFirewallRules("firewall.outbound", configuration.Get("firewall.outbound"), &unsupported),
		},
	}
	if configuration.IsSet("punchy.punch") {
		value := configuration.GetBool("punchy.punch", false)
		config.Punchy = &value
	}
	config.UnsupportedKeys = sortedUniqueStrings(unsupported)
	return config
}

func sanitizeUnsafeRoutes(value any, unsupported *[]string) []meshimport.UnsafeRoute {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	routes := make([]meshimport.UnsafeRoute, 0, len(items))
	for index, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			*unsupported = append(*unsupported, fmt.Sprintf("tun.unsafe_routes[%d]", index))
			continue
		}
		route, routeOK := entry["route"].(string)
		via, viaOK := entry["via"].(string)
		if !routeOK || !viaOK {
			*unsupported = append(*unsupported, fmt.Sprintf("tun.unsafe_routes[%d].via", index))
			continue
		}
		routes = append(routes, meshimport.UnsafeRoute{Route: route, Via: via})
	}
	return routes
}

func sanitizeFirewallRules(path string, value any, unsupported *[]string) []meshimport.FirewallRule {
	items, ok := value.([]any)
	if !ok {
		return []meshimport.FirewallRule{}
	}
	rules := make([]meshimport.FirewallRule, 0, len(items))
	for index, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			*unsupported = append(*unsupported, fmt.Sprintf("%s[%d]", path, index))
			continue
		}
		group := fmt.Sprint(entry["group"])
		if group == "<nil>" || group == "" {
			if host := fmt.Sprint(entry["host"]); host == "any" {
				group = "any"
			} else {
				group = "any"
				*unsupported = append(*unsupported, fmt.Sprintf("%s[%d].principal", path, index))
			}
		}
		rules = append(rules, meshimport.FirewallRule{
			Port: fmt.Sprint(entry["port"]), Proto: fmt.Sprint(entry["proto"]), Group: group,
		})
	}
	return rules
}

func collectUnsupportedConfigKeys(settings map[string]any) []string {
	keys := make([]string, 0)
	walkConfigLeaves(settings, "", func(path string) {
		if !supportedConfigLeaf(path) {
			keys = append(keys, path)
		}
	})
	return keys
}

func walkConfigLeaves(value any, path string, visit func(string)) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			walkConfigLeaves(child, childPath, visit)
		}
	case []any:
		for index, child := range typed {
			walkConfigLeaves(child, path+"["+strconv.Itoa(index)+"]", visit)
		}
	default:
		if path != "" {
			visit(path)
		}
	}
}

func supportedConfigLeaf(path string) bool {
	normalized := normalizeConfigIndexes(path)
	switch normalized {
	case "pki.ca", "pki.cert", "pki.key", "pki.blocklist[]",
		"lighthouse.am_lighthouse", "lighthouse.hosts[]",
		"relay.am_relay", "relay.relays[]",
		"listen.host", "listen.port", "punchy.punch", "tun.dev", "tun.mtu",
		"tun.unsafe_routes[].route", "tun.unsafe_routes[].via",
		"firewall.inbound[].port", "firewall.inbound[].proto", "firewall.inbound[].group", "firewall.inbound[].host",
		"firewall.outbound[].port", "firewall.outbound[].proto", "firewall.outbound[].group", "firewall.outbound[].host":
		return true
	}
	return strings.HasPrefix(normalized, "static_host_map.")
}

func normalizeConfigIndexes(path string) string {
	var builder strings.Builder
	for index := 0; index < len(path); {
		if path[index] != '[' {
			builder.WriteByte(path[index])
			index++
			continue
		}
		end := strings.IndexByte(path[index:], ']')
		if end < 0 {
			builder.WriteString(path[index:])
			break
		}
		builder.WriteString("[]")
		index += end + 1
	}
	return builder.String()
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringSliceMap(value any) map[string][]string {
	items, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string][]string, len(items))
	for key, item := range items {
		result[key] = stringSlice(item)
	}
	return result
}

func sortedUniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func readDiscoveryFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- path comes from operator-controlled Nebula config and is validated as absolute
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, discoveryMaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > discoveryMaxFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", discoveryMaxFileBytes)
	}
	return contents, nil
}

func hasDefaultNebulaArtifacts(dir string) bool {
	for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
