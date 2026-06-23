package configgen

// LighthouseInfo describes a lighthouse node for config generation.
type LighthouseInfo struct {
	NebulaIPs  []string
	PublicAddr string // "1.2.3.4:4242"
}

// FirewallRule represents a single firewall rule.
type FirewallRule struct {
	Port  string // "any", "22", "443"
	Proto string // "any", "tcp", "udp", "icmp"
	Group string // "any", "admin", etc.
}

// AdvancedUnsafeRoute mirrors models.UnsafeRoute for the generator input.
type AdvancedUnsafeRoute struct {
	Route string
	Via   string
}

// GeneratorInput contains all parameters needed to generate a Nebula config.
type GeneratorInput struct {
	HostName         string
	NebulaIPs        []string
	IsLighthouse     bool
	IsRelay          bool
	CACertPath       string
	CertPath         string
	KeyPath          string
	ListenPort       int
	Lighthouses      []LighthouseInfo
	Relays           []string
	FirewallInbound  []FirewallRule
	FirewallOutbound []FirewallRule

	// Optional per-host overrides. Zero values mean "use the default".
	PunchyOverride *bool
	ListenHost     string
	MTU            int
	TunDevice      string
	UnsafeRoutes   []AdvancedUnsafeRoute

	// Optional inline PEM blocks. When CACertPEM is non-empty, CertPEM and
	// KeyPEM must also be non-empty; all three are emitted as literal-block
	// scalars in the pki section. When empty, the path-based fields above
	// are used instead. Mobile Nebula clients use the inline form since
	// they import a self-contained YAML config.
	CACertPEM string
	CertPEM   string
	KeyPEM    string

	// Blocklist is the per-CA list of revoked certificate fingerprints.
	// Emitted as pki.blocklist in config.yml so the Nebula daemon rejects
	// handshakes from revoked peers (GHSA-cm26-5974-52h8).
	Blocklist []string
}
