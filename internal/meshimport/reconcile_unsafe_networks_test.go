package meshimport

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// snapshotWithUnsafeNetworks mirrors snapshotWithValidity but signs the host
// certificate with unsafe networks, the way an existing gateway's cert looks.
func (f certificateFixture) snapshotWithUnsafeNetworks(t *testing.T, id, name, network string, unsafe []netip.Prefix) Snapshot {
	t.Helper()
	tbs := &cert.TBSCertificate{
		Version: cert.Version2, Name: name,
		Networks:       []netip.Prefix{netip.MustParsePrefix(network)},
		UnsafeNetworks: unsafe,
		NotBefore:      f.now.Add(-time.Hour), NotAfter: f.now.Add(90 * 24 * time.Hour),
		PublicKey: make([]byte, 32), Curve: cert.Curve_CURVE25519,
	}
	hostCertificate, err := tbs.Sign(f.ca, cert.Curve_CURVE25519, f.caPrivateKey)
	if err != nil {
		t.Fatalf("sign host certificate: %v", err)
	}
	pemBytes, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatalf("marshal host certificate: %v", err)
	}
	return Snapshot{
		ID: id, HostID: "host-" + id, CertificatePEM: string(pemBytes),
		Profile: AgentProfile{
			NebulaConfigPath: "/etc/nebula/config.yml", NebulaCAPath: "/etc/nebula/ca.crt",
			NebulaCertPath: "/etc/nebula/host.crt", NebulaKeyPath: "/etc/nebula/host.key",
		},
		Config: ConfigSnapshot{ReportedName: name, ListenHost: "0.0.0.0", ListenPort: 4242},
	}
}

// Importing a mesh must carry over what an existing gateway's certificate
// already authorizes. Dropping it would let the import succeed and then strip
// the gateway's routing authority at the next re-issuance — blackholing the
// LAN behind it, with nothing in the import report to explain why.
func TestReconcile_CapturesUnsafeNetworksFromCertificate(t *testing.T) {
	fixture := newCertificateFixture(t)
	snapshot := fixture.snapshotWithUnsafeNetworks(t, "s-gw", "gw", "10.42.0.99/16", []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.10.0.0/16"),
	})

	report := fixture.reconcile(snapshot)

	if len(report.Proposal.Hosts) != 1 {
		t.Fatalf("got %d host proposals, want 1", len(report.Proposal.Hosts))
	}
	got := report.Proposal.Hosts[0].Host.UnsafeNetworks
	want := []string{"10.10.0.0/16", "192.168.1.0/24"} // sorted
	if len(got) != len(want) {
		t.Fatalf("unsafe networks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unsafe networks[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReconcile_OrdinaryHostImportsNoUnsafeNetworks(t *testing.T) {
	fixture := newCertificateFixture(t)
	snapshot := fixture.snapshot(t, "s-1", "plain", "10.42.0.10/16", nil)

	report := fixture.reconcile(snapshot)

	if len(report.Proposal.Hosts) != 1 {
		t.Fatalf("got %d host proposals, want 1", len(report.Proposal.Hosts))
	}
	if got := report.Proposal.Hosts[0].Host.UnsafeNetworks; len(got) != 0 {
		t.Errorf("unsafe networks = %v, want none", got)
	}
}

// An imported certificate whose unsafe network overlaps the target overlay
// would shadow real mesh peers once imported, so it blocks the preview rather
// than landing a config that blackholes traffic to those peers. The fixture's
// target network is 10.42.0.0/16 (see certificateFixture.reconcile).
func TestReconcile_BlocksUnsafeNetworkOverlappingOverlay(t *testing.T) {
	fixture := newCertificateFixture(t)
	snapshot := fixture.snapshotWithUnsafeNetworks(t, "s-gw", "gw", "10.42.0.99/16", []netip.Prefix{
		netip.MustParsePrefix("10.42.5.0/24"),
	})

	report := fixture.reconcile(snapshot)

	var found bool
	for _, issue := range report.Blockers {
		if issue.Code == IssueInvalidUnsafeNetworks {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an %s blocker; got %#v", IssueInvalidUnsafeNetworks, report.Blockers)
	}
}
