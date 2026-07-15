package meshimport

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestReconcileDerivesIdentityFromCertificate(t *testing.T) {
	fixture := newCertificateFixture(t)
	snapshot := fixture.snapshot(t, "snapshot-a", "node-a", "10.42.0.10/24", []string{"ops"})
	snapshot.Config.ReportedName = "config-name"

	report := Reconcile(ReconcileInput{
		NetworkID: "network-1", CAID: "ca-1", NetworkCIDRs: []string{"10.42.0.0/16"},
		CACertificatePEM: fixture.caPEM, CAFingerprint: fixture.caFingerprint,
		Snapshots: []Snapshot{snapshot}, Now: fixture.now,
	})

	if len(report.Blockers) != 0 {
		t.Fatalf("blockers = %#v", report.Blockers)
	}
	requireIssueCode(t, report.Warnings, IssueConfigNameMismatch)
	if len(report.Proposal.Hosts) != 1 {
		t.Fatalf("proposal hosts = %d, want 1", len(report.Proposal.Hosts))
	}
	host := report.Proposal.Hosts[0].Host
	if host.Name != "node-a" || !reflect.DeepEqual(host.Groups, []string{"ops"}) || !reflect.DeepEqual(host.NebulaIPs, []string{"10.42.0.10"}) {
		t.Fatalf("certificate-derived host = %#v", host)
	}
}

func TestReconcileRejectsInvalidCertificateAddresses(t *testing.T) {
	fixture := newCertificateFixture(t)
	tests := []struct {
		name      string
		snapshots []Snapshot
		code      string
	}{
		{
			name: "outside network",
			snapshots: []Snapshot{
				fixture.snapshot(t, "outside", "outside", "10.99.0.10/24", nil),
			},
			code: IssueAddressOutsideNetwork,
		},
		{
			name: "duplicate address",
			snapshots: []Snapshot{
				fixture.snapshot(t, "one", "one", "10.42.0.10/24", nil),
				fixture.snapshot(t, "two", "two", "10.42.0.10/24", nil),
			},
			code: IssueDuplicateOverlayAddress,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := Reconcile(ReconcileInput{
				NetworkID: "network-1", CAID: "ca-1", NetworkCIDRs: []string{"10.42.0.0/16"},
				CACertificatePEM: fixture.caPEM, CAFingerprint: fixture.caFingerprint,
				Snapshots: test.snapshots, Now: fixture.now,
			})
			requireIssueCode(t, report.Blockers, test.code)
		})
	}
}

func TestReconcileRejectsCertificateFromAnotherCA(t *testing.T) {
	fixture := newCertificateFixture(t)
	otherCA := newCertificateFixture(t)
	foreign := otherCA.snapshot(t, "foreign", "foreign", "10.42.0.10/24", nil)

	report := fixture.reconcile(foreign)
	requireIssueCode(t, report.Blockers, IssueInvalidHostCertificate)
	if len(report.Proposal.Hosts) != 0 {
		t.Fatalf("unverified certificate produced a Host proposal: %#v", report.Proposal.Hosts)
	}
}

func TestReconcileTopologyAndEndpoints(t *testing.T) {
	fixture := newCertificateFixture(t)
	lighthouse := fixture.snapshot(t, "lh", "lighthouse", "10.42.0.1/24", []string{"infra"})
	lighthouse.Config.AmLighthouse = true
	lighthouse.Config.ListenPort = 4242
	client := fixture.snapshot(t, "client", "client", "10.42.0.2/24", nil)
	client.Config.LighthouseHosts = []string{"10.42.0.1"}
	client.Config.StaticHostMap = map[string][]string{"10.42.0.1": {"203.0.113.10:4242"}}

	report := fixture.reconcile(lighthouse, client)
	if len(report.Blockers) != 0 {
		t.Fatalf("blockers = %#v", report.Blockers)
	}
	var found bool
	for _, proposal := range report.Proposal.Hosts {
		if proposal.Host.Name == "lighthouse" {
			found = true
			if !proposal.Host.IsLighthouse || proposal.Host.PublicIP != "203.0.113.10" || proposal.Host.ListenPort != 4242 {
				t.Fatalf("lighthouse proposal = %#v", proposal.Host)
			}
		}
	}
	if !found {
		t.Fatal("lighthouse host missing from proposal")
	}
}

func TestReconcileRejectsTopologyConflicts(t *testing.T) {
	fixture := newCertificateFixture(t)
	lighthouse := fixture.snapshot(t, "lh", "lighthouse", "10.42.0.1/24", nil)
	lighthouse.Config.AmLighthouse = true
	clientA := fixture.snapshot(t, "client-a", "client-a", "10.42.0.2/24", nil)
	clientA.Config.LighthouseHosts = []string{"10.42.0.1"}
	clientA.Config.StaticHostMap = map[string][]string{"10.42.0.1": {"203.0.113.10:4242"}}
	clientB := fixture.snapshot(t, "client-b", "client-b", "10.42.0.3/24", nil)
	clientB.Config.LighthouseHosts = []string{"10.42.0.1"}
	clientB.Config.StaticHostMap = map[string][]string{"10.42.0.1": {"203.0.113.11:4242"}}
	report := fixture.reconcile(lighthouse, clientA, clientB)
	requireIssueCode(t, report.Blockers, IssueEndpointConflict)

	unresolved := fixture.snapshot(t, "unresolved", "unresolved", "10.42.0.4/24", nil)
	unresolved.Config.LighthouseHosts = []string{"10.42.0.99"}
	unresolved.Config.Relays = []string{"10.42.0.98"}
	report = fixture.reconcile(unresolved)
	requireIssueCode(t, report.Blockers, IssueUnresolvedLighthouse)
	requireIssueCode(t, report.Blockers, IssueUnresolvedRelay)
}

func TestReconcileFirewallUnsafeRoutesAndUnsupportedKeys(t *testing.T) {
	fixture := newCertificateFixture(t)
	first := fixture.snapshot(t, "first", "first", "10.42.0.10/24", []string{"ops"})
	second := fixture.snapshot(t, "second", "second", "10.42.0.11/24", []string{"ops"})
	policy := FirewallPolicy{
		Inbound:  []FirewallRule{{Port: "22", Proto: "tcp", Group: "ops"}},
		Outbound: []FirewallRule{{Port: "any", Proto: "any", Group: "any"}},
	}
	first.Config.Firewall = policy
	second.Config.Firewall = policy
	first.Config.UnsafeRoutes = []UnsafeRoute{{Route: "192.0.2.0/24", Via: "10.42.0.1"}}

	report := fixture.reconcile(first, second)
	if len(report.Blockers) != 0 {
		t.Fatalf("blockers = %#v", report.Blockers)
	}
	if !reflect.DeepEqual(report.Proposal.Firewall, policy) {
		t.Fatalf("firewall proposal = %#v", report.Proposal.Firewall)
	}
	if got := report.Proposal.Hosts[0].Host.Advanced; got == nil || len(got.UnsafeRoutes) != 1 {
		t.Fatalf("unsafe routes were not preserved: %#v", report.Proposal.Hosts)
	}

	second.Config.Firewall.Inbound = []FirewallRule{{Port: "443", Proto: "tcp", Group: "ops"}}
	second.Config.UnsupportedKeys = []string{"sshd.host_key", "stats.message_metrics"}
	report = fixture.reconcile(first, second)
	requireIssueCode(t, report.Blockers, IssueDivergentFirewall)
	requireIssueCode(t, report.Warnings, IssueUnsupportedConfigKey)

	second.Config.UnsupportedKeys = []string{"handshakes.try_interval"}
	report = fixture.reconcile(first, second)
	requireIssueCode(t, report.Blockers, IssueUnsupportedConfigKey)
}

func TestReconcileBlocklistAndCARoots(t *testing.T) {
	fixture := newCertificateFixture(t)
	first := fixture.snapshot(t, "first", "first", "10.42.0.10/24", nil)
	second := fixture.snapshot(t, "second", "second", "10.42.0.11/24", nil)
	first.Config.Blocklist = []string{"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	second.Config.Blocklist = []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	first.Config.CARootFingerprints = []string{fixture.caFingerprint}
	second.Config.CARootFingerprints = []string{fixture.caFingerprint}

	report := fixture.reconcile(first, second)
	if len(report.Blockers) != 0 {
		t.Fatalf("blockers = %#v", report.Blockers)
	}
	want := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if !reflect.DeepEqual(report.Proposal.Blocklist, want) {
		t.Fatalf("blocklist = %#v, want %#v", report.Proposal.Blocklist, want)
	}

	second.Config.Blocklist = []string{"not-a-fingerprint"}
	second.Config.CARootFingerprints = []string{fixture.caFingerprint, "extra-root"}
	report = fixture.reconcile(first, second)
	requireIssueCode(t, report.Blockers, IssueInvalidBlocklist)
	requireIssueCode(t, report.Blockers, IssueDivergentBlocklist)
	requireIssueCode(t, report.Blockers, IssueExtraCARoot)
}

func TestReconcileMarksHostWhoseCertificateIsBlocklisted(t *testing.T) {
	fixture := newCertificateFixture(t)
	revoked := fixture.snapshot(t, "revoked", "revoked", "10.42.0.10/24", nil)
	ordinary := fixture.snapshot(t, "ordinary", "ordinary", "10.42.0.11/24", nil)
	certificate, _, err := cert.UnmarshalCertificateFromPEM([]byte(revoked.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	blocklist := []string{"  " + strings.ToUpper(fingerprint) + "  "}
	revoked.Config.Blocklist = blocklist
	ordinary.Config.Blocklist = blocklist

	report := fixture.reconcile(revoked, ordinary)
	if len(report.Blockers) != 0 {
		t.Fatalf("blockers = %#v", report.Blockers)
	}
	statuses := make(map[string]models.HostStatus)
	for _, proposal := range report.Proposal.Hosts {
		statuses[proposal.SnapshotID] = proposal.Host.Status
	}
	if statuses[revoked.ID] != models.HostStatusBlocked {
		t.Fatalf("revoked status = %q, want blocked", statuses[revoked.ID])
	}
	if statuses[ordinary.ID] != models.HostStatusImporting {
		t.Fatalf("ordinary status = %q, want importing", statuses[ordinary.ID])
	}
}

func TestReconcileCertificateExpiryWarningsAndBlockers(t *testing.T) {
	base := newCertificateFixture(t)
	near := base.snapshotWithValidity(t, "near", "near", "10.42.0.10/24", base.now.Add(-time.Hour), base.now.Add(12*time.Hour))
	report := base.reconcile(near)
	requireIssueCode(t, report.Warnings, IssueHostCertificateNearExpiry)

	expired := base.snapshotWithValidity(t, "expired", "expired", "10.42.0.11/24", base.now.Add(-2*time.Hour), base.now.Add(-time.Hour))
	report = base.reconcile(expired)
	requireIssueCode(t, report.Blockers, IssueHostCertificateExpired)

	nearCA := newCertificateFixtureWithValidity(t, base.now.Add(-24*time.Hour), base.now.Add(12*time.Hour))
	report = nearCA.reconcile(nearCA.snapshotWithValidity(t, "host", "host", "10.42.0.12/24", base.now.Add(-time.Hour), base.now.Add(6*time.Hour)))
	requireIssueCode(t, report.Warnings, IssueCACertificateNearExpiry)

	expiredCA := newCertificateFixtureWithValidity(t, base.now.Add(-48*time.Hour), base.now.Add(-time.Hour))
	report = expiredCA.reconcile(expiredCA.snapshotWithValidity(t, "host", "host", "10.42.0.13/24", base.now.Add(-3*time.Hour), base.now.Add(-2*time.Hour)))
	requireIssueCode(t, report.Blockers, IssueCACertificateExpired)
}

func TestReconcileIsDeterministicAcrossArrivalOrder(t *testing.T) {
	fixture := newCertificateFixture(t)
	first := fixture.snapshot(t, "b", "bravo", "10.42.0.20/24", nil)
	second := fixture.snapshot(t, "a", "alpha", "10.42.0.10/24", nil)
	first.Config.UnsupportedKeys = []string{"z.key", "a.key"}
	second.Config.ReportedName = "wrong"

	forward := fixture.reconcile(first, second)
	reverse := fixture.reconcile(second, first)
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("reconciliation depends on arrival order:\nforward=%#v\nreverse=%#v", forward, reverse)
	}
}

type certificateFixture struct {
	now           time.Time
	ca            cert.Certificate
	caPrivateKey  ed25519.PrivateKey
	caPEM         string
	caFingerprint string
}

func newCertificateFixture(t *testing.T) certificateFixture {
	t.Helper()
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	return newCertificateFixtureWithValidityAt(t, now, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
}

func newCertificateFixtureWithValidity(t *testing.T, notBefore, notAfter time.Time) certificateFixture {
	t.Helper()
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	return newCertificateFixtureWithValidityAt(t, now, notBefore, notAfter)
}

func newCertificateFixtureWithValidityAt(t *testing.T, now, notBefore, notAfter time.Time) certificateFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tbs := &cert.TBSCertificate{
		Version: cert.Version2, Name: "Imported CA", IsCA: true,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Groups:   []string{"ops", "infra"}, NotBefore: notBefore, NotAfter: notAfter,
		PublicKey: publicKey, Curve: cert.Curve_CURVE25519,
	}
	caCertificate, err := tbs.Sign(nil, cert.Curve_CURVE25519, privateKey)
	if err != nil {
		t.Fatalf("sign CA: %v", err)
	}
	pemBytes, err := caCertificate.MarshalPEM()
	if err != nil {
		t.Fatalf("marshal CA: %v", err)
	}
	fingerprint, err := caCertificate.Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint CA: %v", err)
	}
	return certificateFixture{now: now, ca: caCertificate, caPrivateKey: privateKey, caPEM: string(pemBytes), caFingerprint: fingerprint}
}

func (f certificateFixture) snapshot(t *testing.T, id, name, network string, groups []string) Snapshot {
	t.Helper()
	return f.snapshotWithValidity(t, id, name, network, f.now.Add(-time.Hour), f.now.Add(90*24*time.Hour), groups...)
}

func (f certificateFixture) snapshotWithValidity(t *testing.T, id, name, network string, notBefore, notAfter time.Time, groups ...string) Snapshot {
	t.Helper()
	tbs := &cert.TBSCertificate{
		Version: cert.Version2, Name: name, Networks: []netip.Prefix{netip.MustParsePrefix(network)},
		Groups: groups, NotBefore: notBefore, NotAfter: notAfter,
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

func (f certificateFixture) reconcile(snapshots ...Snapshot) Report {
	return Reconcile(ReconcileInput{
		NetworkID: "network-1", CAID: "ca-1", NetworkCIDRs: []string{"10.42.0.0/16"},
		CACertificatePEM: f.caPEM, CAFingerprint: f.caFingerprint,
		Snapshots: snapshots, Now: f.now, NearExpiryWindow: 24 * time.Hour,
	})
}

func requireIssueCode(t *testing.T, issues []Issue, code string) {
	t.Helper()
	for _, issue := range issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("issue %q not found in %#v", code, issues)
}
