package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	nebulaconfig "github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"

	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// SEC-PERSIST-001: a successful persistence/delivery decision is not the
// oracle. Real Nebula engines exchange UDP packets on loopback and expose
// the authenticated tunnel state and actual blocklist handshake refusal.
func TestRevocationEnforcedByNebulaAcrossCAOverlap(t *testing.T) {
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	require.NoError(t, s.Migrate(ctx))
	owner := &models.Operator{ID: "fixture-owner", Username: "fixture-owner", PasswordHash: "fixture-hash", Role: models.OperatorRoleAdmin, Status: models.OperatorStatusActive}
	require.NoError(t, s.CreateOperator(ctx, owner))
	original, err := pki.NewCA("fixture-original-ca", 24*time.Hour)
	require.NoError(t, err)
	t.Cleanup(original.Wipe)
	successor, err := pki.NewCA("fixture-successor-ca", 24*time.Hour)
	require.NoError(t, err)
	t.Cleanup(successor.Wipe)
	originalPEM, err := original.CACertPEM()
	require.NoError(t, err)
	successorPEM, err := successor.CACertPEM()
	require.NoError(t, err)
	fingerprint, err := original.CACertFingerprint()
	require.NoError(t, err)
	ca := &models.CA{ID: "fixture-ca", Name: "fixture-original-ca", OwnerOperatorID: owner.ID, CertPEM: string(originalPEM), Fingerprint: fingerprint, Status: models.CAStatusActive,
		// Only the public certificate and ownership are read by revocation.
		EncryptedKeyDEK: []byte{0}, EncryptedKeyMaterial: []byte{0}, NonceDEK: []byte{0}, NonceKey: []byte{0}}
	require.NoError(t, s.CreateCA(ctx, ca))
	network := &models.Network{ID: "fixture-network", Name: "fixture", CAID: ca.ID, CIDRs: []string{"192.0.2.0/24"}}
	require.NoError(t, s.CreateNetwork(ctx, network))
	host := &models.Host{ID: "fixture-target", Name: "target", NetworkID: network.ID, CAID: ca.ID, NebulaIPs: []string{"192.0.2.2"}, Status: models.HostStatusPending, Kind: models.HostKindAgent, Role: models.HostRoleHost}
	require.NoError(t, s.CreateHost(ctx, host))

	gateway := revocationFixtureIdentity(t, original, "gateway", "192.0.2.1")
	previous := revocationFixtureIdentity(t, original, "previous", "192.0.2.2")
	current := revocationFixtureIdentity(t, original, "current", "192.0.2.2")
	allowed := revocationFixtureIdentity(t, original, "allowed", "192.0.2.3")
	next := revocationFixtureIdentity(t, successor, "successor-peer", "192.0.2.4")
	require.NoError(t, s.SaveCertificateAndEnrollHost(ctx, host.ID, previous.pem, previous.fp, previous.cert.NotBefore(), previous.cert.NotAfter()))
	require.NoError(t, s.SaveCertificateAndUpdateHostCert(ctx, host.ID, previous.fp, current.pem, current.fp, current.cert.NotBefore(), current.cert.NotAfter()))

	var rejected atomic.Int64
	gatewayLogger := slog.New(&revocationLog{count: &rejected, handler: log.Handler()})
	gwPort := revocationUDPPort(t)
	gwConfig := func(bundle []byte, blocklist []string) string {
		return revocationConfig(t, gateway, gwPort, 0, bundle, blocklist)
	}
	gw, configuration := startRevocationPeer(t, gatewayLogger, gwConfig(originalPEM, nil))
	start := func(peer revocationIdentity, roots []byte) *nebula.Control {
		control, _ := startRevocationPeer(t, log, revocationConfig(t, peer, revocationUDPPort(t), gwPort, roots, nil))
		return control
	}
	old := start(previous, originalPEM)
	waitRevocationTunnel(t, old, gw, gateway.addr, previous.addr)
	old.Stop()
	require.NoError(t, old.Wait())
	require.Eventually(t, func() bool { return gw.GetCertByVpnIp(previous.addr) == nil }, 5*time.Second, 20*time.Millisecond)
	target := start(current, originalPEM)
	control := start(allowed, originalPEM)
	waitRevocationTunnel(t, target, gw, gateway.addr, current.addr)
	waitRevocationTunnel(t, control, gw, gateway.addr, allowed.addr)

	_, err = s.BlockHostForOperator(ctx, owner.ID, host.ID, "fixture block")
	require.NoError(t, err)
	blocklist, err := s.GetBlocklistForCA(ctx, ca.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{previous.fp, current.fp}, blocklist)
	require.Error(t, configuration.ReloadConfigString("pki: [unterminated").Err)
	require.NotNil(t, gw.GetCertByVpnIp(current.addr), "failed reload should not be mistaken for enforcement")

	overlap := bytes.Join([][]byte{originalPEM, successorPEM}, []byte("\n"))
	result := configuration.ReloadConfigString(gwConfig(overlap, blocklist))
	require.NoError(t, result.Err)
	require.False(t, result.Failed, result.String())
	require.Eventually(t, func() bool { return gw.GetCertByVpnIp(current.addr) == nil }, 8*time.Second, 20*time.Millisecond, "established blocked tunnel survived")
	require.NotNil(t, gw.GetCertByVpnIp(allowed.addr), "overlap reload disconnected the allowed peer")
	successorPeer := start(next, overlap)
	waitRevocationTunnel(t, successorPeer, gw, gateway.addr, next.addr)
	for _, peer := range []revocationIdentity{current, previous} {
		target.Stop()
		require.NoError(t, target.Wait())
		before := rejected.Load()
		target = start(peer, overlap)
		target.CreateTunnel(gateway.addr)
		require.Eventually(t, func() bool { return rejected.Load() > before }, 5*time.Second, 20*time.Millisecond, "Nebula did not reject the %s generation", peer.cert.Name())
		require.Nil(t, gw.GetCertByVpnIp(peer.addr))
	}
	require.NotNil(t, control.GetCertByVpnIp(gateway.addr))
}

type revocationIdentity struct {
	addr     netip.Addr
	cert     cert.Certificate
	pem, key []byte
	fp       string
}

func revocationFixtureIdentity(t *testing.T, ca *pki.CAManager, name, ip string) revocationIdentity {
	t.Helper()
	key := make([]byte, curve25519.ScalarSize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	pub, err := curve25519.X25519(key, curve25519.Basepoint)
	require.NoError(t, err)
	addr := netip.MustParseAddr(ip)
	c, err := ca.Sign(pki.SignRequest{Name: name, PublicKey: pub, Networks: []netip.Prefix{netip.PrefixFrom(addr, 24)}, Duration: time.Hour})
	require.NoError(t, err)
	pem, err := c.MarshalPEM()
	require.NoError(t, err)
	fp, err := c.Fingerprint()
	require.NoError(t, err)
	return revocationIdentity{addr: addr, cert: c, pem: pem, key: cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, key), fp: fp}
}

func revocationUDPPort(t *testing.T) int {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := socket.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, socket.Close())
	return port
}

func revocationConfig(t *testing.T, id revocationIdentity, port, gatewayPort int, roots []byte, list []string) string {
	t.Helper()
	rules := []configgen.FirewallRule{{Port: "any", Proto: "any", Group: "any"}}
	input := configgen.GeneratorInput{HostName: id.cert.Name(), NebulaIPs: []string{id.addr.String()}, ListenHost: "127.0.0.1", ListenPort: port, IsLighthouse: gatewayPort == 0, CACertPEM: string(roots), CertPEM: string(id.pem), KeyPEM: string(id.key), Blocklist: list, FirewallInbound: rules, FirewallOutbound: rules}
	if gatewayPort != 0 {
		input.Lighthouses = []configgen.LighthouseInfo{{NebulaIPs: []string{"192.0.2.1"}, PublicAddr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(gatewayPort)).String()}}
	} // #nosec G115 -- a UDP port is uint16
	raw, err := configgen.Generate(input)
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &cfg))

	cfg["timers"] = map[string]any{"connection_alive_interval": 1, "pending_deletion_interval": 1}
	cfg["local_api"] = map[string]any{"enabled": false}
	cfg["logging"] = map[string]any{"level": "debug"}
	raw, err = yaml.Marshal(cfg)
	require.NoError(t, err)
	return string(raw)
}

func startRevocationPeer(t *testing.T, log *slog.Logger, raw string) (*nebula.Control, *nebulaconfig.C) {
	t.Helper()
	cfg := nebulaconfig.NewC(log)
	require.NoError(t, cfg.LoadString(raw))
	// Use Nebula's userspace device: no privileges or real host routes, and
	// no shutdown race in the v1.12.0 disabled-TUN implementation.
	c, err := nebula.Main(cfg, false, "revocation-fixture", log, overlay.NewUserDeviceFromConfig)
	require.NoError(t, err)
	t.Cleanup(func() { c.Stop(); require.NoError(t, c.Wait()) })
	require.NoError(t, c.Start())
	return c, cfg
}

func waitRevocationTunnel(t *testing.T, from, to *nebula.Control, toIP, fromIP netip.Addr) {
	t.Helper()
	from.CreateTunnel(toIP)
	require.Eventually(t, func() bool { return from.GetCertByVpnIp(toIP) != nil && to.GetCertByVpnIp(fromIP) != nil }, 5*time.Second, 20*time.Millisecond)
}

type revocationLog struct {
	count   *atomic.Int64
	handler slog.Handler
}

func (h *revocationLog) Enabled(context.Context, slog.Level) bool { return true }
func (h *revocationLog) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "Failed to process handshake packet" {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "error" && strings.Contains(a.Value.String(), cert.ErrBlockListed.Error()) {
				h.count.Add(1)
			}
			return true
		})
	}
	return h.handler.Handle(ctx, r)
}
func (h *revocationLog) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &revocationLog{h.count, h.handler.WithAttrs(attrs)}
}
func (h *revocationLog) WithGroup(group string) slog.Handler {
	return &revocationLog{h.count, h.handler.WithGroup(group)}
}
