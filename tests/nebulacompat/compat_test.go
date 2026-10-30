package nebulacompat_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"golang.org/x/crypto/curve25519"
)

// fixtureDir holds the configs the main module renders; its
// TestCompatFixturesUpToDate keeps them current.
const fixtureDir = "../../internal/configgen/testdata/nebulacompat"

// TestRenderedConfigsLoadOnOldestSupportedRelease runs every fixture through
// Nebula's own config test (`nebula -test`): PKI, firewall, lighthouse, relay
// and punchy setup, without a tun device or sockets.
func TestRenderedConfigsLoadOnOldestSupportedRelease(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join(fixtureDir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures in %s", fixtureDir)
	}
	pki := writePKI(t)
	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path) // #nosec G304 -- fixture from the repository
			if err != nil {
				t.Fatal(err)
			}
			yml := strings.NewReplacer(
				"/nebulacompat/ca.crt", pki.ca,
				"/nebulacompat/host.crt", pki.cert,
				"/nebulacompat/host.key", pki.key,
			).Replace(string(raw))

			logger := logrus.New()
			logger.Out = io.Discard
			c := config.NewC(logger)
			if err := c.LoadString(yml); err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, err := nebula.Main(c, true, "nebulacompat", logger, nil); err != nil {
				t.Fatalf("nebula config test failed: %v", err)
			}
		})
	}
}

type pkiFiles struct{ ca, cert, key string }

// writePKI signs a CA and a host certificate for 192.168.100.10/24, the
// address every fixture uses, with the old release's cert package.
func writePKI(t *testing.T) pkiFiles {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTBS := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "nebulacompat-ca",
		Networks:  []netip.Prefix{netip.MustParsePrefix("192.168.100.0/24")},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		PublicKey: caPub,
		IsCA:      true,
		Curve:     cert.Curve_CURVE25519,
	}
	ca, err := caTBS.Sign(nil, cert.Curve_CURVE25519, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	hostPriv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(hostPriv); err != nil {
		t.Fatal(err)
	}
	hostPub, err := curve25519.X25519(hostPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	hostTBS := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "web-1",
		Networks:  []netip.Prefix{netip.MustParsePrefix("192.168.100.10/24")},
		Groups:    []string{"admin"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
		PublicKey: hostPub,
		Curve:     cert.Curve_CURVE25519,
	}
	host, err := hostTBS.Sign(ca, cert.Curve_CURVE25519, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caPEM, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, err := host.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pkiFiles{
		ca:   write("ca.crt", caPEM),
		cert: write("host.crt", hostPEM),
		key:  write("host.key", cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, hostPriv)),
	}
}
