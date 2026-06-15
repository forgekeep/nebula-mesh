package web

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/config"
)

// writeIDPCAPEM writes the TLS mock IdP's self-signed certificate to a PEM file
// and returns its path, for use as oidc.tls_ca_cert.
func writeIDPCAPEM(t *testing.T, idp *mockIDP) string {
	t.Helper()
	cert := idp.server.Certificate()
	if cert == nil {
		t.Fatal("TLS mock IdP has no certificate")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(t.TempDir(), "idp-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOIDCTLSPin_DiscoverySucceedsWithPin verifies that pinning the IdP's CA
// lets discovery succeed against an otherwise-untrusted self-signed TLS IdP.
func TestOIDCTLSPin_DiscoverySucceedsWithPin(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServerTLS(t)
	caPath := writeIDPCAPEM(t, idp)

	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
		AllowedEmails: []string{"alice@example.com"},
		DefaultRole:   "user",
		TLSCACert:     caPath,
	})
	if o == nil {
		t.Fatal("expected non-nil OIDC with valid CA pin")
	}
	if o.httpClient == nil {
		t.Error("expected pinned httpClient to be set when tls_ca_cert is configured")
	}
}

// TestOIDCTLSPin_DiscoveryFailsWithoutPin verifies that without pinning, the
// self-signed TLS IdP is rejected by the system trust store at discovery.
func TestOIDCTLSPin_DiscoveryFailsWithoutPin(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServerTLS(t)

	cfg := config.OIDCConfig{
		Enabled:       true,
		Issuer:        idp.Issuer(),
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		RedirectURL:   "https://nebula-mesh.test/ui/oidc/callback",
		AllowedEmails: []string{"alice@example.com"},
		DefaultRole:   "user",
		// No TLSCACert: the self-signed cert is not trusted.
	}
	sm := NewSessionManager(s)
	_, err := NewOIDC(context.Background(), &cfg, s, sm, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected discovery to fail against untrusted self-signed IdP without pinning")
	}
}

// TestOIDCTLSPin_BadCAFile verifies a missing or malformed CA file fails NewOIDC
// loudly instead of silently falling back to the system store.
func TestOIDCTLSPin_BadCAFile(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServerTLS(t)
	sm := NewSessionManager(s)

	base := config.OIDCConfig{
		Enabled:       true,
		Issuer:        idp.Issuer(),
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		RedirectURL:   "https://nebula-mesh.test/ui/oidc/callback",
		AllowedEmails: []string{"alice@example.com"},
		DefaultRole:   "user",
	}

	t.Run("missing file", func(t *testing.T) {
		cfg := base
		cfg.TLSCACert = filepath.Join(t.TempDir(), "does-not-exist.pem")
		if _, err := NewOIDC(context.Background(), &cfg, s, sm, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})

	t.Run("garbage file", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "garbage.pem")
		if err := os.WriteFile(bad, []byte("not a pem certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := base
		cfg.TLSCACert = bad
		if _, err := NewOIDC(context.Background(), &cfg, s, sm, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Fatal("expected error for non-PEM CA file")
		}
	})
}

// TestOIDCTLSPin_FullCallback drives the full callback flow (token exchange +
// id_token verification) against the TLS IdP with pinning, proving the pinned
// client is used end to end, not just for discovery.
func TestOIDCTLSPin_FullCallback(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServerTLS(t)
	caPath := writeIDPCAPEM(t, idp)

	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
		AllowedEmails: []string{"alice@example.com"},
		DefaultRole:   "user",
		TLSCACert:     caPath,
	})

	idp.NextIDToken(map[string]any{
		"sub":                "alice-sub",
		"aud":                "test-client",
		"email":              "alice@example.com",
		"email_verified":     true,
		"preferred_username": "alice",
		"name":               "Alice",
	})

	rec := driveCallback(t, o, "state-tlspin", "code-1")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
}
