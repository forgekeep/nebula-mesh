package config

import (
	"errors"
	"testing"
)

func TestRequireSecureBind(t *testing.T) {
	tlsOn := func(c *ServerConfig) { c.TLSCert = "cert.pem"; c.TLSKey = "key.pem" }

	tests := []struct {
		name    string
		listen  string
		tls     bool
		allow   bool
		wantErr bool
	}{
		{name: "tls on external", listen: ":8080", tls: true, wantErr: false},
		{name: "tls on wildcard", listen: "0.0.0.0:8080", tls: true, wantErr: false},

		{name: "plaintext loopback v4", listen: "127.0.0.1:8080", wantErr: false},
		{name: "plaintext loopback v6", listen: "[::1]:8080", wantErr: false},
		{name: "plaintext localhost", listen: "localhost:8080", wantErr: false},

		{name: "plaintext empty host (all ifaces)", listen: ":8080", wantErr: true},
		{name: "plaintext wildcard v4", listen: "0.0.0.0:8080", wantErr: true},
		{name: "plaintext wildcard v6", listen: "[::]:8080", wantErr: true},
		{name: "plaintext routable v4", listen: "10.0.0.5:8080", wantErr: true},

		{name: "plaintext external with opt-out", listen: ":8080", allow: true, wantErr: false},
		{name: "plaintext routable with opt-out", listen: "0.0.0.0:8080", allow: true, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ServerConfig{Listen: tt.listen, AllowInsecureHTTP: tt.allow}
			if tt.tls {
				tlsOn(cfg)
			}
			err := cfg.RequireSecureBind()
			if tt.wantErr && err == nil {
				t.Fatalf("RequireSecureBind() = nil, want error for listen=%q tls=%v allow=%v", tt.listen, tt.tls, tt.allow)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("RequireSecureBind() = %v, want nil for listen=%q tls=%v allow=%v", err, tt.listen, tt.tls, tt.allow)
			}
		})
	}
}

func TestRequireSecureBind_ErrorIsActionable(t *testing.T) {
	cfg := &ServerConfig{Listen: "0.0.0.0:8080"}
	err := cfg.RequireSecureBind()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"tls_cert", "allow_insecure_http", "loopback"} {
		if !errors.Is(err, err) || !contains(err.Error(), want) {
			t.Errorf("error message %q missing actionable hint %q", err.Error(), want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
