package config

import "testing"

// #188: SSRF guards for alerts.webhook_url and oidc.issuer.

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		allowPrivate bool
		wantErr      bool
	}{
		{name: "public https ok", url: "https://hooks.example.com/x", wantErr: false},
		{name: "public http ok", url: "http://alerts.example.com/x", wantErr: false},
		{name: "non-http scheme rejected", url: "file:///etc/passwd", wantErr: true},
		{name: "gopher rejected", url: "gopher://evil/x", wantErr: true},
		{name: "missing host rejected", url: "https://", wantErr: true},
		{name: "loopback rejected", url: "http://127.0.0.1:9093/x", wantErr: true},
		{name: "localhost rejected", url: "http://localhost/x", wantErr: true},
		{name: "private rejected", url: "http://10.0.0.5/x", wantErr: true},
		{name: "metadata link-local rejected", url: "http://169.254.169.254/latest/meta-data/", wantErr: true},
		{name: "loopback allowed with opt-out", url: "http://127.0.0.1:9093/x", allowPrivate: true, wantErr: false},
		{name: "private allowed with opt-out", url: "http://10.0.0.5/x", allowPrivate: true, wantErr: false},
		// IPv4-mapped IPv6 forms must classify by the embedded v4 address.
		{name: "mapped loopback rejected", url: "http://[::ffff:127.0.0.1]:9093/x", wantErr: true},
		{name: "mapped private rejected", url: "http://[::ffff:10.0.0.5]/x", wantErr: true},
		{name: "mapped unspecified rejected", url: "http://[::ffff:0.0.0.0]/x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(tt.url, tt.allowPrivate)
			if tt.wantErr && err == nil {
				t.Fatalf("validateWebhookURL(%q, %v) = nil, want error", tt.url, tt.allowPrivate)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateWebhookURL(%q, %v) = %v, want nil", tt.url, tt.allowPrivate, err)
			}
		})
	}
}

func TestOIDCValidate_IssuerScheme(t *testing.T) {
	base := func(issuer string) *OIDCConfig {
		return &OIDCConfig{
			Enabled:     true,
			Issuer:      issuer,
			DefaultRole: "user", // avoid tripping the admin-allowlist check
		}
	}
	tests := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{name: "https public ok", issuer: "https://idp.example.com/realm", wantErr: false},
		{name: "http public rejected", issuer: "http://idp.example.com/realm", wantErr: true},
		{name: "http loopback ok (dev)", issuer: "http://localhost:5556/dex", wantErr: false},
		{name: "http 127.0.0.1 ok (dev)", issuer: "http://127.0.0.1:5556/dex", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := base(tt.issuer).Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("issuer %q: Validate() = nil, want error", tt.issuer)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("issuer %q: Validate() = %v, want nil", tt.issuer, err)
			}
		})
	}
}
