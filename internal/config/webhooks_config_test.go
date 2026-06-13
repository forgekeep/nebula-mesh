package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeAndLoad(t *testing.T, body string) (*ServerConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadServerConfig(path)
}

func TestWebhooksConfig_Parses(t *testing.T) {
	cfg, err := writeAndLoad(t, `
master_key: ""
webhooks:
  enabled: true
  url: https://hooks.example.com/nebula
  hmac_secret: s3cret
  events: [host.enrolled, host.blocked]
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Webhooks.Enabled || cfg.Webhooks.URL != "https://hooks.example.com/nebula" {
		t.Fatalf("webhooks not parsed: %+v", cfg.Webhooks)
	}
	if len(cfg.Webhooks.Events) != 2 || cfg.Webhooks.Events[0] != "host.enrolled" {
		t.Errorf("events = %v", cfg.Webhooks.Events)
	}
}

func TestWebhooksConfig_RejectsPrivateURL(t *testing.T) {
	_, err := writeAndLoad(t, `
master_key: ""
webhooks:
  enabled: true
  url: http://127.0.0.1:9000/hook
`)
	if err == nil {
		t.Fatal("expected SSRF rejection of a loopback webhooks.url")
	}
}

func TestWebhooksConfig_AllowsPrivateWhenOptedIn(t *testing.T) {
	cfg, err := writeAndLoad(t, `
master_key: ""
webhooks:
  enabled: true
  url: http://127.0.0.1:9000/hook
  allow_private: true
`)
	if err != nil {
		t.Fatalf("load with allow_private: %v", err)
	}
	if !cfg.Webhooks.AllowPrivate {
		t.Error("allow_private not parsed")
	}
}
