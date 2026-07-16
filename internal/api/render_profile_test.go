package api

import (
	"context"
	"strings"
	"testing"
)

func TestRenderHostConfigUsesStoredAgentProfile(t *testing.T) {
	srv, sqliteStore := newTestServer(t)
	networkID := createNetwork(t, srv)
	host := renderTestHost(t, srv, networkID)
	_, err := sqliteStore.DB().ExecContext(context.Background(), `INSERT INTO host_agent_profiles (
		host_id, mesh_import_id, nebula_config_path, nebula_ca_path,
		nebula_cert_path, nebula_key_path, config_ack_v1
	) VALUES (?, NULL, ?, ?, ?, ?, 1)`, host.ID,
		"/custom/nebula/node.yml", "/custom/pki/root.pem", "/custom/pki/node.pem", "/custom/pki/node.key")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := srv.renderHostConfig(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/custom/pki/root.pem", "/custom/pki/node.pem", "/custom/pki/node.key"} {
		if !strings.Contains(string(rendered), path) {
			t.Errorf("rendered config does not contain %s\n%s", path, rendered)
		}
	}
}
