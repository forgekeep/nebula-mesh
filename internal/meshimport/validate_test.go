package meshimport

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateSnapshotRejectsOversizeAndUnsafePaths(t *testing.T) {
	valid := Snapshot{
		ID: "snapshot", HostID: "host", CertificatePEM: "certificate",
		Profile: AgentProfile{
			NebulaConfigPath: "/etc/nebula/config.yml", NebulaCAPath: "/etc/nebula/ca.crt",
			NebulaCertPath: "/etc/nebula/host.crt", NebulaKeyPath: "/etc/nebula/host.key",
		},
	}
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		err    error
	}{
		{"relative config path", func(s *Snapshot) { s.Profile.NebulaConfigPath = "etc/nebula/config.yml" }, ErrInvalidAgentPath},
		{"unclean key path", func(s *Snapshot) { s.Profile.NebulaKeyPath = "/etc/nebula/../secret.key" }, ErrInvalidAgentPath},
		{"nul cert path", func(s *Snapshot) { s.Profile.NebulaCertPath = "/etc/nebula/host\x00.crt" }, ErrInvalidAgentPath},
		{"oversize", func(s *Snapshot) { s.CertificatePEM = strings.Repeat("x", 2048) }, ErrSnapshotTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := valid
			test.mutate(&got)
			if err := ValidateSnapshot(got, Limits{MaxSnapshotBytes: 1024, MaxPathBytes: 255}); !errors.Is(err, test.err) {
				t.Fatalf("ValidateSnapshot error = %v, want %v", err, test.err)
			}
		})
	}
}
