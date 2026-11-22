package releaseconfig

import (
	"path/filepath"
	"strings"
	"testing"
)

// SEC-PACKAGE-001: keep a single verified installer instead of letting
// the two service roles acquire independent verification rules.
func TestServiceRolesUseSharedVerifiedInstaller(t *testing.T) {
	for _, role := range []string{"nebula_agent", "nebula_mgmt"} {
		t.Run(role, func(t *testing.T) {
			source := readFile(t, filepath.Join(repositoryRoot(t), "deploy/ansible/roles", role, "tasks/main.yml"))
			if !strings.Contains(source, "name: nebula_verified_package") || strings.Contains(source, "ansible.builtin.get_url:") || strings.Contains(source, "ansible.builtin.apt:") || strings.Contains(source, "ansible.builtin.dnf:") {
				t.Fatal("service role must delegate package verification and installation to the common role")
			}
		})
	}
}
