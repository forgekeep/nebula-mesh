package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// stopPropagatingDirectives are the systemd dependency types that make
// systemd stop or restart this unit when the named unit stops or restarts.
// After= and Wants= are ordering/weak-dependency only and stay allowed.
var stopPropagatingDirectives = []string{"PartOf", "BindsTo", "Requires", "Requisite"}

// TestSystemdUnitDoesNotCoupleAgentToNebula pins the unit half of the
// nebula_reload_command contract.
//
// The hook runs synchronously inside nebula-agent.service's control group.
// If the unit declares stop/restart propagation from nebula.service, then a
// hook that restarts Nebula — the documented `systemctl restart nebula`
// case, and the only option where `reload` is not supported — makes systemd
// tear down the agent while that very command is still running. The hook is
// killed with the cgroup, the config ack never goes out, and the restarted
// agent is handed the same update again: a restart loop that looks like a
// flapping tunnel rather than a unit-file bug.
//
// Reload delivery is only as safe as the unit shipped alongside it, so guard
// the unit from the package that implements the hook.
func TestSystemdUnitDoesNotCoupleAgentToNebula(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "systemd", "nebula-agent.service")
	unit, err := os.ReadFile(path) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}

	for i, line := range strings.Split(string(unit), "\n") {
		directive := strings.TrimSpace(line)
		if directive == "" || strings.HasPrefix(directive, "#") || strings.HasPrefix(directive, ";") {
			continue
		}
		key, value, ok := strings.Cut(directive, "=")
		if !ok {
			continue
		}
		for _, forbidden := range stopPropagatingDirectives {
			if !strings.EqualFold(strings.TrimSpace(key), forbidden) {
				continue
			}
			// Field-wise, not substring: these directives take a space
			// separated list, and "my-nebula.service" is a different unit.
			if slices.Contains(strings.Fields(value), "nebula.service") {
				t.Errorf("%s:%d: %s — %s=nebula.service propagates stops to the agent, "+
					"so a nebula_reload_command that restarts Nebula kills the hook "+
					"before it can ack (use After=/Wants= for ordering instead)",
					path, i+1, directive, forbidden)
			}
		}
	}
}
