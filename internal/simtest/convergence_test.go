package simtest

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// TestSim_ConfigConvergence exercises the CONFIG_CONVERGENCE invariant from
// ADR 0009: after a network-level config change bumps the network config
// version, every live host must converge to the new version within bounded
// polls — and exactly once (no host left stuck below the version, no host
// re-shipped config forever).
//
// This is the propagation correctness that per-request unit tests cannot
// reach: it depends on the interaction between BumpNetworkConfigVersion and
// the host-vs-network version comparison in the agent-updates handler across a
// whole fleet. The version bump is driven through the store directly — the
// production trigger is a host role change (internal/api/hosts.go), but the
// invariant under test is the delivery mechanism, not that one handler.
func TestSim_ConfigConvergence(t *testing.T) {
	const fleetSize = 25
	ctx := context.Background()

	h := New(t)
	netID := h.CreateNetwork("sim-net", "10.10.0.0/16")

	// Enroll a fleet of regular hosts and bring each to steady state.
	agents := make([]*Agent, fleetSize)
	for i := range agents {
		agents[i] = h.Enroll(netID, fmt.Sprintf("host-%02d", i), fmt.Sprintf("10.10.1.%d", i+10))
		agents[i].DrainToConverged(h, 5)
	}

	v0, err := h.Store.GetNetworkConfigVersion(ctx, netID)
	if err != nil {
		t.Fatalf("read network version: %v", err)
	}

	// A network-level config change occurs.
	if err := h.Store.BumpNetworkConfigVersion(ctx, netID); err != nil {
		t.Fatalf("bump network version: %v", err)
	}
	want := v0 + 1
	h.Journal.Add(Event{Actor: "operator", Action: "bump-version", Target: netID,
		Note: fmt.Sprintf("%d -> %d", v0, want)})

	// Propagation: the next poll for every host must deliver the new config.
	for _, a := range agents {
		if r := a.Poll(h); r.ConfigYAML == nil {
			t.Errorf("CONFIG_CONVERGENCE violated: %q did not receive config after version %d->%d\n%s",
				a.Name, v0, want, h.Journal.Report(a.HostID))
			continue
		}
		hv, err := h.Store.GetHostConfigVersion(ctx, a.HostID)
		if err != nil {
			t.Fatalf("read host version for %q: %v", a.Name, err)
		}
		if hv != want {
			t.Errorf("CONFIG_CONVERGENCE violated: %q at version %d, want %d", a.Name, hv, want)
		}
	}

	// Exactly-once: a subsequent poll must not re-ship config (no churn).
	for _, a := range agents {
		if r := a.Poll(h); r.ConfigYAML != nil {
			t.Errorf("CONFIG_CONVERGENCE violated: %q re-shipped config while already at version %d (churn)\n%s",
				a.Name, want, h.Journal.Report(a.HostID))
		}
	}
}

func TestSim_AckCapableConfigConvergenceIsAtLeastOnceAndIdempotent(t *testing.T) {
	ctx := context.Background()
	h := New(t)
	networkID := h.CreateNetwork("ack-net", "10.20.0.0/16")
	agent := h.EnrollAckCapable(networkID, "ack-host", "10.20.0.10")
	initial := agent.Poll(h)
	if initial.ConfigYAML == nil || initial.ConfigVersion <= 0 {
		t.Fatalf("initial config not pending: %#v", initial)
	}
	if status := agent.AckConfig(h, initial.ConfigVersion); status != http.StatusOK {
		t.Fatalf("initial ack status = %d", status)
	}
	if err := h.Store.BumpNetworkConfigVersion(ctx, networkID); err != nil {
		t.Fatal(err)
	}
	first := agent.Poll(h)
	second := agent.Poll(h)
	if first.ConfigYAML == nil || second.ConfigYAML == nil || first.ConfigVersion != second.ConfigVersion {
		t.Fatalf("unacked config was not delivered at least once: first=%#v second=%#v", first, second)
	}
	beforeAck, _ := h.Store.GetHostConfigVersion(ctx, agent.HostID)
	if beforeAck == first.ConfigVersion {
		t.Fatalf("send advanced applied version before ack: %d", beforeAck)
	}
	if status := agent.AckConfig(h, first.ConfigVersion); status != http.StatusOK {
		t.Fatalf("ack status = %d", status)
	}
	if status := agent.AckConfig(h, first.ConfigVersion); status != http.StatusOK {
		t.Fatalf("idempotent ack retry status = %d", status)
	}
	if applied, _ := h.Store.GetHostConfigVersion(ctx, agent.HostID); applied != first.ConfigVersion {
		t.Fatalf("applied version = %d, want %d", applied, first.ConfigVersion)
	}
	if converged := agent.Poll(h); converged.ConfigYAML != nil {
		t.Fatalf("config re-delivered after ack: %#v", converged)
	}
}
