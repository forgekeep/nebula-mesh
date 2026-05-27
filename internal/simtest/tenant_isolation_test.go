package simtest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// TestSim_TenantIsolation exercises the TENANT_ISOLATION invariant from ADR
// 0009 against the repo's most advisory-prone area. Two non-admin operators
// each own a CA; a host owned by one (via its CA) must be invisible and
// immutable to the other. Authz gates on CA ownership (internal/api/authz.go),
// so this checks that gate holds across read, every mutation, and list.
func TestSim_TenantIsolation(t *testing.T) {
	h := New(t)
	netID := h.CreateNetwork("iso-net", "10.70.0.0/16")
	alice := h.NewTenant("alice")
	bob := h.NewTenant("bob")
	aHost := h.CreateHostUnderCA(netID, alice.CAID, "alice-host", "10.70.0.10")

	// Sanity: the owner and an admin can read the host (so a deny below is
	// isolation, not a broken fixture).
	if code := h.APIAs(alice.Key, http.MethodGet, "/api/v1/hosts/"+aHost, nil, nil); code != http.StatusOK {
		t.Fatalf("owner alice GET own host: HTTP %d, want 200", code)
	}
	if code := h.API(http.MethodGet, "/api/v1/hosts/"+aHost, nil, nil); code != http.StatusOK {
		t.Fatalf("admin GET host: HTTP %d, want 200", code)
	}

	// Bob (a different tenant) must be denied read and every mutation.
	probes := []struct {
		op, method, path string
		body             any
	}{
		{"read", http.MethodGet, "/api/v1/hosts/" + aHost, nil},
		{"update", http.MethodPatch, "/api/v1/hosts/" + aHost, map[string]any{"name": "pwned"}},
		{"block", http.MethodPost, "/api/v1/hosts/" + aHost + "/block", nil},
		{"delete", http.MethodDelete, "/api/v1/hosts/" + aHost, nil},
	}
	for _, p := range probes {
		if code := h.APIAs(bob.Key, p.method, p.path, p.body, nil); code != http.StatusForbidden {
			t.Errorf("TENANT_ISOLATION: bob %s of alice's host = HTTP %d; want 403 forbidden", p.op, code)
		}
	}

	// Bob's host list must not reveal alice's host.
	var list json.RawMessage
	if code := h.APIAs(bob.Key, http.MethodGet, "/api/v1/hosts", nil, &list); code != http.StatusOK {
		t.Fatalf("bob list hosts: HTTP %d, want 200", code)
	}
	if bytes.Contains(list, []byte(aHost)) {
		t.Errorf("TENANT_ISOLATION: alice's host %q leaked into bob's host list: %s", aHost, list)
	}

	// The host must survive bob's failed mutations intact.
	if code := h.APIAs(alice.Key, http.MethodGet, "/api/v1/hosts/"+aHost, nil, nil); code != http.StatusOK {
		t.Errorf("alice's host not intact after bob's probes: HTTP %d", code)
	}
}
