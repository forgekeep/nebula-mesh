package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestAuditRows_AllProductionPathsConform fires a representative sample
// of write endpoints, then reads back every audit row the store emitted
// and validates each one against assertValidAuditRow. The point is to
// catch regressions where a handler:
//
//   - passes a literal action string not in the closed enum
//     (e.g. the historical "settings.enforce_2fa" drift fixed alongside
//     this test)
//   - records an empty actor (recordAuditAction called outside the
//     bearerAuth context)
//   - records an empty resource for an action that requires one
//   - lets a secret-shaped value into the details field
//   - writes a JSON-looking details payload that doesn't parse
//
// Not exhaustive: the rotate-cert / reenroll / mobile-bundle /
// ca.rotated paths are covered by other tests in this package (see
// auditActionsExercisedElsewhere below) and not re-driven here. The
// host.rekey.completed constant has no emitter at all and is tracked
// in auditActionsPendingImplementation.
func TestAuditRows_AllProductionPathsConform(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// network.create — the sweep's own fixture network emits it.
	netID := createNetwork(t, srv)

	// network.firewall.update — rewrite the network's firewall policy,
	// exercising the full-ruleset details payload.
	mustDo(t, srv, http.MethodPut, "/api/v1/networks/"+netID+"/firewall",
		[]byte(`{"inbound":[{"port":"443","proto":"tcp","group":"servers"}],"outbound":[{"port":"any","proto":"any","group":"all"}]}`),
		http.StatusOK)

	// host.create — normal create.
	hostID := mustCreateHost(t, srv, netID, "audit-h1", "192.168.100.50")

	// host.update — PATCH the host's name, exercising the JSON-diff
	// details payload.
	mustDo(t, srv, http.MethodPatch, "/api/v1/hosts/"+hostID,
		[]byte(`{"name":"audit-h1-renamed"}`), http.StatusOK)

	// host.block / host.unblock.
	mustDo(t, srv, http.MethodPost, "/api/v1/hosts/"+hostID+"/block", nil, http.StatusOK)
	mustDo(t, srv, http.MethodPost, "/api/v1/hosts/"+hostID+"/unblock", nil, http.StatusOK)

	// host.delete.
	mustDo(t, srv, http.MethodDelete, "/api/v1/hosts/"+hostID, nil, http.StatusNoContent)

	// ca.created — create a fresh non-default CA, then delete it.
	caBody, _ := json.Marshal(createCARequest{Name: "audit-ca", Duration: "720h"})
	caResp := mustDo(t, srv, http.MethodPost, "/api/v1/cas", caBody, http.StatusCreated)
	var ca struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(caResp, &ca); err != nil {
		t.Fatalf("decode ca: %v", err)
	}

	// ca.deleted — the new CA isn't the default, so delete is permitted.
	mustDo(t, srv, http.MethodDelete, "/api/v1/cas/"+ca.ID, nil, http.StatusNoContent)

	// operator.create.
	opBody, _ := json.Marshal(createOperatorRequest{Username: "audit-op", Password: "pw"})
	opResp := mustDo(t, srv, http.MethodPost, "/api/v1/operators", opBody, http.StatusCreated)
	var op struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(opResp, &op); err != nil {
		t.Fatalf("decode operator: %v", err)
	}

	// operator.disable / operator.enable.
	mustDo(t, srv, http.MethodPost, "/api/v1/operators/"+op.ID+"/disable", nil, http.StatusNoContent)
	mustDo(t, srv, http.MethodPost, "/api/v1/operators/"+op.ID+"/enable", nil, http.StatusNoContent)

	// operator.api_key.create.
	keyBody, _ := json.Marshal(createAPIKeyRequest{Name: "audit-key"})
	keyResp := mustDo(t, srv, http.MethodPost, "/api/v1/operators/"+op.ID+"/api-keys", keyBody, http.StatusCreated)
	var keyEntry struct {
		Entry struct {
			ID string `json:"id"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(keyResp, &keyEntry); err != nil {
		t.Fatalf("decode api key: %v", err)
	}

	// operator.api_key.revoke.
	mustDo(t, srv, http.MethodDelete,
		fmt.Sprintf("/api/v1/operators/%s/api-keys/%s", op.ID, keyEntry.Entry.ID),
		nil, http.StatusNoContent)

	// settings.enforce_2fa — the action that was historically a literal
	// string drift; PATCHing here verifies the const-based path emits a
	// well-formed row.
	mustDo(t, srv, http.MethodPatch, "/api/v1/settings",
		[]byte(`{"enforce_2fa":true}`), http.StatusOK)

	// host.auth.failed — a signed-poll with missing headers exercises
	// the empty-resource exception (no host known yet).
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("signed-poll missing-headers: status = %d, want 400", rec.Code)
	}

	// Read back every audit row and validate each.
	rows, err := st.ListAuditEntries(ctx, store.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no audit rows recorded — test exercised nothing")
	}

	seen := map[string]int{}
	for _, row := range rows {
		assertValidAuditRow(t, row)
		seen[row.Action]++
	}

	for _, want := range auditActionsExercisedByCoverageSweep {
		if seen[want] == 0 {
			t.Errorf("test did not produce any %q audit rows (coverage gap)", want)
		}
	}
}

// auditActionsExercisedByCoverageSweep is the single source of truth for
// which audit actions the coverage sweep above is expected to drive.
// TestAuditRows_AllProductionPathsConform verifies each one was
// actually emitted; TestKnownAuditActions_HaveCallSiteCoverage derives
// the orphan-detection set from this slice so the two tests cannot
// drift apart.
//
// Add a new entry only after wiring the coverage sweep to drive a
// handler that emits the action.
var auditActionsExercisedByCoverageSweep = []string{
	auditHostCreate,
	auditHostUpdate,
	auditHostBlock,
	auditHostUnblock,
	auditHostDelete,
	auditCACreated,
	auditCADeleted,
	auditNetworkCreate,
	auditNetworkFirewallUpdate,
	auditOperatorCreate,
	auditOperatorDisable,
	auditOperatorEnable,
	auditOperatorAPIKeyCreate,
	auditOperatorAPIKeyRevoke,
	auditSettingsEnforce2FA,
	auditHostAuthFailed,
}

// auditActionsExercisedElsewhere lists known audit actions that are
// covered by other tests in this package rather than re-driven by the
// coverage sweep above. Keep this list curated: any audit constant that
// is neither in the coverage sweep nor here (nor in
// auditActionsPendingImplementation) is an orphan, and
// TestKnownAuditActions_HaveCallSiteCoverage will flag it.
var auditActionsExercisedElsewhere = map[string]string{
	auditHostRotateCertRequested:   "hosts_rotate_cert_test.go",
	auditHostReenrollRequested:     "hosts_reenroll_test.go",
	auditHostMobileBundleIssued:    "mobile_bundle_test.go",
	auditHostMobileBundleForbidden: "mobile_bundle_test.go",
	auditCARotated:                 "cas_test.go",
}

// auditActionsPendingImplementation lists audit constants that were
// declared in advance of an emitter — typically because a feature was
// landed in phases and the constant block was populated up-front so
// later PRs could fill in the call sites. Each entry's string value is
// a freeform tracker (PR / commit / issue) pointing at where the
// constant was introduced and why.
//
// Loophole acknowledged: nothing prevents a contributor from adding a
// constant + a plausible-looking entry here and shipping without
// wiring an emitter. The map is a coordination aid, not a hard
// forcing function. Human review is the real defense.
//
// Removing an entry without adding an emitter (or moving it to
// auditActionsExercisedElsewhere) will trip
// TestKnownAuditActions_HaveCallSiteCoverage on the next run.
var auditActionsPendingImplementation = map[string]string{
	auditHostRekeyCompleted: "introduced in PR #75/#78 (commit b04cfd6, " +
		"\"feat(store): foundation for ADR 0004 agent auth\") alongside " +
		"the other agent-auth audit labels, with the intent that a " +
		"follow-up PR would wire the emit at the point where the agent " +
		"completes its re-enrollment with the rekey-token-minted key. " +
		"Not yet wired.",
}

// TestKnownAuditActions_HaveCallSiteCoverage asserts every action in
// the api-package audit enum is either driven by TestAuditRows_
// AllProductionPathsConform (derived from
// auditActionsExercisedByCoverageSweep, the same slice that test uses
// to verify emission), exercised by another test in this package
// (auditActionsExercisedElsewhere), or documented as pending
// implementation (auditActionsPendingImplementation).
//
// To resolve a failure: either wire up the missing emitter, point the
// constant at the test file that exercises it (in the maps above), or
// remove the constant from metrics.go + knownAuditActions.
func TestKnownAuditActions_HaveCallSiteCoverage(t *testing.T) {
	exercisedHere := make(map[string]struct{}, len(auditActionsExercisedByCoverageSweep))
	for _, a := range auditActionsExercisedByCoverageSweep {
		exercisedHere[a] = struct{}{}
	}
	for action := range knownAuditActions {
		if _, ok := exercisedHere[action]; ok {
			continue
		}
		if _, ok := auditActionsExercisedElsewhere[action]; ok {
			continue
		}
		if _, ok := auditActionsPendingImplementation[action]; ok {
			continue
		}
		t.Errorf("audit action %q has no documented call-site coverage: "+
			"either drive it from TestAuditRows_AllProductionPathsConform, "+
			"add it to auditActionsExercisedElsewhere with the covering "+
			"test file, mark it auditActionsPendingImplementation with a "+
			"spec pointer, or remove the constant from metrics.go", action)
	}
}

// mustCreateHost POSTs a fresh host into the given network and returns
// the host ID. Fatals on any non-201 response.
func mustCreateHost(t *testing.T, srv *Server, networkID, name, ip string) string {
	t.Helper()
	body, _ := json.Marshal(createHostRequest{
		NetworkID: networkID,
		Name:      name,
		NebulaIPs: []string{ip},
	})
	resp := mustDo(t, srv, http.MethodPost, "/api/v1/hosts", body, http.StatusCreated)
	var out createHostResponse
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatalf("decode createHostResponse: %v", err)
	}
	return out.Host.ID
}

// mustDo fires an admin-authenticated request and asserts the response
// status. Returns the response body.
func mustDo(t *testing.T, srv *Server, method, path string, body []byte, wantStatus int) []byte {
	t.Helper()
	var rdr *bytes.Buffer
	if body != nil {
		rdr = bytes.NewBuffer(body)
	} else {
		rdr = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != wantStatus {
		t.Fatalf("%s %s: status = %d, want %d; body = %s",
			method, path, w.Code, wantStatus, w.Body.String())
	}
	return w.Body.Bytes()
}
