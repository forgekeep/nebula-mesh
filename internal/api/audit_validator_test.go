package api

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// knownAuditActions mirrors the closed set of audit action constants
// declared in metrics.go for the internal/api package. Any new audit
// action name emitted by an api-package handler must:
//
//  1. Get a typed `audit*` constant in metrics.go.
//  2. Be added to the newMetrics() pre-seed loop so the Prometheus
//     counter shows up with a zero value before the first event.
//  3. Be added to this set.
//
// Scope caveat: the internal/web/, internal/alerts/, and internal/cli/
// packages also emit audit rows (via store.AddAuditEntry directly) with
// their own action strings — those are NOT mirrored here, and this
// validator does not assert anything about them. The audit-row contract
// pinned by this file applies only to recordAuditAction call sites
// under internal/api/.
var knownAuditActions = map[string]struct{}{
	auditHostCreate:                {},
	auditHostDelete:                {},
	auditHostUpdate:                {},
	auditHostBlock:                 {},
	auditHostUnblock:               {},
	auditHostAuthFailed:            {},
	auditHostRotateCertRequested:   {},
	auditHostReenrollRequested:     {},
	auditHostRekeyCompleted:        {},
	auditHostMobileBundleIssued:    {},
	auditHostMobileBundleForbidden: {},
	auditCACreated:                 {},
	auditCAImported:                {},
	auditCADeleted:                 {},
	auditCARotated:                 {},
	auditMeshImportCreated:         {},
	auditMeshImportTokenRotated:    {},
	auditMeshImportCanceled:        {},
	auditMeshImportHostRegistered:  {},
	auditMeshImportFinalized:       {},
	auditNetworkCreate:             {},
	auditNetworkFirewallUpdate:     {},
	auditOperatorCreate:            {},
	auditOperatorDisable:           {},
	auditOperatorEnable:            {},
	auditOperatorAPIKeyCreate:      {},
	auditOperatorAPIKeyRevoke:      {},
	auditSettingsEnforce2FA:        {},
}

// actionsAllowingEmptyResource lists the actions where Resource == ""
// is semantically meaningful — currently just early-stage signed-poll
// failures that fail before identifying a host (missing headers,
// unknown fingerprint, blocklisted-but-deleted host row). For every
// other action, an empty resource indicates a missing argument at the
// recordAuditAction call site.
var actionsAllowingEmptyResource = map[string]struct{}{
	auditHostAuthFailed: {},
}

// piiPatterns are content shapes that must never appear in an audit
// row's details field. The list is intentionally narrow — the spirit
// is "catch obvious secret-pasting accidents", not exhaustive PII
// detection.
//
// Deliberate blind spots:
//
//   - UUID-shaped strings — legitimate IDs (host.ID, operator.ID,
//     api_key.ID) and raw enrollment tokens both look like UUIDs.
//     If a future handler started writing raw enrollment tokens into
//     `details`, this validator would not catch it.
//
//   - TOTP secrets (base32, ~16-32 chars, no separator) — minted in
//     internal/web/totp.go. No current emitter logs them, but the
//     shape is indistinguishable from base32 audit identifiers, so a
//     regex would false-positive on legitimate content.
//
//   - 2FA recovery codes (10-char hex) — minted in internal/web/
//     totp.go. Shape collides with short hex IDs in fixture data.
//
//   - Bare JWTs (without the "Bearer " prefix) — the bearer regex
//     catches `Bearer eyJ...` but a raw JWT pasted naked passes. OIDC
//     ID tokens flow through internal/web/oidc.go; check there if
//     extending coverage.
//
//   - Operator API keys (32-byte hex) — indistinguishable from the
//     SHA-256 hash digests that legitimately appear in audit rows
//     (host fingerprints, token-hash IDs). Can't be regex-disambig-
//     uated without false positives.
//
//   - The bearer regex requires at least 20 chars of base64-shaped
//     trailing content, which dodges legitimate phrases like
//     "bearer token expired" while still catching `Bearer eyJhbGc...`.
//
//   - The password regex requires a `:` or `=` separator and at least
//     six trailing non-space chars so it doesn't trip on phrases like
//     "password changed" or "password=". Tighten further if a handler
//     legitimately needs to log a short value following "password=".
var piiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}`),
	regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*\S{6,}`),
}

// assertValidAuditRow checks a single audit row against the project's
// audit-row contract: required fields populated, action in the closed
// enum, details JSON-shaped values parse, no secret-shaped content
// leaked into details. Failures are reported via t.Errorf so a single
// test can surface every malformed row in one run.
func assertValidAuditRow(t *testing.T, row *models.AuditEntry) {
	t.Helper()
	if row == nil {
		t.Error("audit row: nil")
		return
	}
	if row.Action == "" {
		t.Error("audit row: empty action")
		return
	}
	if _, ok := knownAuditActions[row.Action]; !ok {
		t.Errorf("audit row: action %q not in knownAuditActions enum "+
			"(drift — add an audit* const to internal/api/metrics.go, "+
			"add it to the newMetrics pre-seed loop, and mirror it here)",
			row.Action)
	}
	if row.Actor == "" {
		t.Errorf("audit row %s: empty actor (recordAuditAction was called "+
			"without an actor on the context — check bearerAuth ordering)",
			row.Action)
	}
	if row.Resource == "" {
		if _, ok := actionsAllowingEmptyResource[row.Action]; !ok {
			t.Errorf("audit row %s: empty resource (only %s permits empty)",
				row.Action, auditHostAuthFailed)
		}
	}
	if row.Timestamp.IsZero() {
		t.Errorf("audit row %s: zero timestamp", row.Action)
	}
	if row.Details != "" {
		d := strings.TrimSpace(row.Details)
		if strings.HasPrefix(d, "{") || strings.HasPrefix(d, "[") {
			var v any
			if err := json.Unmarshal([]byte(row.Details), &v); err != nil {
				t.Errorf("audit row %s: details begins with {/[ but does not parse as JSON: %v",
					row.Action, err)
			}
		}
		for _, pat := range piiPatterns {
			if pat.MatchString(row.Details) {
				t.Errorf("audit row %s: details matches PII/secret pattern %s",
					row.Action, pat)
			}
		}
	}
}

// --- unit tests on the validator itself ----------------------------------

func TestAuditValidator_AcceptsWellFormed(t *testing.T) {
	cases := []models.AuditEntry{
		{Actor: "alice", Action: auditHostCreate, Resource: "host-1", Details: "name=foo", Timestamp: nowForTest()},
		{Actor: "alice", Action: auditHostUpdate, Resource: "host-1", Details: `{"name":["old","new"]}`, Timestamp: nowForTest()},
		{Actor: "alice", Action: auditHostDelete, Resource: "host-1", Details: "", Timestamp: nowForTest()},
		// auditHostAuthFailed: empty resource is allowed only for this action.
		{Actor: "unknown", Action: auditHostAuthFailed, Resource: "", Details: authReasonUnknownFingerprint, Timestamp: nowForTest()},
		{Actor: "alice", Action: auditSettingsEnforce2FA, Resource: "enforce_2fa", Details: "true", Timestamp: nowForTest()},
	}
	for _, row := range cases {
		t.Run(row.Action, func(t *testing.T) {
			sub := &testing.T{}
			assertValidAuditRow(sub, &row)
			if sub.Failed() {
				t.Errorf("expected row to validate, but assertions failed: %+v", row)
			}
		})
	}
}

func TestAuditValidator_RejectsBadShapes(t *testing.T) {
	cases := []struct {
		name string
		row  models.AuditEntry
	}{
		{"empty action", models.AuditEntry{Actor: "alice", Resource: "x", Timestamp: nowForTest()}},
		{"unknown action", models.AuditEntry{Actor: "alice", Action: "host.totally_new_action", Resource: "x", Timestamp: nowForTest()}},
		{"empty actor", models.AuditEntry{Action: auditHostCreate, Resource: "host-1", Timestamp: nowForTest()}},
		{"empty resource on action that requires it", models.AuditEntry{Actor: "alice", Action: auditHostCreate, Resource: "", Timestamp: nowForTest()}},
		{"zero timestamp", models.AuditEntry{Actor: "alice", Action: auditHostCreate, Resource: "host-1"}},
		{"json-shaped details that does not parse", models.AuditEntry{Actor: "alice", Action: auditHostUpdate, Resource: "h", Details: `{name: nope}`, Timestamp: nowForTest()}},
		{"private-key in details", models.AuditEntry{Actor: "alice", Action: auditHostCreate, Resource: "h", Details: "-----BEGIN PRIVATE KEY-----\nAAAA\n", Timestamp: nowForTest()}},
		{"bearer token in details", models.AuditEntry{Actor: "alice", Action: auditHostCreate, Resource: "h", Details: "Bearer abcdefghijklmnopqrstuv1234", Timestamp: nowForTest()}},
		{"password= in details", models.AuditEntry{Actor: "alice", Action: auditHostCreate, Resource: "h", Details: "password=hunter2", Timestamp: nowForTest()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sub := &testing.T{}
			assertValidAuditRow(sub, &c.row)
			if !sub.Failed() {
				t.Errorf("expected validator to reject row %+v, but it passed", c.row)
			}
		})
	}
}

func nowForTest() time.Time { return time.Now() }
