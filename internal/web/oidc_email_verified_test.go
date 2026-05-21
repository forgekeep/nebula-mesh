package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// TestOIDC_HandleCallback_EmailVerified covers the email_verified claim
// enforcement: a permitted email at a permitted domain must not satisfy
// AllowedEmails when the IdP has not asserted the address is verified.
//
// Default-deny posture: missing claim is treated the same as explicit
// false. Matches dexidp/dex's connector posture (go-oidc itself does
// not enforce this claim — the RP must).
//
// The string-encoding rows ("true"/"TRUE"/"false") cover real IdP
// shapes — Azure AD, Salesforce, older Keycloak — that parseEmailVerified
// must accept. Numeric (1) and nil rows confirm the parser stays
// default-deny for non-spec shapes.
//
// The RequireEmailVerified opt-out row covers the escape hatch for
// legacy IdPs whose encoding the parser still can't decode: an explicit
// `false` on the config field skips the check entirely.
func TestOIDC_HandleCallback_EmailVerified(t *testing.T) {
	skipCheck := false
	cases := []struct {
		name            string
		emailVerified   any  // value to put under the email_verified key
		omitClaim       bool // true = drop the email_verified key entirely
		requireOverride *bool
		wantStatus      int
		wantBodyContain string
		wantAuditAction string
	}{
		{
			name:            "verified true succeeds",
			emailVerified:   true,
			wantStatus:      http.StatusSeeOther,
			wantBodyContain: "",
			wantAuditAction: "operator.oidc.login",
		},
		{
			name:            "verified false rejects",
			emailVerified:   false,
			wantStatus:      http.StatusForbidden,
			wantBodyContain: "not allowed to log in",
			wantAuditAction: "operator.oidc.denied",
		},
		{
			name:            "claim missing rejects",
			omitClaim:       true,
			wantStatus:      http.StatusForbidden,
			wantBodyContain: "not allowed to log in",
			wantAuditAction: "operator.oidc.denied",
		},
		{
			name:            "string true succeeds",
			emailVerified:   "true",
			wantStatus:      http.StatusSeeOther,
			wantBodyContain: "",
			wantAuditAction: "operator.oidc.login",
		},
		{
			name:            "string TRUE succeeds (case-insensitive)",
			emailVerified:   "TRUE",
			wantStatus:      http.StatusSeeOther,
			wantBodyContain: "",
			wantAuditAction: "operator.oidc.login",
		},
		{
			name:            "string false rejects",
			emailVerified:   "false",
			wantStatus:      http.StatusForbidden,
			wantBodyContain: "not allowed to log in",
			wantAuditAction: "operator.oidc.denied",
		},
		{
			// idToken.Claims(&map[string]any) routes through
			// encoding/json, which decodes JSON numbers as float64
			// by default. Production callers never see Go int from
			// the wire — use float64 here so the test asserts the
			// real-world code path. (Earlier int(1) row passed by
			// accident: the parser rejects both int and float64,
			// but only float64 reflects what the JSON decoder
			// actually produces.)
			name:            "numeric float64(1) rejects (non-spec encoding)",
			emailVerified:   float64(1),
			wantStatus:      http.StatusForbidden,
			wantBodyContain: "not allowed to log in",
			wantAuditAction: "operator.oidc.denied",
		},
		{
			// Same shape as above with a trailing zero; pinning
			// the no-numeric-coercion contract.
			name:            "numeric float64(1.0) rejects",
			emailVerified:   float64(1.0),
			wantStatus:      http.StatusForbidden,
			wantBodyContain: "not allowed to log in",
			wantAuditAction: "operator.oidc.denied",
		},
		{
			name:            "explicit nil rejects",
			emailVerified:   nil,
			wantStatus:      http.StatusForbidden,
			wantBodyContain: "not allowed to log in",
			wantAuditAction: "operator.oidc.denied",
		},
		{
			name:            "RequireEmailVerified=false skips the check",
			emailVerified:   false,
			requireOverride: &skipCheck,
			wantStatus:      http.StatusSeeOther,
			wantBodyContain: "",
			wantAuditAction: "operator.oidc.login",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, s := newTestWeb(t)
			idp := setupOIDCServer(t)
			o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
				AllowedEmails:        []string{"alice@example.com"},
				DefaultRole:          "user",
				RequireEmailVerified: tc.requireOverride,
			})

			claims := map[string]any{
				"sub":                "alice-sub",
				"aud":                "test-client",
				"email":              "alice@example.com",
				"preferred_username": "alice",
				"name":               "Alice",
			}
			if !tc.omitClaim {
				claims["email_verified"] = tc.emailVerified
			}
			idp.NextIDToken(claims)

			rec := driveCallback(t, o, "state-emailverified", "code-1")
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantBodyContain != "" && !strings.Contains(rec.Body.String(), tc.wantBodyContain) {
				t.Errorf("body = %q, want substring %q", rec.Body.String(), tc.wantBodyContain)
			}

			// Confirm an audit row of the expected shape landed. The
			// store is in-memory and small; a list-and-scan is fine.
			rows, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 10})
			if err != nil {
				t.Fatalf("ListAuditEntries: %v", err)
				return
			}
			found := false
			for _, row := range rows {
				if row.Action == tc.wantAuditAction {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected audit action %q, got rows: %+v", tc.wantAuditAction, rows)
			}
		})
	}
}

// TestParseEmailVerified exercises the parser at the function boundary
// rather than through the full callback path, so it can pin shapes that
// the JWT decode pipeline collapses (json.Number → float64 after a JSON
// round-trip) before they reach the parser. Production callers receive
// values from `idToken.Claims(&map[string]any{})`, which routes through
// encoding/json; JSON numbers arrive as float64. UseNumber would change
// that — a future refactor flipping it should still see json.Number
// rejected.
//
// The strict posture is load-bearing per the parser's doc comment:
// every widening is a security-sensitive change. This test pins the
// rejection of every non-spec shape we've considered.
func TestParseEmailVerified(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want bool
	}{
		// Accepted (spec or documented compatibility shape):
		{"bool_true", true, true},
		{"bool_false", false, false},
		{"string_true", "true", true},
		{"string_false", "false", false},
		{"string_True_mixed_case", "True", true},
		{"string_TRUE_upper", "TRUE", true},
		{"string_False_mixed_case", "False", false},

		// Rejected — non-spec shapes that production claim-decoding
		// can actually emit:
		{"float64_1_rejects", float64(1), false},
		{"float64_1.0_rejects", float64(1.0), false},
		{"float64_0_rejects", float64(0), false},
		// json.Number is what a json.Decoder with UseNumber() would
		// yield. The production decoder doesn't use it today, but
		// the parser's contract must still reject the shape.
		{"json_Number_1_rejects", json.Number("1"), false},
		{"json_Number_0_rejects", json.Number("0"), false},

		// Rejected — non-spec shapes from defensive coverage:
		{"int_1_rejects", int(1), false},
		{"int_0_rejects", int(0), false},
		{"string_1_rejects", "1", false},
		{"string_yes_rejects", "yes", false},
		{"string_on_rejects", "on", false},
		{"whitespace_padded_true_rejects", " true ", false},
		{"nested_object_rejects", map[string]any{"value": true}, false},
		{"slice_rejects", []any{true}, false},
		{"nil_rejects", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEmailVerified(tc.raw); got != tc.want {
				t.Errorf("parseEmailVerified(%T %v) = %v, want %v", tc.raw, tc.raw, got, tc.want)
			}
		})
	}
}

// TestOIDC_HandleCallback_EmailVerifiedBypass_AuditsAcceptance pins the
// per-login audit shape when `RequireEmailVerified=false`. The bypass is
// not silent: every callback whose `email_verified` claim would otherwise
// have failed the gate is tagged with `email_unverified_accepted=true` on
// the success-path `operator.oidc.login` row. Combined with the startup
// WARN log, this lets a forensics reader distinguish bypass-logins from
// verified-and-passed logins via a single substring grep against an
// existing audit action.
//
// Coverage matrix:
//   - email_verified=false → audit row tagged
//   - email_verified missing → audit row tagged
//   - email_verified=true with bypass enabled → row NOT tagged (the
//     bypass is only meaningful when the claim would have failed; a
//     verified login under a relaxed policy is still a verified login)
func TestOIDC_HandleCallback_EmailVerifiedBypass_AuditsAcceptance(t *testing.T) {
	skipCheck := false
	cases := []struct {
		name          string
		emailVerified any
		omitClaim     bool
		wantTagged    bool // success-path row should carry `email_unverified_accepted=true`
	}{
		{
			name:          "bypass_with_false_claim_tags_audit",
			emailVerified: false,
			wantTagged:    true,
		},
		{
			name:       "bypass_with_missing_claim_tags_audit",
			omitClaim:  true,
			wantTagged: true,
		},
		{
			name:          "bypass_with_verified_true_does_not_tag",
			emailVerified: true,
			wantTagged:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, s := newTestWeb(t)
			idp := setupOIDCServer(t)
			o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
				AllowedEmails:        []string{"alice@example.com"},
				DefaultRole:          "user",
				RequireEmailVerified: &skipCheck,
			})

			claims := map[string]any{
				"sub":                "alice-sub",
				"aud":                "test-client",
				"email":              "alice@example.com",
				"preferred_username": "alice",
				"name":               "Alice",
			}
			if !tc.omitClaim {
				claims["email_verified"] = tc.emailVerified
			}
			idp.NextIDToken(claims)

			rec := driveCallback(t, o, "state-bypass-audit", "code-bypass")
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusSeeOther, rec.Body.String())
			}

			rows, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 10})
			if err != nil {
				t.Fatalf("ListAuditEntries: %v", err)
				return
			}
			var loginRow *models.AuditEntry
			for _, row := range rows {
				if row.Action == "operator.oidc.login" {
					loginRow = row
					break
				}
			}
			if loginRow == nil {
				t.Fatalf("no operator.oidc.login audit row found; rows: %+v", rows)
				return
			}
			gotTagged := strings.Contains(loginRow.Details, "email_unverified_accepted=true")
			t.Logf("audit row: action=%q resource=%q details=%q", loginRow.Action, loginRow.Resource, loginRow.Details)
			if gotTagged != tc.wantTagged {
				t.Errorf("audit row tagged=%v, want %v; details=%q", gotTagged, tc.wantTagged, loginRow.Details)
			}
			// On bypass-tagged rows the issuer must still be present as
			// a prefix — the tag is additive, not a replacement, so
			// existing queries that filter by issuer keep working.
			if tc.wantTagged && !strings.HasPrefix(loginRow.Details, idp.Issuer()) {
				t.Errorf("audit details = %q, want prefix %q (issuer)", loginRow.Details, idp.Issuer())
			}
		})
	}
}
