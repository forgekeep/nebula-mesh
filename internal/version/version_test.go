package version

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrint_FullValues(t *testing.T) {
	var buf bytes.Buffer
	Print(&buf, "nebula-mgmt", "v1.2.3", "abcdef0123456", "2026-01-02T03:04:05Z")
	got := buf.String()
	want := "nebula-mgmt v1.2.3 (abcdef0, built 2026-01-02T03:04:05Z)\n"
	if got != want {
		t.Errorf("Print = %q, want %q", got, want)
	}
}

func TestPrint_ShortCommitNotTruncated(t *testing.T) {
	var buf bytes.Buffer
	Print(&buf, "x", "v1", "abc123", "2026")
	got := buf.String()
	if !strings.Contains(got, "(abc123, built 2026)") {
		t.Errorf("short commit was truncated: %q", got)
	}
}

func TestResolve_AllPlaceholdersFillsDefaults(t *testing.T) {
	// With no ldflags, an `go install` of the test binary may still populate
	// VCS info from the test runner's module — so we only assert the
	// fallback contract: non-empty values for every field.
	v, c, d := Resolve("", "", "")
	if v == "" || c == "" || d == "" {
		t.Errorf("Resolve filled empties incompletely: v=%q c=%q d=%q", v, c, d)
	}
}

func TestResolve_KeepsExplicitValues(t *testing.T) {
	v, c, d := Resolve("v9.9.9", "deadbeef", "2030-01-01")
	if v != "v9.9.9" || c != "deadbeef" || d != "2030-01-01" {
		t.Errorf("Resolve overwrote explicit values: v=%q c=%q d=%q", v, c, d)
	}
}

func TestIsPlaceholder(t *testing.T) {
	cases := map[string]bool{
		"":        true,
		"dev":     true,
		"none":    true,
		"unknown": true,
		"v1.0.0":  false,
		"abc123":  false,
	}
	for in, want := range cases {
		if got := isPlaceholder(in); got != want {
			t.Errorf("isPlaceholder(%q) = %v, want %v", in, got, want)
		}
	}
}
