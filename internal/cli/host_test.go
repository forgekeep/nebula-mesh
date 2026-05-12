package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostBlock_Success(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"h1","status":"blocked"}`))
	}))
	defer srv.Close()

	if err := HostBlock(srv.URL, "test-key", "h1"); err != nil {
		t.Fatalf("HostBlock returned error: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/hosts/h1/block" {
		t.Errorf("path = %q, want /api/v1/hosts/h1/block", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("auth = %q, want Bearer test-key", gotAuth)
	}
}

func TestHostUnblock_Success(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"h1","status":"pending"}`))
	}))
	defer srv.Close()

	if err := HostUnblock(srv.URL, "test-key", "h1"); err != nil {
		t.Fatalf("HostUnblock returned error: %v", err)
	}
	if gotPath != "/api/v1/hosts/h1/unblock" {
		t.Errorf("path = %q, want /api/v1/hosts/h1/unblock", gotPath)
	}
}

func TestHostDelete_Success(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := HostDelete(srv.URL, "test-key", "h1"); err != nil {
		t.Fatalf("HostDelete returned error: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/api/v1/hosts/h1" {
		t.Errorf("path = %q, want /api/v1/hosts/h1", gotPath)
	}
}

func TestHostAction_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"host not found"}`))
	}))
	defer srv.Close()

	err := HostBlock(srv.URL, "test-key", "missing")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error = %q, should mention HTTP 404", err.Error())
	}
}

func TestHostAction_MissingAPIKey(t *testing.T) {
	if err := HostBlock("http://example.invalid", "", "h1"); err == nil {
		t.Fatal("expected error for empty api key")
	}
}

func TestHostAction_MissingServerURL(t *testing.T) {
	if err := HostBlock("", "test-key", "h1"); err == nil {
		t.Fatal("expected error for empty server URL")
	}
}
