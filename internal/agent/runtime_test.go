package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	agentpop "github.com/forgekeep/nebula-mesh/internal/agent/pop"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
)

func TestParseNebulaVersion(t *testing.T) {
	tests := []struct {
		out     string
		want    string
		wantErr bool
	}{
		{out: "Version: 1.12.0\n", want: "1.12.0"},
		{out: "Version: 1.10.3", want: "1.10.3"},
		{out: "some banner\nVersion: 1.12.0-rc1\n", want: "1.12.0-rc1"},
		{out: "", wantErr: true},
		{out: "nebula 1.12.0\n", wantErr: true},
		{out: "Version: dev\n", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseNebulaVersion([]byte(tt.out))
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseNebulaVersion(%q) = %q, want error", tt.out, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("parseNebulaVersion(%q) = %q, %v; want %q", tt.out, got, err, tt.want)
		}
	}
}

// runtimeServer records the agent's requests in order and answers runtime
// reports with runtimeStatus.
type runtimeServer struct {
	mu            sync.Mutex
	paths         []string
	runtimeStatus int
	pub           ed25519.PublicKey
	t             *testing.T
}

func (s *runtimeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.Method+" "+r.URL.Path)
	status := s.runtimeStatus
	s.mu.Unlock()
	if r.Method == http.MethodPost {
		canonical := corepop.CanonicalString(r.Method, r.URL.Path, r.Host,
			r.Header.Get(corepop.HeaderTimestamp), r.Header.Get(corepop.HeaderNonce))
		sig, err := agentpop.DecodeSignature(r.Header.Get(corepop.HeaderSignature))
		if err != nil || !ed25519.Verify(s.pub, []byte(canonical), sig) {
			s.t.Errorf("runtime report %s is not signed over its path", r.URL.Path)
		}
		w.WriteHeader(status)
		return
	}
	_ = json.NewEncoder(w).Encode(UpdatesResponse{Blocklist: []string{}})
}

func (s *runtimeServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

// newRuntimePoller builds a poller whose reporter runs a fake nebula binary
// file through runVersion instead of executing it.
func newRuntimePoller(t *testing.T, status int) (*Poller, *runtimeServer, string, *int) {
	t.Helper()
	dir := t.TempDir()
	pub := writeSigningKey(t, filepath.Join(dir, "host.signing.key"))
	srv := &runtimeServer{runtimeStatus: status, pub: pub, t: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	binary := filepath.Join(dir, "nebula")
	if err := os.WriteFile(binary, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newTestPoller(t, PollerConfig{ServerURL: ts.URL, Fingerprint: "fp", DataDir: dir, Interval: time.Hour})
	runs := 0
	p.runtime = newRuntimeReporter(binary)
	p.runtime.runVersion = func(_ context.Context, path string) ([]byte, error) {
		runs++
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if string(raw) == "v1" {
			return []byte("Version: 1.11.2\n"), nil
		}
		return []byte("Version: 1.12.0\n"), nil
	}
	return p, srv, binary, &runs
}

func TestPoller_ReportsRuntimeBeforePollingOnce(t *testing.T) {
	p, srv, _, runs := newRuntimePoller(t, http.StatusOK)
	for i := 0; i < 2; i++ {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"POST /api/v1/agent/runtime/" + runtime.GOOS + "/1.11.2",
		"GET /api/v1/agent/updates",
		"GET /api/v1/agent/updates",
	}
	if got := srv.requests(); !equalStrings(got, want) {
		t.Errorf("requests = %q, want %q", got, want)
	}
	if *runs != 1 {
		t.Errorf("nebula -version ran %d times, want 1 for an unchanged binary", *runs)
	}
}

func TestPoller_ReportsAgainWhenBinaryChanges(t *testing.T) {
	p, srv, binary, runs := newRuntimePoller(t, http.StatusOK)
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	// An upgrade replaces the file: new size and modification time.
	if err := os.WriteFile(binary, []byte("v2-upgraded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(binary, time.Now().Add(time.Minute), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := srv.requests()
	if len(got) != 4 || got[2] != "POST /api/v1/agent/runtime/"+runtime.GOOS+"/1.12.0" {
		t.Errorf("requests = %q, want a second report of 1.12.0", got)
	}
	if *runs != 2 {
		t.Errorf("nebula -version ran %d times, want 2", *runs)
	}
}

func TestPoller_RetriesRuntimeReportAfterServerError(t *testing.T) {
	p, srv, _, _ := newRuntimePoller(t, http.StatusInternalServerError)
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatalf("a failed runtime report must not fail the poll: %v", err)
	}
	srv.mu.Lock()
	srv.runtimeStatus = http.StatusOK
	srv.mu.Unlock()
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	reports := 0
	for _, r := range srv.requests() {
		if r == "POST /api/v1/agent/runtime/"+runtime.GOOS+"/1.11.2" {
			reports++
		}
	}
	if reports != 2 {
		t.Errorf("runtime reports = %d, want a retry after the failure", reports)
	}
}

func TestPoller_StopsReportingWhenServerLacksEndpoint(t *testing.T) {
	p, srv, _, _ := newRuntimePoller(t, http.StatusNotFound)
	for i := 0; i < 3; i++ {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	reports := 0
	for _, r := range srv.requests() {
		if r[:4] == "POST" {
			reports++
		}
	}
	if reports != 1 {
		t.Errorf("runtime reports = %d, want 1 against a server without the endpoint", reports)
	}
}

func TestPoller_PollsWithoutNebulaBinary(t *testing.T) {
	p, srv, _, _ := newRuntimePoller(t, http.StatusOK)
	p.runtime = newRuntimeReporter(filepath.Join(t.TempDir(), "missing-nebula"))
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := srv.requests(); !equalStrings(got, []string{"GET /api/v1/agent/updates"}) {
		t.Errorf("requests = %q, want only the poll", got)
	}
}

func TestRunNebulaVersion_ExecutesBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary")
	}
	binary := filepath.Join(t.TempDir(), "nebula")
	script := "#!/bin/sh\n[ \"$1\" = \"-version\" ] || exit 2\necho 'Version: 1.12.0'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatal(err)
	}
	r := newRuntimeReporter(binary)
	got, err := r.detect(t.Context())
	if err != nil || got != "1.12.0" {
		t.Fatalf("detect = %q, %v; want 1.12.0", got, err)
	}
}

func TestRunNebulaVersion_FailingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary")
	}
	binary := filepath.Join(t.TempDir(), "nebula")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatal(err)
	}
	var exitErr *exec.ExitError
	_, err := newRuntimeReporter(binary).detect(t.Context())
	if err == nil || !errors.As(err, &exitErr) {
		t.Fatalf("detect err = %v, want the binary's exit error", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
