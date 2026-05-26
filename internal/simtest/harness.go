// Package simtest is the in-process fleet-simulation scaffold described in
// ADR 0009. It stands up the real management server behind an httptest
// listener over an in-memory store, then drives it with virtual agents that
// speak the real enrollment and proof-of-possession poll protocol — the only
// thing virtualized is the Nebula node the server never observes. Tests use it
// to assert fleet-scale invariants (config convergence, tenant isolation,
// token single-use, ...) that per-request unit tests cannot reach.
//
// It is a test-support library: it is only ever imported from _test.go files,
// so it is excluded from production binaries. It takes a minimal [TB] rather
// than importing the testing package directly.
package simtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/api"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TB is the slice of *testing.T that simtest needs. Keeping it an interface
// avoids importing the testing package from non-test source.
type TB interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
	Logf(format string, args ...any)
}

//nolint:gosec // static test credential, not a real secret
const apiKey = "simtest-api-key" // #nosec G101

// Option configures a Harness.
type Option func(*options)

type options struct{ fileStore bool }

// WithFileStore backs the harness with a temp-file SQLite database instead of
// ":memory:". The in-memory store pins MaxOpenConns(1), which serializes every
// query and masks concurrency bugs; a file-backed store uses the production
// pool (WAL, multiple connections), so concurrency invariants (token
// single-use, IP-uniqueness races) exercise the real path. Required for any
// test that relies on connection-level concurrency.
func WithFileStore() Option { return func(o *options) { o.fileStore = true } }

// Harness is a running management server plus the handles a test needs to
// drive it: the store (for direct assertions and config-version reads), the
// default CA, and a shared event Journal.
type Harness struct {
	tb      TB
	Server  *httptest.Server
	Store   *store.SQLiteStore
	CA      *models.CA
	Journal *Journal

	master *keystore.Master
	logger *slog.Logger
	clk    *simClock
}

// simClock is a controllable clock shared by the server and the virtual
// agents. Until SetClock is called it returns real time, so tests that don't
// touch it behave exactly as before. Once set, Advance moves both the server's
// now and the agents' poll timestamps in lockstep — so advancing past a cert's
// renewal window does not also trip the PoP timestamp-skew check.
type simClock struct {
	mu  sync.Mutex
	set bool
	t   time.Time
}

func (c *simClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set {
		return c.t
	}
	return time.Now()
}

func (c *simClock) setTo(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.set, c.t = true, t
}

func (c *simClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set {
		c.set, c.t = true, time.Now()
	}
	c.t = c.t.Add(d)
}

// SetClock freezes the harness clock at t (server + agents). Call before
// Advance to exercise time-dependent paths deterministically.
func (h *Harness) SetClock(t time.Time) { h.clk.setTo(t) }

// Advance moves the harness clock forward by d (freezing at now first if it
// was still live).
func (h *Harness) Advance(d time.Duration) { h.clk.advance(d) }

// now returns the harness clock time (used by virtual agents for poll
// timestamps so they stay consistent with the server's clock).
func (h *Harness) now() time.Time { return h.clk.now() }

// Tenant is a non-admin operator with its own API key and CA, for
// multi-tenant isolation tests.
type Tenant struct {
	Key        string
	OperatorID string
	CAID       string
}

// New brings up a fresh in-memory server with one admin operator, an API key,
// and a default CA — the same shape as the integration e2e harness, exposed as
// a reusable library.
func New(tb TB, opts ...Option) *Harness {
	tb.Helper()
	ctx := context.Background()

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	dbPath := ":memory:"
	if o.fileStore {
		dir, err := os.MkdirTemp("", "simtest-*")
		if err != nil {
			tb.Fatalf("temp dir: %v", err)
		}
		tb.Cleanup(func() { _ = os.RemoveAll(dir) })
		dbPath = filepath.Join(dir, "nebula.db")
	}

	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		tb.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		tb.Fatalf("migrate: %v", err)
	}
	tb.Cleanup(func() { _ = s.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(s, logger)
	clk := &simClock{}
	srv.WithClock(clk.now)

	master, err := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	if err != nil {
		tb.Fatalf("new master: %v", err)
	}
	srv.WithMaster(master)
	srv.WithCAResolver(pki.NewCAResolver(s, master))

	op := &models.Operator{
		ID:           "simtest-admin",
		Username:     "admin",
		PasswordHash: "hash",
		Role:         "admin",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		tb.Fatalf("create operator: %v", err)
	}
	keySum := sha256.Sum256([]byte(apiKey))
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID:         "simtest-admin-key",
		OperatorID: op.ID,
		Name:       "simtest-admin-key",
		KeyHash:    hex.EncodeToString(keySum[:]),
	}); err != nil {
		tb.Fatalf("create api key: %v", err)
	}

	ca, _, err := pki.MintAndStoreCA(ctx, s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "simtest-ca",
		Duration: 365 * 24 * time.Hour,
	})
	if err != nil {
		tb.Fatalf("mint CA: %v", err)
	}
	srv.WithDefaultCAID(ca.ID)

	ts := httptest.NewServer(srv)
	tb.Cleanup(ts.Close)

	return &Harness{tb: tb, Server: ts, Store: s, CA: ca, Journal: NewJournal(), master: master, logger: logger, clk: clk}
}

// NewTenant store-creates a non-admin operator with its own API key and CA,
// returning a Tenant whose Key authenticates as that operator. Hosts created
// under the tenant's CAID are owned by it; another tenant must not be able to
// read or mutate them (authz gates on CA ownership — internal/api/authz.go).
func (h *Harness) NewTenant(name string) *Tenant {
	h.tb.Helper()
	ctx := context.Background()
	op := &models.Operator{
		ID:           name,
		Username:     name,
		PasswordHash: "hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := h.Store.CreateOperator(ctx, op); err != nil {
		h.tb.Fatalf("create operator %q: %v", name, err)
	}
	key := name + "-key"
	sum := sha256.Sum256([]byte(key))
	if err := h.Store.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID:         name + "-key",
		OperatorID: op.ID,
		Name:       name + "-key",
		KeyHash:    hex.EncodeToString(sum[:]),
	}); err != nil {
		h.tb.Fatalf("create api key for %q: %v", name, err)
	}
	ca, _, err := pki.MintAndStoreCA(ctx, h.Store, h.master, h.logger, pki.MintRequest{
		Operator: op,
		Name:     name + "-ca",
		Duration: 365 * 24 * time.Hour,
	})
	if err != nil {
		h.tb.Fatalf("mint CA for %q: %v", name, err)
	}
	return &Tenant{Key: key, OperatorID: op.ID, CAID: ca.ID}
}

// CreateHostUnderCA store-creates an enrolled-shaped host row owned by caID on
// the given network, returning its ID. Bypasses the create API so isolation
// tests can plant a host under one tenant's CA directly.
func (h *Harness) CreateHostUnderCA(networkID, caID, name, ip string) string {
	h.tb.Helper()
	now := time.Now()
	host := &models.Host{
		ID:        name,
		NetworkID: networkID,
		Name:      name,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		Kind:      models.HostKindAgent,
		CAID:      caID,
		NebulaIPs: []string{ip},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.Store.CreateHost(context.Background(), host); err != nil {
		h.tb.Fatalf("create host %q under CA %q: %v", name, caID, err)
	}
	return host.ID
}

// API issues an authenticated admin API request and returns the decoded JSON
// body (into out, if non-nil) and status code. It fails the test on transport
// errors so callers can focus on status assertions.
func (h *Harness) API(method, path string, body, out any) int {
	return h.APIAs(apiKey, method, path, body, out)
}

// APIAs is like API but authenticates with the given API key — used by
// multi-tenant isolation tests to act as a specific Tenant.
func (h *Harness) APIAs(key, method, path string, body, out any) int {
	h.tb.Helper()
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			h.tb.Fatalf("marshal %s %s body: %v", method, path, err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.Server.URL+path, r)
	if err != nil {
		h.tb.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.tb.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if out != nil && resp.Body != nil {
		// Best-effort decode; callers that don't care pass nil.
		_ = json.NewDecoder(resp.Body).Decode(out)
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode
}

// CreateNetwork creates a network and returns its ID.
func (h *Harness) CreateNetwork(name string, cidrs ...string) string {
	h.tb.Helper()
	var net models.Network
	code := h.API(http.MethodPost, "/api/v1/networks", map[string]any{
		"name": name, "cidrs": cidrs,
	}, &net)
	if code != http.StatusCreated {
		h.tb.Fatalf("create network %q: HTTP %d", name, code)
	}
	return net.ID
}
