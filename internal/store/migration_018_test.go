package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store/migrations"

	_ "modernc.org/sqlite"
)

// migrations017 is the ordered up-migration set preceding 018.
var migrations017 = []string{
	"001_initial.up.sql", "002_config_version.up.sql", "003_audit_log.up.sql",
	"004_blocklist_fk.up.sql", "005_operators.up.sql", "006_operator_totp.up.sql",
	"007_operator_oidc.up.sql", "008_host_advanced.up.sql", "009_per_operator_cas.up.sql",
	"010_cert_alerts.up.sql", "011_server_settings.up.sql", "012_agent_auth.up.sql",
	"013_host_mobile.up.sql", "014_multi_address.up.sql", "015_ca_predecessor.up.sql",
	"016_enrollment_token_hash.up.sql", "017_pop_nonces.up.sql",
}

func applyMigrationFiles(t *testing.T, db *sql.DB, files []string) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, f := range files {
		b, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, stmt := range splitSQLStatementsForTest(string(b)) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("apply %s stmt %q: %v", f, stmt, err)
			}
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES (?)", f); err != nil {
			t.Fatalf("record %s: %v", f, err)
		}
	}
}

// execMigrationFile runs each statement of one migration file and returns the
// first error (used to assert intentional fail-loud behavior).
func execMigrationFile(db *sql.DB, file string) error {
	b, err := migrations.FS.ReadFile(file)
	if err != nil {
		return err
	}
	for _, stmt := range splitSQLStatementsForTest(string(b)) {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			return err
		}
	}
	return nil
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// TestMigration018_BackfillsNetworkID_AndDownRoundTrip verifies the backfill of
// pre-existing host_addresses rows (the SELECT that no store-method test
// exercises, since those create rows after the column exists) and the down
// migration's drop-index-before-drop-column round trip.
func TestMigration018_BackfillsNetworkID_AndDownRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations017)

	// Seed a network + host + a pre-existing host_addresses row (pre-018 schema,
	// no network_id column) so the 018 backfill SELECT is actually exercised.
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "host-1")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")

	if columnExistsInDB(t, db, "host_addresses", "network_id") {
		t.Fatal("network_id should not exist before 018")
	}

	if err := execMigrationFile(db, "018_host_address_network_uniqueness.up.sql"); err != nil {
		t.Fatalf("apply 018: %v", err)
	}

	if !columnExistsInDB(t, db, "host_addresses", "network_id") {
		t.Fatal("network_id should exist after 018")
	}
	var gotNet string
	if err := db.QueryRowContext(context.Background(),
		`SELECT network_id FROM host_addresses WHERE host_id = ?`, "h1").Scan(&gotNet); err != nil {
		t.Fatalf("read backfilled network_id: %v", err)
	}
	if gotNet != "net1" {
		t.Errorf("backfilled network_id = %q, want net1", gotNet)
	}

	// Down round-trip: index dropped before column.
	if err := execMigrationFile(db, "018_host_address_network_uniqueness.down.sql"); err != nil {
		t.Fatalf("apply 018 down: %v", err)
	}
	if columnExistsInDB(t, db, "host_addresses", "network_id") {
		t.Error("network_id should be gone after 018 down")
	}
}

// TestMigration018_FailsLoudOnDuplicateOverlayIP pins the deliberate fail-safe:
// if a database already holds two hosts sharing one overlay IP in a network (the
// security defect this migration exists to prevent), CREATE UNIQUE INDEX must
// abort the migration rather than silently tolerate it.
func TestMigration018_FailsLoudOnDuplicateOverlayIP(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations017)

	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "host-1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h2", "net1", "host-2")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 0, "10.0.0.5")

	err = execMigrationFile(db, "018_host_address_network_uniqueness.up.sql")
	if err == nil {
		t.Fatal("018 must fail loud on a pre-existing duplicate overlay IP, but succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Errorf("018 failure = %v, want a UNIQUE constraint error", err)
	}
}

// openSeeded017 returns a single-connection in-memory DB with migrations 001–017
// applied. Foreign keys are off (sql.Open default), so tests can seed orphan
// host_addresses rows directly; MaxOpenConns(1) keeps the per-connection
// ":memory:" database stable across the guard's multiple queries.
func openSeeded017(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	applyMigrationFiles(t, db, migrations017)
	// Migration 014 ends with PRAGMA foreign_keys=ON; turn it back off so tests
	// can seed orphan host_addresses rows (the realistic FK-on path is covered by
	// the Migrate-level tests, which reopen via NewSQLiteStore).
	mustExec(t, db, `PRAGMA foreign_keys = OFF`)
	return db
}

// seedTempDBThrough017 creates a temp-file SQLite database, applies migrations
// 001–017 with foreign keys off (so orphan rows can be seeded), runs seed, then
// closes it. Returns the path for NewSQLiteStore to reopen.
func seedTempDBThrough017(t *testing.T, seed func(*sql.DB)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	db.SetMaxOpenConns(1)
	applyMigrationFiles(t, db, migrations017)
	// Disable FK so seed can insert orphan rows; NewSQLiteStore reopens with
	// foreign_keys=ON, exercising the realistic path.
	mustExec(t, db, `PRAGMA foreign_keys = OFF`)
	seed(db)
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}
	return path
}

func countHostAddresses(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM host_addresses`).Scan(&n); err != nil {
		t.Fatalf("count host_addresses: %v", err)
	}
	return n
}

func countHostAddressesFor(t *testing.T, db *sql.DB, hostID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM host_addresses WHERE host_id = ?`, hostID).Scan(&n); err != nil {
		t.Fatalf("count host_addresses for %s: %v", hostID, err)
	}
	return n
}

func hostAddressList(t *testing.T, db *sql.DB, hostID string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT address FROM host_addresses WHERE host_id = ? ORDER BY position`, hostID)
	if err != nil {
		t.Fatalf("list host_addresses for %s: %v", hostID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan address: %v", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate addresses: %v", err)
	}
	return out
}

// TestCheckOverlayIPConflicts_CrossHostFailsLoud pins the irreducible case: two
// distinct hosts sharing one overlay IP. The guard fails loud with a message
// naming both hosts and the IP, frames it as a security defect, is precise that
// removing the row does not revoke the certificate, and mutates nothing.
func TestCheckOverlayIPConflicts_CrossHostFailsLoud(t *testing.T) {
	db := openSeeded017(t)
	defer db.Close()
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h2", "net1", "web-2")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 0, "10.0.0.5")

	err := checkOverlayIPConflicts(context.Background(), db)
	if err == nil {
		t.Fatal("cross-host duplicate must fail loud, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"10.0.0.5", "web-1", "web-2", "security", "does NOT revoke", "before upgrading"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q\n--- message ---\n%s", want, msg)
		}
	}
	if n := countHostAddresses(t, db); n != 2 {
		t.Errorf("cross-host fail path mutated host_addresses: got %d rows, want 2", n)
	}
}

// TestCheckOverlayIPConflicts_SameHostDupAutoCollapses verifies one host bound to
// the same IP twice is collapsed to a single row (no winner to choose, same
// certificate), so the guard returns nil and 018 then applies.
func TestCheckOverlayIPConflicts_SameHostDupAutoCollapses(t *testing.T) {
	db := openSeeded017(t)
	defer db.Close()
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
	// h1 holds 10.0.0.5 twice (a redundant binding to collapse) and 10.0.0.8 once
	// (a legitimately distinct second address that must be preserved — guards
	// against a regression that keyed the DELETE on host_id alone).
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 1, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 2, "10.0.0.8")

	if err := checkOverlayIPConflicts(context.Background(), db); err != nil {
		t.Fatalf("same-host duplicate should auto-collapse, got error: %v", err)
	}
	addrs := hostAddressList(t, db, "h1")
	got := map[string]int{}
	for _, a := range addrs {
		got[a]++
	}
	if len(addrs) != 2 || got["10.0.0.5"] != 1 || got["10.0.0.8"] != 1 {
		t.Errorf("collapse should leave exactly one 10.0.0.5 and preserve 10.0.0.8, got %v", addrs)
	}
	if err := execMigrationFile(db, "018_host_address_network_uniqueness.up.sql"); err != nil {
		t.Fatalf("018 should apply cleanly after collapse: %v", err)
	}
}

// TestCheckOverlayIPConflicts_CrossHostFailDoesNotCleanup pins the invariant that
// the cross-host fail path mutates nothing — even when orphan and same-host
// duplicate rows (which would otherwise be auto-repaired) are also present. A
// regression that ran cleanup before the fail-loud check would delete rows from
// a database meant to be left untouched, and would pass every other test.
func TestCheckOverlayIPConflicts_CrossHostFailDoesNotCleanup(t *testing.T) {
	db := openSeeded017(t)
	defer db.Close()
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h2", "net1", "web-2")
	// Cross-host conflict (must fail loud).
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 0, "10.0.0.5")
	// Cleanable rows that must NOT be touched on the fail path.
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 1, "10.0.0.7")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 2, "10.0.0.7")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "ghost", 0, "10.0.0.9")

	before := countHostAddresses(t, db)
	if err := checkOverlayIPConflicts(context.Background(), db); err == nil {
		t.Fatal("cross-host conflict must fail loud")
	}
	if after := countHostAddresses(t, db); after != before {
		t.Errorf("fail path mutated host_addresses: before=%d after=%d (cleanup must not run when failing loud)", before, after)
	}
}

// TestCrossHostOverlayConflicts_GroupingAndDedup exercises the grouping logic:
// multiple distinct conflicts produce one group each in deterministic order, and
// a host appearing twice within a group (via a same-host duplicate) is listed
// once.
func TestCrossHostOverlayConflicts_GroupingAndDedup(t *testing.T) {
	db := openSeeded017(t)
	defer db.Close()
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	for _, h := range []struct{ id, name string }{{"h1", "web-1"}, {"h2", "web-2"}, {"h3", "web-3"}} {
		mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, h.id, "net1", h.name)
	}
	// Group A (10.0.0.5): h1 (listed twice) + h2 → h1 must dedup to one entry.
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 1, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 0, "10.0.0.5")
	// Group B (10.0.0.6): h2 + h3.
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 1, "10.0.0.6")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h3", 0, "10.0.0.6")

	conflicts, err := crossHostOverlayConflicts(context.Background(), db)
	if err != nil {
		t.Fatalf("crossHostOverlayConflicts: %v", err)
	}
	if len(conflicts) != 2 {
		t.Fatalf("want 2 conflict groups, got %d: %+v", len(conflicts), conflicts)
	}
	if conflicts[0].address != "10.0.0.5" || conflicts[1].address != "10.0.0.6" {
		t.Errorf("groups out of order: %q then %q", conflicts[0].address, conflicts[1].address)
	}
	if len(conflicts[0].hosts) != 2 {
		t.Errorf("group 10.0.0.5 should list 2 distinct hosts (h1 deduped), got %v", conflicts[0].hosts)
	}
}

// TestFormatCrossHostConflicts_Caps exercises the truncation guards on both the
// group list and the per-group host list (a slice-bound or off-by-one here would
// otherwise only surface on a pathological database during a failed upgrade).
func TestFormatCrossHostConflicts_Caps(t *testing.T) {
	var groups []overlayConflict
	for i := 0; i < maxConflictsListed+3; i++ {
		groups = append(groups, overlayConflict{
			network: "net1", address: fmt.Sprintf("10.0.0.%d", i), hosts: []string{"a (h-a)", "b (h-b)"},
		})
	}
	if msg := formatCrossHostConflicts(groups); !strings.Contains(msg, "… and 3 more") {
		t.Errorf("group cap not applied:\n%s", msg)
	}

	var hosts []string
	for i := 0; i < maxConflictsListed+5; i++ {
		hosts = append(hosts, fmt.Sprintf("host-%d (h%d)", i, i))
	}
	if msg := formatCrossHostConflicts([]overlayConflict{{network: "net1", address: "10.0.0.1", hosts: hosts}}); !strings.Contains(msg, "… and 5 more") {
		t.Errorf("per-group host cap not applied:\n%s", msg)
	}
}

// TestCheckOverlayIPConflicts_CleanupLogsAudit verifies the auto-repair emits the
// slog.Warn audit lines — the only operator-visible record that startup silently
// mutated host_addresses.
func TestCheckOverlayIPConflicts_CleanupLogsAudit(t *testing.T) {
	db := openSeeded017(t)
	defer db.Close()
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 1, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "ghost", 0, "10.0.0.9")

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	if err := checkOverlayIPConflicts(context.Background(), db); err != nil {
		t.Fatalf("auto-repair should succeed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "removed orphaned host_addresses") {
		t.Errorf("missing orphan cleanup audit log:\n%s", out)
	}
	if !strings.Contains(out, "collapsed duplicate same-host") {
		t.Errorf("missing same-host cleanup audit log:\n%s", out)
	}
}

// TestCheckOverlayIPConflicts_OrphanAutoRemoves verifies a host_addresses row
// whose host no longer exists (reachable only with foreign keys off) is removed
// as dangling junk; the guard returns nil.
func TestCheckOverlayIPConflicts_OrphanAutoRemoves(t *testing.T) {
	db := openSeeded017(t)
	defer db.Close()
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "ghost", 0, "10.0.0.9")

	if err := checkOverlayIPConflicts(context.Background(), db); err != nil {
		t.Fatalf("orphan row should auto-remove, got error: %v", err)
	}
	if n := countHostAddressesFor(t, db, "ghost"); n != 0 {
		t.Errorf("orphan row not removed: %d remain", n)
	}
	if total := countHostAddresses(t, db); total != 1 {
		t.Errorf("expected 1 surviving row, got %d", total)
	}
}

// TestCheckOverlayIPConflicts_NoneIsNoop verifies distinct IPs with no orphans
// return nil and leave the table untouched.
func TestCheckOverlayIPConflicts_NoneIsNoop(t *testing.T) {
	db := openSeeded017(t)
	defer db.Close()
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h2", "net1", "web-2")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 0, "10.0.0.6")

	if err := checkOverlayIPConflicts(context.Background(), db); err != nil {
		t.Fatalf("no conflicts should return nil, got: %v", err)
	}
	if n := countHostAddresses(t, db); n != 2 {
		t.Errorf("no-op case mutated rows: got %d, want 2", n)
	}
}

// TestMigrate_CrossHostConflictFailsLoudUntouched drives a real Migrate over a DB
// with a cross-host duplicate: it must fail before 018 runs, so network_id is
// never added and the conflicting rows are left intact for the operator.
func TestMigrate_CrossHostConflictFailsLoudUntouched(t *testing.T) {
	path := seedTempDBThrough017(t, func(db *sql.DB) {
		mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
		mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
		mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h2", "net1", "web-2")
		mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
		mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 0, "10.0.0.5")
	})

	st, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(context.Background()); err == nil {
		t.Fatal("Migrate must fail loud on a cross-host overlay-IP conflict")
	}
	if columnExistsInDB(t, st.db, "host_addresses", "network_id") {
		t.Error("018 must not run on the fail path (network_id was added)")
	}
	if n := countHostAddresses(t, st.db); n != 2 {
		t.Errorf("fail path mutated host_addresses: got %d rows, want 2", n)
	}
}

// TestMigrate_AutoResolvesOrphanAndSameHost drives a real Migrate over a DB with
// an orphan row and a same-host duplicate (no cross-host conflict): the guard
// repairs both and 018 applies cleanly.
func TestMigrate_AutoResolvesOrphanAndSameHost(t *testing.T) {
	path := seedTempDBThrough017(t, func(db *sql.DB) {
		mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
		mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "web-1")
		mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
		mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 1, "10.0.0.5")
		mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "ghost", 0, "10.0.0.9")
	})

	st, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate should auto-resolve and succeed, got: %v", err)
	}
	if !columnExistsInDB(t, st.db, "host_addresses", "network_id") {
		t.Error("018 should have applied (network_id missing)")
	}
	if n := countHostAddressesFor(t, st.db, "ghost"); n != 0 {
		t.Errorf("orphan not removed: %d rows for ghost", n)
	}
	if n := countHostAddressesFor(t, st.db, "h1"); n != 1 {
		t.Errorf("same-host dup not collapsed: %d rows for h1, want 1", n)
	}
}
