package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/store/migrations"

	_ "modernc.org/sqlite"
)

// TestMigration014_BackfillsAndDropsLegacyColumns verifies that migration 014
// creates new normalized tables network_cidrs and host_addresses, backfills data
// from the legacy networks.cidr and hosts.nebula_ip columns, and drops those columns.
//
// This test independently verifies the migration without relying on store methods
// that haven't been updated yet.
func TestMigration014_BackfillsAndDropsLegacyColumns(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Apply migrations up to 013 (without 014 yet).
	migrations013 := []string{
		"001_initial.up.sql",
		"002_config_version.up.sql",
		"003_audit_log.up.sql",
		"004_blocklist_fk.up.sql",
		"005_operators.up.sql",
		"006_operator_totp.up.sql",
		"007_operator_oidc.up.sql",
		"008_host_advanced.up.sql",
		"009_per_operator_cas.up.sql",
		"010_cert_alerts.up.sql",
		"011_server_settings.up.sql",
		"012_agent_auth.up.sql",
		"013_host_mobile.up.sql",
	}

	// Create schema_migrations tracking table.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	// Apply migrations 001-013.
	for _, f := range migrations013 {
		sqlBytes, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}
		for _, stmt := range splitSQLStatementsForTest(string(sqlBytes)) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("apply migration %s stmt %q: %v", f, stmt, err)
			}
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES (?)", f); err != nil {
			t.Fatalf("record migration %s: %v", f, err)
		}
	}

	// At this point, old columns should exist.
	if !columnExistsInDB(t, db, "networks", "cidr") {
		t.Fatalf("column networks.cidr should exist before migration 014")
	}
	if !columnExistsInDB(t, db, "hosts", "nebula_ip") {
		t.Fatalf("column hosts.nebula_ip should exist before migration 014")
	}

	// Insert test data using the pre-014 schema.
	testNetID := "net_test_014"
	testCIDR := "10.42.0.0/24"
	testHostID := "host_test_014"
	testAddr := "10.42.0.5"

	if _, err := db.ExecContext(ctx, `
		INSERT INTO networks (id, name, cidr, created_at, ca_id)
		VALUES (?, ?, ?, ?, ?)
	`, testNetID, "test-net", testCIDR, time.Now(), "ca_test"); err != nil {
		t.Fatalf("insert network (pre-014): %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO hosts (
			id, network_id, name, nebula_ip, groups_json, role, is_lighthouse, is_relay,
			public_ip, listen_port, status, cert_fingerprint, cert_expires_at,
			last_seen_at, created_at, updated_at, advanced_json, ca_id,
			prev_cert_fingerprint, cert_rotated_at, pending_rekey, signing_pub_pem,
			kind, variant
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, testHostID, testNetID, "test-host", testAddr, "[]", "host", 0, 0, "1.2.3.4", 4242,
		"pending", "", nil, nil, time.Now(), time.Now(), "", "ca_test", "", nil, 0, "", "agent", ""); err != nil {
		t.Fatalf("insert host (pre-014): %v", err)
	}

	// Apply migration 014.
	migr014Bytes, err := migrations.FS.ReadFile("014_multi_address.up.sql")
	if err != nil {
		t.Fatalf("read migration 014: %v", err)
	}
	for _, stmt := range splitSQLStatementsForTest(string(migr014Bytes)) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply migration 014 stmt: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES (?)", "014_multi_address.up.sql"); err != nil {
		t.Fatalf("record migration 014: %v", err)
	}

	// Verify new tables exist.
	if !tableExistsInDB(t, db, "network_cidrs") {
		t.Fatalf("table network_cidrs does not exist after migration 014")
	}
	if !tableExistsInDB(t, db, "host_addresses") {
		t.Fatalf("table host_addresses does not exist after migration 014")
	}

	// Verify old columns are dropped.
	if columnExistsInDB(t, db, "networks", "cidr") {
		t.Errorf("column networks.cidr should be dropped after migration 014")
	}
	if columnExistsInDB(t, db, "hosts", "nebula_ip") {
		t.Errorf("column hosts.nebula_ip should be dropped after migration 014")
	}

	// Verify backfill: CIDR should be in network_cidrs at position 0.
	var gotCIDR string
	if err := db.QueryRowContext(ctx, `
		SELECT cidr FROM network_cidrs WHERE network_id = ? AND position = 0
	`, testNetID).Scan(&gotCIDR); err != nil {
		t.Fatalf("query network_cidrs: %v", err)
	}
	if gotCIDR != testCIDR {
		t.Errorf("network_cidrs CIDR = %q, want %q", gotCIDR, testCIDR)
	}

	// Verify backfill: nebula_ip should be in host_addresses at position 0.
	var gotAddr string
	if err := db.QueryRowContext(ctx, `
		SELECT address FROM host_addresses WHERE host_id = ? AND position = 0
	`, testHostID).Scan(&gotAddr); err != nil {
		t.Fatalf("query host_addresses: %v", err)
	}
	if gotAddr != testAddr {
		t.Errorf("host_addresses address = %q, want %q", gotAddr, testAddr)
	}
}

// TestMigration014_OnEmptyDB verifies that migration 014 applies without error
// to an empty database (no networks or hosts to backfill).
func TestMigration014_OnEmptyDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Create schema_migrations tracking table.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	// Apply migrations 001-013.
	migrations013 := []string{
		"001_initial.up.sql",
		"002_config_version.up.sql",
		"003_audit_log.up.sql",
		"004_blocklist_fk.up.sql",
		"005_operators.up.sql",
		"006_operator_totp.up.sql",
		"007_operator_oidc.up.sql",
		"008_host_advanced.up.sql",
		"009_per_operator_cas.up.sql",
		"010_cert_alerts.up.sql",
		"011_server_settings.up.sql",
		"012_agent_auth.up.sql",
		"013_host_mobile.up.sql",
	}

	for _, f := range migrations013 {
		sqlBytes, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}
		for _, stmt := range splitSQLStatementsForTest(string(sqlBytes)) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("apply migration %s: %v", f, err)
			}
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES (?)", f); err != nil {
			t.Fatalf("record migration %s: %v", f, err)
		}
	}

	// Apply migration 014 to an empty database (no networks or hosts to backfill).
	migr014Bytes, err := migrations.FS.ReadFile("014_multi_address.up.sql")
	if err != nil {
		t.Fatalf("read migration 014: %v", err)
	}
	for _, stmt := range splitSQLStatementsForTest(string(migr014Bytes)) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply migration 014 to empty DB: %v", err)
		}
	}

	// Verify new tables exist.
	if !tableExistsInDB(t, db, "network_cidrs") {
		t.Fatalf("table network_cidrs does not exist after migration 014 on empty DB")
	}
	if !tableExistsInDB(t, db, "host_addresses") {
		t.Fatalf("table host_addresses does not exist after migration 014 on empty DB")
	}

	// Verify the tables are empty (no data to backfill).
	var networkCIDRsCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM network_cidrs").Scan(&networkCIDRsCount); err != nil {
		t.Fatalf("query network_cidrs count: %v", err)
	}
	if networkCIDRsCount != 0 {
		t.Errorf("network_cidrs has %d rows, want 0 on empty DB", networkCIDRsCount)
	}

	var hostAddressesCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_addresses").Scan(&hostAddressesCount); err != nil {
		t.Fatalf("query host_addresses count: %v", err)
	}
	if hostAddressesCount != 0 {
		t.Errorf("host_addresses has %d rows, want 0 on empty DB", hostAddressesCount)
	}
}

// tableExistsInDB checks if a table with the given name exists in the database.
func tableExistsInDB(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'table' AND name = ?
	`, table).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	return count > 0
}

// columnExistsInDB checks if a column with the given name exists in the table.
func columnExistsInDB(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ");")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var dflt sql.NullString
		var notnull, pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return true
		}
	}
	return false
}

// splitSQLStatementsForTest is a copy of splitSQLStatements from sqlite.go for testing.
// It splits an SQL script into individual statements, respecting quotes and comments.
func splitSQLStatementsForTest(src string) []string {
	var (
		out      []string
		current  []byte
		inSingle bool
		inDouble bool
		inLine   bool
		paren    int
	)
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inLine {
			current = append(current, c)
			if c == '\n' {
				inLine = false
			}
			continue
		}
		switch {
		case !inSingle && !inDouble && c == '-' && i+1 < len(src) && src[i+1] == '-':
			inLine = true
			current = append(current, c)
		case !inDouble && c == '\'':
			inSingle = !inSingle
			current = append(current, c)
		case !inSingle && c == '"':
			inDouble = !inDouble
			current = append(current, c)
		case !inSingle && !inDouble && c == '(':
			paren++
			current = append(current, c)
		case !inSingle && !inDouble && c == ')':
			if paren > 0 {
				paren--
			}
			current = append(current, c)
		case !inSingle && !inDouble && paren == 0 && c == ';':
			stmt := trimSpaceSQL(string(current))
			if stmt != "" {
				out = append(out, stmt)
			}
			current = current[:0]
		default:
			current = append(current, c)
		}
	}
	if tail := trimSpaceSQL(string(current)); tail != "" {
		out = append(out, tail)
	}
	return out
}

func trimSpaceSQL(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
