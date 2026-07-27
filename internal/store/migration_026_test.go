package store

import (
	"context"
	"database/sql"
	"sync"
	"testing"
)

var migrations025 = append(append([]string{}, migrations023...),
	"024_mesh_import_challenge_limits.up.sql",
	"025_oidc_unique.up.sql",
)

func TestMigration026RedeliversRenderedConfigExactlyOnce(t *testing.T) {
	path := t.TempDir() + "/store.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open seed sqlite: %v", err)
	}
	applyMigrationFiles(t, db, migrations025)
	mustExec(t, db, `INSERT INTO networks (id, name, config_version) VALUES (?, ?, ?)`, "net-1", "one", 7)
	mustExec(t, db, `INSERT INTO networks (id, name, config_version) VALUES (?, ?, ?)`, "net-2", "two", 41)
	if err := db.Close(); err != nil {
		t.Fatalf("close seed sqlite: %v", err)
	}

	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	for i := 0; i < 2; i++ {
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate pass %d: %v", i+1, err)
		}
	}

	for networkID, want := range map[string]int{"net-1": 8, "net-2": 42} {
		got, err := s.GetNetworkConfigVersion(context.Background(), networkID)
		if err != nil {
			t.Fatalf("get network %s config version: %v", networkID, err)
		}
		if got != want {
			t.Errorf("network %s config version = %d, want %d", networkID, got, want)
		}
	}

	var applied int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, "026_redeliver_wdf_config.up.sql").Scan(&applied); err != nil {
		t.Fatalf("query migration record: %v", err)
	}
	if applied != 1 {
		t.Errorf("migration records = %d, want 1", applied)
	}
}

func TestMigration026DownDoesNotDiscardLaterConfigVersion(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	applyMigrationFiles(t, db, migrations025)
	mustExec(t, db, `INSERT INTO networks (id, name, config_version) VALUES (?, ?, ?)`, "net-1", "one", 7)
	if err := execMigrationFile(db, "026_redeliver_wdf_config.up.sql"); err != nil {
		t.Fatalf("apply 026: %v", err)
	}
	mustExec(t, db, `UPDATE networks SET config_version = config_version + 1 WHERE id = ?`, "net-1")
	if err := execMigrationFile(db, "026_redeliver_wdf_config.down.sql"); err != nil {
		t.Fatalf("apply 026 down: %v", err)
	}

	var got int
	if err := db.QueryRow(`SELECT config_version FROM networks WHERE id = ?`, "net-1").Scan(&got); err != nil {
		t.Fatalf("read config version: %v", err)
	}
	if got != 9 {
		t.Errorf("config version after down = %d, want 9", got)
	}
}

func TestMigration026ConcurrentMigrateBumpsConfigOnce(t *testing.T) {
	path := t.TempDir() + "/store.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open seed sqlite: %v", err)
	}
	applyMigrationFiles(t, db, migrations025)
	mustExec(t, db, `INSERT INTO networks (id, name, config_version) VALUES (?, ?, ?)`, "net-1", "one", 7)
	if err := db.Close(); err != nil {
		t.Fatalf("close seed sqlite: %v", err)
	}

	stores := make([]*SQLiteStore, 2)
	for i := range stores {
		stores[i], err = NewSQLiteStore(path)
		if err != nil {
			t.Fatalf("open store %d: %v", i, err)
		}
		defer stores[i].Close()
	}

	start := make(chan struct{})
	errs := make(chan error, len(stores))
	var wg sync.WaitGroup
	for _, s := range stores {
		wg.Go(func() {
			<-start
			errs <- s.Migrate(context.Background())
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate: %v", err)
		}
	}

	got, err := stores[0].GetNetworkConfigVersion(context.Background(), "net-1")
	if err != nil {
		t.Fatalf("get config version: %v", err)
	}
	if got != 8 {
		t.Errorf("config version after concurrent migrate = %d, want 8", got)
	}
}
