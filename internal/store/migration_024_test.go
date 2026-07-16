package store

import (
	"context"
	"database/sql"
	"testing"
)

var migrations023 = append(append([]string{}, migrations022...), "023_mesh_import.up.sql")

func TestMigration024UpgradeFrom023AndRepeatedMigrate(t *testing.T) {
	path := t.TempDir() + "/store.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open seed sqlite: %v", err)
	}
	applyMigrationFiles(t, db, migrations023)
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
	for _, index := range []string{
		"idx_mesh_import_challenges_active_session",
		"idx_mesh_import_challenges_active_fingerprint",
	} {
		if !indexExistsInDB(t, s.db, index) {
			t.Errorf("index %s does not exist", index)
		}
	}
	var applied int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`,
		"024_mesh_import_challenge_limits.up.sql").Scan(&applied); err != nil {
		t.Fatalf("query migration record: %v", err)
	}
	if applied != 1 {
		t.Errorf("migration records = %d, want 1", applied)
	}
}

func TestMigration024DownKeepsChallengeTable(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations023)
	if err := execMigrationFile(db, "024_mesh_import_challenge_limits.up.sql"); err != nil {
		t.Fatalf("apply 024: %v", err)
	}
	if err := execMigrationFile(db, "024_mesh_import_challenge_limits.down.sql"); err != nil {
		t.Fatalf("rollback 024: %v", err)
	}

	if !tableExistsInDB(t, db, "mesh_import_challenges") {
		t.Fatal("down migration removed mesh_import_challenges")
	}
	for _, index := range []string{
		"idx_mesh_import_challenges_active_session",
		"idx_mesh_import_challenges_active_fingerprint",
	} {
		if indexExistsInDB(t, db, index) {
			t.Errorf("index %s still exists after down migration", index)
		}
	}
}
