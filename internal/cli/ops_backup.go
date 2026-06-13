package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/backup"
	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// OpsBackup writes a consistent snapshot of the control-plane database
// referenced by configPath to outputPath. When passphrase is non-empty the
// archive is encrypted. appVersion is recorded in the manifest. The master key
// is intentionally not included — restore requires the operator to supply it.
func OpsBackup(configPath, outputPath, passphrase, appVersion string) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	s, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	schemaVer, err := latestMigration(ctx, s.DB())
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	// O_EXCL: never silently overwrite an existing backup file.
	out, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- outputPath is the operator-supplied --output CLI argument
	if err != nil {
		return fmt.Errorf("create %s: %w", outputPath, err)
	}
	defer func() { _ = out.Close() }()

	meta := backup.Meta{AppVersion: appVersion, SchemaVersion: schemaVer, Now: time.Now()}
	if err := backup.Create(ctx, s.DB(), out, meta, passphrase, filepath.Dir(cfg.DBPath)); err != nil {
		// Remove the half-written archive so a failed backup leaves nothing
		// that could be mistaken for a usable one.
		_ = os.Remove(outputPath)
		return fmt.Errorf("create backup: %w", err)
	}

	enc := ""
	if passphrase != "" {
		enc = " (encrypted)"
	}
	_ = s.AddAuditEntry(ctx, "ops", "backup.created", outputPath, "schema="+schemaVer)
	fmt.Printf("wrote backup%s to %s (schema %s)\n", enc, outputPath, schemaVer)
	return nil
}

// OpsRestore restores a backup archive into the data dir referenced by
// configPath. It refuses to overwrite an existing live database unless force is
// set (in which case the current DB is moved aside). After restoring it runs
// migrations forward and verifies the master key can decrypt every restored CA,
// failing loudly on mismatch rather than at first signing.
func OpsRestore(configPath, inputPath, passphrase string, force bool) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	master, err := resolveMaster(cfg, configPath)
	if err != nil {
		return err
	}

	if _, statErr := os.Stat(cfg.DBPath); statErr == nil {
		if !force {
			return fmt.Errorf("refusing to overwrite existing database at %s; pass --force to replace it", cfg.DBPath)
		}
		if err := moveAside(cfg.DBPath); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", cfg.DBPath, statErr)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	in, err := os.Open(inputPath) // #nosec G304 -- operator-supplied archive path is the documented CLI argument
	if err != nil {
		return fmt.Errorf("open %s: %w", inputPath, err)
	}
	defer func() { _ = in.Close() }()

	manifest, err := backup.Restore(in, cfg.DBPath, passphrase)
	if err != nil {
		return fmt.Errorf("restore archive: %w", err)
	}

	ctx := context.Background()
	s, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open restored store: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Roll an older backup forward to the binary's schema.
	if err := s.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate restored database: %w", err)
	}

	// Master-key check: every CA must decrypt under the supplied key, or the
	// restore is useless. Fail here, loudly, not at first signing.
	resolver := pki.NewCAResolver(s, master)
	cas, err := s.ListCAs(ctx)
	if err != nil {
		return fmt.Errorf("list restored CAs: %w", err)
	}
	for _, ca := range cas {
		if _, err := resolver.LoadByID(ctx, ca.ID); err != nil {
			return fmt.Errorf("master key cannot decrypt CA %q (%s): %w — the restored database is in place at %s but NEBULA_MGMT_MASTER_KEY does not match this backup",
				ca.Name, ca.ID, err, cfg.DBPath)
		}
	}

	_ = s.AddAuditEntry(ctx, "ops", "backup.restored", inputPath, "schema="+manifest.SchemaVersion)
	fmt.Printf("restored %s (app %s, schema %s, taken %s); verified %d CA key(s) decrypt under the master key\n",
		inputPath, manifest.AppVersion, manifest.SchemaVersion, manifest.CreatedAt.Format(time.RFC3339), len(cas))
	return nil
}

// resolveMaster resolves the master key the same way the server does: env wins
// over the config field. It is required so the post-restore decryption check
// can run.
func resolveMaster(cfg *config.ServerConfig, configPath string) (*keystore.Master, error) {
	masterB64 := cfg.MasterKey
	if env := os.Getenv("NEBULA_MGMT_MASTER_KEY"); env != "" {
		masterB64 = env
	}
	if masterB64 == "" {
		return nil, fmt.Errorf("master key required for restore: set NEBULA_MGMT_MASTER_KEY env or master_key in %s", configPath)
	}
	master, err := keystore.NewMasterFromBase64(masterB64)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	return master, nil
}

// moveAside renames an existing database (and its WAL/SHM siblings) out of the
// way so a fresh single-file snapshot can be restored without colliding with
// stale write-ahead state.
func moveAside(dbPath string) error {
	bak := dbPath + ".pre-restore"
	if err := os.Rename(dbPath, bak); err != nil {
		return fmt.Errorf("move existing database aside: %w", err)
	}
	// WAL/SHM belong to the old DB; a restored consolidated file must not see
	// them. Best-effort removal — they may not exist.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s%s: %w", dbPath, suffix, err)
		}
	}
	fmt.Printf("moved existing database to %s\n", bak)
	return nil
}

// latestMigration returns the name of the most recently applied migration, used
// as the manifest's schema version. An empty database (no migrations table or
// no rows) yields "none".
func latestMigration(ctx context.Context, db *sql.DB) (string, error) {
	var name string
	err := db.QueryRowContext(ctx, "SELECT name FROM schema_migrations ORDER BY name DESC LIMIT 1").Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "none", nil
	}
	if err != nil {
		return "", err
	}
	return name, nil
}
