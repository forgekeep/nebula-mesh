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
	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
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
	if passphrase == "" && schemaVer >= "006_operator_totp.up.sql" && schemaVer < "029_encrypt_operator_totp.up.sql" {
		var legacySeeds int
		if err := s.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM operators WHERE totp_secret <> ''`).Scan(&legacySeeds); err != nil {
			return fmt.Errorf("check legacy TOTP seeds before backup: %w", err)
		}
		if legacySeeds != 0 {
			return fmt.Errorf("unencrypted backup would contain %d plaintext TOTP seed(s): start the server to migrate the database or supply a backup passphrase", legacySeeds)
		}
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
// configPath. With the server stopped, it stages, migrates and verifies the
// archive before publishing the replacement. An existing database is only
// replaced with force, and is retained as a rollback copy.
func OpsRestore(configPath, inputPath, passphrase string, force bool) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	master, hasher, err := resolveRuntimeKeys(cfg, configPath)
	if err != nil {
		return err
	}
	defer hasher.Destroy()

	existing, statErr := os.Lstat(cfg.DBPath)
	if statErr == nil && !force {
		return fmt.Errorf("refusing to overwrite existing database at %s; pass --force to replace it", cfg.DBPath)
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
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

	// Stage in a private directory on the same filesystem. Never open the
	// live database for writes while validating archive contents.
	stageDir, err := os.MkdirTemp(filepath.Dir(cfg.DBPath), ".nebula-restore-*")
	if err != nil {
		return fmt.Errorf("create restore staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageDir) }()
	stagedDB := filepath.Join(stageDir, "nebula.db")
	manifest, err := backup.Restore(in, stagedDB, passphrase)
	if err != nil {
		return fmt.Errorf("restore archive: %w", err)
	}

	verifiedCAs, err := prepareRestoredDB(stagedDB, inputPath, manifest.SchemaVersion, master, hasher)
	if err != nil {
		return err
	}
	if err := publishRestoredDB(stagedDB, cfg.DBPath, existing); err != nil {
		return err
	}

	fmt.Printf("restored %s (app %s, schema %s, taken %s); verified %d CA key(s) decrypt under the master key\n",
		inputPath, manifest.AppVersion, manifest.SchemaVersion, manifest.CreatedAt.Format(time.RFC3339), verifiedCAs)
	return nil
}

func prepareRestoredDB(stagedDB, inputPath, schemaVersion string, master *keystore.Master, hasher *credentialhash.Hasher) (_ int, err error) {
	ctx := context.Background()
	s, err := store.NewSQLiteStore(stagedDB,
		store.WithCredentialHasher(hasher),
		store.WithTOTPSecretMaster(master),
		store.WithCredentialCutoverGuard(credentialCutoverMasterGuard(master)),
	)
	if err != nil {
		return 0, fmt.Errorf("open restored store: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close staged database: %w", closeErr))
		}
	}()

	// Roll an older backup forward to the binary's schema.
	if err := s.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate restored database: %w", err)
	}

	// Master-key check: every CA must decrypt under the supplied key, or the
	// restore is useless. Fail here, loudly, not at first signing.
	resolver := pki.NewCAResolver(s, master)
	cas, err := s.ListCAs(ctx)
	if err != nil {
		return 0, fmt.Errorf("list restored CAs: %w", err)
	}
	if err := verifyRestoredCAs(ctx, cas, resolver.VerifyCAKey); err != nil {
		return 0, err
	}

	_ = s.AddAuditEntry(ctx, "ops", "backup.restored", inputPath, "schema="+schemaVersion)
	return len(cas), nil
}

// verifyRestoredCAs checks every restored CA without taking ownership of decrypted keys.
func verifyRestoredCAs(ctx context.Context, cas []*models.CA, verify func(context.Context, string) error) error {
	for _, ca := range cas {
		if err := verify(ctx, ca.ID); err != nil {
			return fmt.Errorf("master key cannot decrypt CA %q (%s): %w — verify NEBULA_MGMT_MASTER_KEY for this backup; database not replaced",
				ca.Name, ca.ID, err)
		}
	}
	return nil
}

// resolveMaster resolves the master key the same way the server does: env wins
// over the config field. It is required so the post-restore decryption check
// can run.
func resolveRuntimeKeys(cfg *config.ServerConfig, configPath string) (*keystore.Master, *credentialhash.Hasher, error) {
	masterB64 := cfg.MasterKey
	if env := os.Getenv("NEBULA_MGMT_MASTER_KEY"); env != "" {
		masterB64 = env
	}
	if masterB64 == "" {
		return nil, nil, fmt.Errorf("master key required for restore: set NEBULA_MGMT_MASTER_KEY env or master_key in %s", configPath)
	}
	master, hasher, err := loadRuntimeKeys(masterB64)
	if err != nil {
		return nil, nil, fmt.Errorf("master key: %w", err)
	}
	return master, hasher, nil
}

func publishRestoredDB(stagedDB, dbPath string, existing os.FileInfo) error {
	if err := requireNoSQLiteSidecars(stagedDB); err != nil {
		return fmt.Errorf("staged database did not close cleanly: %w", err)
	}
	if err := requireNoSQLiteSidecars(dbPath); err != nil {
		return fmt.Errorf("cannot replace database; stop the server and close SQLite cleanly: %w", err)
	}
	if existing == nil {
		// Do not clobber a destination that appeared during validation.
		if err := os.Link(stagedDB, dbPath); err != nil {
			return fmt.Errorf("install restored database: %w", err)
		}
		return nil
	}
	current, err := os.Lstat(dbPath)
	if err != nil {
		return fmt.Errorf("check existing database before replacement: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(existing, current) {
		return fmt.Errorf("refusing to replace changed or non-regular database at %s", dbPath)
	}
	bak := dbPath + ".pre-restore"
	// Keep the original at its live path until replacement succeeds, and
	// never overwrite an earlier rollback copy.
	if err := os.Link(dbPath, bak); err != nil {
		return fmt.Errorf("preserve existing database at %s (move a prior rollback copy out of the way first): %w", bak, err)
	}
	if err := os.Rename(stagedDB, dbPath); err != nil {
		return fmt.Errorf("install restored database (original retained at %s): %w", bak, err)
	}
	fmt.Printf("preserved existing database at %s\n", bak)
	return nil
}

func requireNoSQLiteSidecars(dbPath string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		path := dbPath + suffix
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("SQLite sidecar exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect SQLite sidecar %s: %w", path, err)
		}
	}
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
