package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

const migration029Name = "029_encrypt_operator_totp.up.sql"

func legacyTOTPFixture(t *testing.T) (string, *keystore.Master) {
	t.Helper()
	path := t.TempDir() + "/store.db"
	master, err := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSQLiteStore(path, WithTOTPSecretMaster(master))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"enabled", "pending", "blank"} {
		if err := s.CreateOperator(ctx, &models.Operator{
			ID: id, Username: id, PasswordHash: "hash", Role: models.OperatorRoleUser,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []string{
		`DROP TRIGGER operator_totp_secret_insert`,
		`DROP TRIGGER operator_totp_secret_update`,
		`DELETE FROM schema_migrations WHERE name = '` + migration029Name + `'`,
		`UPDATE operators SET totp_secret = 'JBSWY3DPEHPK3PXP', totp_enabled = 1 WHERE id = 'enabled'`,
		`UPDATE operators SET totp_secret = 'MFRGGZDFMZTWQ2LK', totp_enabled = 0 WHERE id = 'pending'`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path, master
}

func TestMigration029_SEC_TOTP_001_EncryptsEnabledAndPendingSecrets(t *testing.T) {
	path, master := legacyTOTPFixture(t)
	s, err := NewSQLiteStore(path, WithTOTPSecretMaster(master))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	for _, tc := range []struct {
		id, want string
		enabled  bool
	}{
		{"enabled", "JBSWY3DPEHPK3PXP", true},
		{"pending", "MFRGGZDFMZTWQ2LK", false},
		{"blank", "", false},
	} {
		var stored string
		if err := s.db.QueryRowContext(ctx, `SELECT totp_secret FROM operators WHERE id = ?`, tc.id).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if tc.want == "" && stored != "" {
			t.Fatalf("blank operator stored TOTP = %q", stored)
		}
		if tc.want != "" && (!strings.HasPrefix(stored, totpSecretPrefix) || strings.Contains(stored, tc.want)) {
			t.Fatalf("operator %s TOTP was not encrypted", tc.id)
		}
		op, err := s.GetOperator(ctx, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if op.TOTPSecret != tc.want || op.TOTPEnabled != tc.enabled {
			t.Fatalf("operator %s TOTP state changed after migration", tc.id)
		}
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE operators SET totp_secret = 'JBSWY3DPEHPK3PXP' WHERE id = 'enabled'`); err == nil {
		t.Fatal("SEC-TOTP-001: plaintext write bypassed post-migration trigger")
	}
}

func TestMigration029_SEC_PERSIST_001_MissingMasterRollsBackAndCanRetry(t *testing.T) {
	path, master := legacyTOTPFixture(t)
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Migrate(ctx); !errors.Is(err, ErrTOTPSecretMasterUnavailable) {
		t.Fatalf("migration without master = %v", err)
	}
	assertLegacyTOTPRows(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewSQLiteStore(path, WithTOTPSecretMaster(master))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("retry migration: %v", err)
	}
}

func TestMigration029_SEC_PERSIST_001_SQLFailureRollsBackEverySeed(t *testing.T) {
	path, master := legacyTOTPFixture(t)
	s, err := NewSQLiteStore(path, WithTOTPSecretMaster(master))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// SEC-SECRET-001: migration must clear every application-owned plaintext
	// buffer after a failed write, including rows processed before the failure.
	observer := &observingTOTPCipher{master: master}
	s.totpCipher = observer
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_pending_totp_update
		BEFORE UPDATE OF totp_secret ON operators WHEN NEW.id = 'pending'
		BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("migration SQL failure = %v", err)
	}
	if len(observer.plaintext) == 0 {
		t.Fatal("migration did not pass any plaintext to the cipher")
	}
	for _, buffer := range observer.plaintext {
		for _, b := range buffer {
			if b != 0 {
				t.Fatal("SEC-SECRET-001: plaintext buffer survived failed migration")
			}
		}
	}
	assertLegacyTOTPRows(t, s)
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER fail_pending_totp_update`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("retry migration: %v", err)
	}
}

type observingTOTPCipher struct {
	master    *keystore.Master
	plaintext [][]byte
}

func (c *observingTOTPCipher) Seal(plaintext, aad []byte) (keystore.WrappedBlob, error) {
	c.plaintext = append(c.plaintext, plaintext)
	return c.master.Seal(plaintext, aad)
}

func (c *observingTOTPCipher) Open(blob keystore.WrappedBlob, aad []byte) ([]byte, error) {
	return c.master.Open(blob, aad)
}

func TestSQLiteStore_SEC_TOTP_001_RejectsWrongKeyAndCiphertextSwap(t *testing.T) {
	path, master := legacyTOTPFixture(t)
	s, err := NewSQLiteStore(path, WithTOTPSecretMaster(master))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	wrongMaster, err := keystore.NewMaster(bytes.Repeat([]byte{0x88}, keystore.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewSQLiteStore(path, WithTOTPSecretMaster(wrongMaster))
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Migrate(ctx); err == nil {
		t.Fatal("startup accepted database encrypted under another master key")
	}
	if _, err := other.GetOperator(ctx, "enabled"); err == nil {
		t.Fatal("wrong master key decrypted TOTP secret")
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT totp_secret FROM operators WHERE id = 'enabled'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE operators SET totp_secret = ? WHERE id = 'pending'`, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOperator(ctx, "pending"); err == nil {
		t.Fatal("cross-operator ciphertext swap decrypted TOTP secret")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE operators SET totp_secret = ? WHERE id = 'pending'`, totpSecretPrefix+"malformed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOperator(ctx, "pending"); err == nil {
		t.Fatal("malformed ciphertext was accepted as a TOTP secret")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteStore_SEC_TOTP_001_NewSeedsAreEncryptedAndRequireMaster(t *testing.T) {
	path := t.TempDir() + "/store.db"
	master, err := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSQLiteStore(path, WithTOTPSecretMaster(master))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperator(ctx, &models.Operator{
		ID: "new", Username: "new", PasswordHash: "hash", Role: models.OperatorRoleUser,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOperatorTOTP(ctx, "new", "JBSWY3DPEHPK3PXP", false); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT totp_secret FROM operators WHERE id = 'new'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, totpSecretPrefix) || strings.Contains(stored, "JBSWY3DPEHPK3PXP") {
		t.Fatal("new pending TOTP seed was stored as plaintext")
	}
	bare, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	if err := bare.SetOperatorTOTP(ctx, "new", "another-secret", true); !errors.Is(err, ErrTOTPSecretMasterUnavailable) {
		t.Fatalf("write without master = %v", err)
	}
	if _, err := bare.GetOperator(ctx, "new"); !errors.Is(err, ErrTOTPSecretMasterUnavailable) {
		t.Fatalf("read without master = %v", err)
	}
	if err := s.SetOperatorTOTP(ctx, "new", "", false); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT totp_secret FROM operators WHERE id = 'new'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatal("disabling TOTP left ciphertext in the operator row")
	}
}

func assertLegacyTOTPRows(t *testing.T, s *SQLiteStore) {
	t.Helper()
	var applied int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, migration029Name).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("migration marker exists after failure")
	}
	for id, want := range map[string]string{"enabled": "JBSWY3DPEHPK3PXP", "pending": "MFRGGZDFMZTWQ2LK"} {
		var stored string
		if err := s.db.QueryRow(`SELECT totp_secret FROM operators WHERE id = ?`, id).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != want {
			t.Fatalf("operator %s changed after failed migration", id)
		}
	}
}
