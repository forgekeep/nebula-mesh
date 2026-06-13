// Package backup creates and restores consistent snapshots of the nebula-mgmt
// control-plane database. A backup is a gzipped tar holding a manifest and a
// SQLite snapshot taken with VACUUM INTO (correct under WAL), optionally
// AES-256-GCM encrypted under an operator passphrase so archives can be shipped
// to untrusted storage (#229).
//
// The master key is deliberately NOT part of the archive: the encrypted CA
// private keys in the snapshot are useless without it, so restore requires the
// operator to supply the same NEBULA_MGMT_MASTER_KEY out of band. The caller
// (internal/cli) verifies that key can actually decrypt the restored CAs before
// declaring success.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	// FormatVersion is the archive layout version recorded in the manifest.
	FormatVersion = 1

	manifestName = "manifest.json"
	dbEntryName  = "nebula.db"

	// encMagic prefixes a passphrase-encrypted archive and doubles as the GCM
	// additional authenticated data, binding the format to the ciphertext.
	encMagic = "NMBK1\n"

	// maxArchiveBytes caps how much we read from an archive on restore, a
	// guard against a hostile/truncated archive exhausting memory. The whole
	// archive is held in memory (GCM needs the full plaintext), which is fine
	// for a single-VM SQLite control plane but is the practical size ceiling.
	maxArchiveBytes = 2 << 30 // 2 GiB

	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
	saltLen = 16
)

// Sentinel errors callers can match on.
var (
	ErrPassphraseRequired = errors.New("archive is encrypted: a passphrase is required")
	ErrDecryptFailed      = errors.New("decryption failed: wrong passphrase or corrupt archive")
	ErrCorruptArchive     = errors.New("backup archive is corrupt or truncated")
	ErrUnsupportedFormat  = errors.New("unsupported backup format version")
	ErrMissingDB          = errors.New("backup archive does not contain a database snapshot")
)

// Manifest is the metadata stored alongside the database snapshot.
type Manifest struct {
	FormatVersion int       `json:"format_version"`
	AppVersion    string    `json:"app_version"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	DBFilename    string    `json:"db_filename"`
}

// Meta is the caller-supplied metadata recorded into the manifest.
type Meta struct {
	AppVersion    string    // binary version that produced the backup
	SchemaVersion string    // latest applied migration name
	Now           time.Time // backup timestamp (injected for deterministic tests)
}

// Create writes a consistent, gzipped tar snapshot of db to w. When passphrase
// is non-empty the whole archive is AES-256-GCM encrypted (scrypt KDF) and
// prefixed with the magic header. tmpDir is where the transient VACUUM INTO
// snapshot is written — pass a directory on the same filesystem as the DB; it
// is removed before Create returns.
func Create(ctx context.Context, db *sql.DB, w io.Writer, meta Meta, passphrase, tmpDir string) error {
	snapDir, err := os.MkdirTemp(tmpDir, "nm-backup-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(snapDir) }()
	snapPath := filepath.Join(snapDir, dbEntryName)

	// VACUUM INTO takes a quoted string literal, not a bound parameter; the
	// path is our own temp file, but escape single quotes defensively. It
	// requires the target file not to already exist, which MkdirTemp guarantees.
	// #nosec G202 -- VACUUM INTO takes a quoted string literal, not a bind parameter; snapPath is our own MkdirTemp path with single quotes escaped, not user input
	if _, err := db.ExecContext(ctx, "VACUUM INTO '"+strings.ReplaceAll(snapPath, "'", "''")+"'"); err != nil {
		return fmt.Errorf("vacuum into snapshot: %w", err)
	}
	dbBytes, err := os.ReadFile(snapPath) // #nosec G304 -- snapPath is a temp file we just created
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}

	manifestBytes, err := json.MarshalIndent(Manifest{
		FormatVersion: FormatVersion,
		AppVersion:    meta.AppVersion,
		SchemaVersion: meta.SchemaVersion,
		CreatedAt:     meta.Now.UTC(),
		DBFilename:    dbEntryName,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	// Assemble the tar.gz in memory so it can be encrypted whole when asked.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := writeTarEntry(tw, manifestName, manifestBytes, meta.Now); err != nil {
		return err
	}
	if err := writeTarEntry(tw, dbEntryName, dbBytes, meta.Now); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}

	if passphrase == "" {
		if _, err := w.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write archive: %w", err)
		}
		return nil
	}
	return encrypt(w, buf.Bytes(), passphrase)
}

// Restore reads an archive from r, decrypting it when it carries the encrypted
// magic (which requires passphrase), validates the manifest, and writes the
// embedded database to destDBPath. destDBPath must not already exist — Restore
// never overwrites a database. It returns the parsed manifest.
func Restore(r io.Reader, destDBPath, passphrase string) (Manifest, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxArchiveBytes))
	if err != nil {
		return Manifest{}, fmt.Errorf("read archive: %w", err)
	}
	if bytes.HasPrefix(raw, []byte(encMagic)) {
		if passphrase == "" {
			return Manifest{}, ErrPassphraseRequired
		}
		if raw, err = decrypt(raw, passphrase); err != nil {
			return Manifest{}, err
		}
	}

	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrCorruptArchive, err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var (
		manifest *Manifest
		dbBytes  []byte
	)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("%w: %w", ErrCorruptArchive, err)
		}
		// Match by exact entry name only; never join h.Name onto a path, so a
		// hostile archive cannot traverse out of the destination.
		switch h.Name {
		case manifestName:
			b, err := io.ReadAll(io.LimitReader(tr, maxArchiveBytes))
			if err != nil {
				return Manifest{}, fmt.Errorf("read manifest: %w", err)
			}
			var m Manifest
			if err := json.Unmarshal(b, &m); err != nil {
				return Manifest{}, fmt.Errorf("%w: bad manifest: %w", ErrCorruptArchive, err)
			}
			manifest = &m
		case dbEntryName:
			if dbBytes, err = io.ReadAll(io.LimitReader(tr, maxArchiveBytes)); err != nil {
				return Manifest{}, fmt.Errorf("read db snapshot: %w", err)
			}
		}
	}

	if manifest == nil {
		return Manifest{}, fmt.Errorf("%w: no manifest", ErrCorruptArchive)
	}
	if manifest.FormatVersion != FormatVersion {
		return Manifest{}, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedFormat, manifest.FormatVersion, FormatVersion)
	}
	if dbBytes == nil {
		return Manifest{}, ErrMissingDB
	}

	// O_EXCL: never clobber an existing database. The caller is responsible for
	// moving any prior DB aside (and removing -wal/-shm) before calling Restore.
	f, err := os.OpenFile(destDBPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- destDBPath is the operator-configured db_path, the documented restore target
	if err != nil {
		return Manifest{}, fmt.Errorf("open destination: %w", err)
	}
	if _, err := f.Write(dbBytes); err != nil {
		_ = f.Close()
		return Manifest{}, fmt.Errorf("write database: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return Manifest{}, fmt.Errorf("sync database: %w", err)
	}
	if err := f.Close(); err != nil {
		return Manifest{}, fmt.Errorf("close database: %w", err)
	}
	return *manifest, nil
}

func writeTarEntry(tw *tar.Writer, name string, data []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(data)),
		ModTime:  mod,
		Typeflag: tar.TypeReg,
	}); err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("tar write %s: %w", name, err)
	}
	return nil
}

// encrypt seals plaintext under a scrypt-derived key and writes
// magic | salt | nonce | ciphertext to w.
func encrypt(w io.Writer, plaintext []byte, passphrase string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(encMagic))
	for _, chunk := range [][]byte{[]byte(encMagic), salt, nonce, ciphertext} {
		if _, err := w.Write(chunk); err != nil {
			return fmt.Errorf("write encrypted archive: %w", err)
		}
	}
	return nil
}

// decrypt reverses encrypt. A GCM auth failure (wrong passphrase or tampering)
// surfaces as ErrDecryptFailed.
func decrypt(raw []byte, passphrase string) ([]byte, error) {
	body := raw[len(encMagic):]
	if len(body) < saltLen {
		return nil, ErrCorruptArchive
	}
	salt, body := body[:saltLen], body[saltLen:]
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(body) < ns {
		return nil, ErrCorruptArchive
	}
	nonce, ciphertext := body[:ns], body[ns:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(encMagic))
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

func newGCM(passphrase string, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return gcm, nil
}
