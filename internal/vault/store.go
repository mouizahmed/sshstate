package vault

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db   *sql.DB
	path string
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- The immutable vault root. Exactly one row, enforced by the CHECK.
CREATE TABLE IF NOT EXISTS genesis (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    document TEXT NOT NULL,
    digest   BLOB NOT NULL
) STRICT;

-- Password-wrapped local secrets, one per purpose. Ciphertext only.
CREATE TABLE IF NOT EXISTS wrappers (
    purpose TEXT PRIMARY KEY,
    wrapper TEXT NOT NULL
) STRICT;

-- Public membership. Verify keys and recipients are public by construction;
-- this table is what answers "was this writer authorized?" without a relay.
CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    verify_key  BLOB NOT NULL,
    recipient   TEXT NOT NULL,
    status      TEXT NOT NULL,
    enrolled_at TEXT NOT NULL
) STRICT;

-- Current record heads. The envelope is stored whole, exactly as signed, so a
-- read re-verifies the same bytes a writer signed rather than a reconstruction.
-- The signed membership chain, stored whole. The devices table above is the
-- derived view; this is the evidence, and it is what a revocation extends and
-- an export carries.
CREATE TABLE IF NOT EXISTS membership (
    chain_seq INTEGER PRIMARY KEY,
    event     TEXT NOT NULL,
    digest    BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS records (
    record_id   TEXT PRIMARY KEY,
    record_type TEXT NOT NULL,
    rev         INTEGER NOT NULL,
    digest      BLOB NOT NULL,
    deleted     INTEGER NOT NULL,
    envelope    TEXT NOT NULL,
    seq         INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS records_by_type ON records (record_type);

CREATE TABLE IF NOT EXISTS record_history (
    record_id TEXT NOT NULL,
    digest    BLOB NOT NULL,
    PRIMARY KEY (record_id, digest)
) STRICT;

-- Outbound candidates persisted before transmission, so a retry can
-- reuse the exact signed bytes instead of producing a second mutation.
CREATE TABLE IF NOT EXISTS outbox (
    mutation_id TEXT PRIMARY KEY,
    record_id   TEXT NOT NULL,
    envelope    TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS cursors (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
`

const (
	MetaVaultID     = "vault_id"
	MetaDeviceID    = "device_id"
	MetaKeyEpoch    = "key_epoch"
	MetaSchemaVer   = "schema_version"
	MetaDeviceLabel = "device_label"
)

const SchemaVersion = "1"

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return nil, fmt.Errorf("create vault database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("create vault database: %w", err)
	}
	if err := os.Chmod(path, filePerm); err != nil {
		return nil, fmt.Errorf("secure vault database: %w", err)
	}

	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open vault database: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db, path: path}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := s.checkSchemaVersion(); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO record_history (record_id, digest) SELECT record_id, digest FROM records`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record revision history: %w", err)
	}
	return s, nil
}

func (s *Store) checkSchemaVersion() error {
	got, err := s.Meta(MetaSchemaVer)
	switch {
	case errors.Is(err, ErrNotFound):
		return s.SetMeta(MetaSchemaVer, SchemaVersion)
	case err != nil:
		return err
	case got != SchemaVersion:
		return fmt.Errorf("vault database is schema version %s, this client implements %s", got, SchemaVersion)
	}
	return nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Meta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("meta %q: %w", key, ErrNotFound)
	}
	return v, err
}

func (s *Store) SetMeta(key, value string) error {
	return setMeta(s.db, key, value)
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func setMeta(db execer, key, value string) error {
	_, err := db.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) Initialized() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM genesis`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) PutGenesis(g *protocol.Genesis) error {
	return putGenesis(s.db, g)
}

func putGenesis(db execer, g *protocol.Genesis) error {
	doc, err := protocol.Canonical(g)
	if err != nil {
		return fmt.Errorf("canonical genesis: %w", err)
	}
	digest, err := g.Digest()
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO genesis (id, document, digest) VALUES (1, ?, ?)`, string(doc), digest)
	if err != nil {
		return fmt.Errorf("store genesis (a vault already exists here): %w", err)
	}
	return nil
}

func (s *Store) Genesis() (*protocol.Genesis, []byte, error) {
	var doc string
	var digest []byte
	err := s.db.QueryRow(`SELECT document, digest FROM genesis WHERE id = 1`).Scan(&doc, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("genesis: %w", ErrNotFound)
	}
	if err != nil {
		return nil, nil, err
	}
	var g protocol.Genesis
	if err := protocol.StrictUnmarshal([]byte(doc), &g); err != nil {
		return nil, nil, fmt.Errorf("stored genesis is malformed: %w", err)
	}
	recomputed, err := g.Digest()
	if err != nil {
		return nil, nil, err
	}
	if hex.EncodeToString(recomputed) != hex.EncodeToString(digest) {
		return nil, nil, errors.New("stored genesis does not match its recorded digest")
	}
	return &g, digest, nil
}

func (s *Store) PutWrapper(purpose string, w *crypto.Wrapper) error {
	return putWrapper(s.db, purpose, w)
}

func putWrapper(db execer, purpose string, w *crypto.Wrapper) error {
	body, err := json.Marshal(w)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO wrappers (purpose, wrapper) VALUES (?, ?)
		 ON CONFLICT(purpose) DO UPDATE SET wrapper = excluded.wrapper`, purpose, string(body))
	return err
}

func (s *Store) PutWrappers(wrappers map[string]*crypto.Wrapper) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for purpose, w := range wrappers {
		if err := putWrapper(tx, purpose, w); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Wrapper(purpose string) (*crypto.Wrapper, error) {
	var body string
	err := s.db.QueryRow(`SELECT wrapper FROM wrappers WHERE purpose = ?`, purpose).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("wrapper %q: %w", purpose, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	var w crypto.Wrapper
	if err := protocol.StrictUnmarshal([]byte(body), &w); err != nil {
		return nil, fmt.Errorf("stored wrapper %q is malformed: %w", purpose, err)
	}
	return &w, nil
}

func (s *Store) Wrappers() (map[string]*crypto.Wrapper, error) {
	rows, err := s.db.Query(`SELECT purpose, wrapper FROM wrappers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*crypto.Wrapper{}
	for rows.Next() {
		var purpose, body string
		if err := rows.Scan(&purpose, &body); err != nil {
			return nil, err
		}
		var w crypto.Wrapper
		if err := protocol.StrictUnmarshal([]byte(body), &w); err != nil {
			return nil, fmt.Errorf("stored wrapper %q is malformed: %w", purpose, err)
		}
		out[purpose] = &w
	}
	return out, rows.Err()
}

type DeviceStatus string

const (
	DeviceActive  DeviceStatus = "active"
	DeviceRevoked DeviceStatus = "revoked"
)

type Device struct {
	ID         protocol.ID
	VerifyKey  []byte
	Recipient  string
	Status     DeviceStatus
	EnrolledAt string
}

func (s *Store) PutDevice(d Device) error {
	return putDevice(s.db, d)
}

func putDevice(db execer, d Device) error {
	_, err := db.Exec(
		`INSERT INTO devices (device_id, verify_key, recipient, status, enrolled_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(device_id) DO UPDATE SET
		   verify_key = excluded.verify_key,
		   recipient  = excluded.recipient,
		   status     = excluded.status`,
		string(d.ID), d.VerifyKey, d.Recipient, string(d.Status), d.EnrolledAt)
	return err
}

func (s *Store) Device(id protocol.ID) (Device, error) {
	var d Device
	var idStr, status string
	err := s.db.QueryRow(
		`SELECT device_id, verify_key, recipient, status, enrolled_at FROM devices WHERE device_id = ?`,
		string(id)).Scan(&idStr, &d.VerifyKey, &d.Recipient, &status, &d.EnrolledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, fmt.Errorf("device %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Device{}, err
	}
	d.ID = protocol.ID(idStr)
	d.Status = DeviceStatus(status)
	return d, nil
}

func (s *Store) Devices() ([]Device, error) {
	rows, err := s.db.Query(
		`SELECT device_id, verify_key, recipient, status, enrolled_at FROM devices ORDER BY enrolled_at, device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var idStr, status string
		if err := rows.Scan(&idStr, &d.VerifyKey, &d.Recipient, &status, &d.EnrolledAt); err != nil {
			return nil, err
		}
		d.ID = protocol.ID(idStr)
		d.Status = DeviceStatus(status)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) MembershipEvents() ([]protocol.SignedMembershipEvent, error) {
	rows, err := s.db.Query(`SELECT event FROM membership ORDER BY chain_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.SignedMembershipEvent
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var ev protocol.SignedMembershipEvent
		if err := protocol.StrictUnmarshal([]byte(body), &ev); err != nil {
			return nil, fmt.Errorf("stored membership event: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *Store) PutMembershipEvents(events []protocol.SignedMembershipEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := putMembershipEvents(tx, events); err != nil {
		return err
	}
	return tx.Commit()
}

func putMembershipEvents(tx execer, events []protocol.SignedMembershipEvent) error {
	if _, err := tx.Exec(`DELETE FROM membership`); err != nil {
		return err
	}
	for i := range events {
		body, err := protocol.Canonical(&events[i])
		if err != nil {
			return err
		}
		digest, err := events[i].Digest()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO membership (chain_seq, event, digest) VALUES (?, ?, ?)`,
			int64(events[i].Event.ChainSeq), string(body), digest); err != nil {
			return err
		}
	}
	return nil
}
