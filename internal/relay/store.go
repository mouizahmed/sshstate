package relay

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
)

const SchemaVersion = "1"

const MaxPageBytes = 4 << 20

const schema = `
-- One vault per relay in v1: the server is single-user by design.
CREATE TABLE IF NOT EXISTS vault (
    vault_id   TEXT PRIMARY KEY,
    genesis    TEXT NOT NULL,
    digest     BLOB NOT NULL,
    key_epoch  INTEGER NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- The signed membership chain, stored whole and in order. The relay derives its
-- own view of who may write from this; it is never the other way round.
CREATE TABLE IF NOT EXISTS membership (
    vault_id  TEXT NOT NULL,
    chain_seq INTEGER NOT NULL,
    event     TEXT NOT NULL,
    digest    BLOB NOT NULL,
    PRIMARY KEY (vault_id, chain_seq)
) STRICT;

-- Current record heads. The envelope is stored exactly as signed, so a reader
-- re-verifies the bytes the writer signed rather than a reconstruction.
CREATE TABLE IF NOT EXISTS record_head (
    vault_id  TEXT NOT NULL,
    record_id TEXT NOT NULL,
    rev       INTEGER NOT NULL,
    digest    BLOB NOT NULL,
    seq       INTEGER NOT NULL,
    deleted   INTEGER NOT NULL,
    envelope  TEXT NOT NULL,
    PRIMARY KEY (vault_id, record_id)
) STRICT;

CREATE TABLE IF NOT EXISTS record_ancestor (
    vault_id  TEXT NOT NULL,
    record_id TEXT NOT NULL,
    digest    BLOB NOT NULL,
    PRIMARY KEY (vault_id, record_id, digest)
) STRICT;

-- The immutable accepted-change log. No garbage collection in v1: a
-- client that has been away must be able to replay what it missed.
CREATE TABLE IF NOT EXISTS change_log (
    vault_id  TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    record_id TEXT NOT NULL,
    envelope  TEXT NOT NULL,
    PRIMARY KEY (vault_id, seq)
) STRICT;

-- Sealed key bundles, addressed to one device or to the recovery recipient.
-- Ciphertext only: the relay cannot open these and never holds a vault key.
CREATE TABLE IF NOT EXISTS key_envelope (
    vault_id            TEXT NOT NULL,
    envelope_id         TEXT NOT NULL,
    recipient_device_id TEXT,
    purpose             TEXT NOT NULL,
    key_epoch           INTEGER NOT NULL,
    ciphertext          BLOB NOT NULL,
    created_at          TEXT NOT NULL,
    PRIMARY KEY (vault_id, envelope_id)
) STRICT;

CREATE INDEX IF NOT EXISTS key_envelope_by_recipient
    ON key_envelope (vault_id, recipient_device_id);

-- Pairing sessions. The bundle and snapshot are separate columns because a
-- snapshot can be far larger than the 1 MiB bound on a parsed JSON object.
CREATE TABLE IF NOT EXISTS pairing (
    session_id       TEXT PRIMARY KEY,
    vault_id         TEXT NOT NULL,
    joiner_device_id TEXT NOT NULL,
    state            TEXT NOT NULL,
    session          TEXT NOT NULL,
    bundle           BLOB,
    snapshot         BLOB,
    expires_at       INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS pairing_active ON pairing (vault_id, joiner_device_id, state);

-- Recovery admission challenges. Consumed once, whatever the outcome.
CREATE TABLE IF NOT EXISTS recovery_nonce (
    vault_id   TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, nonce)
) STRICT;

-- Durable mutation outcomes. Rejections are stored too: a retried
-- candidate must get the same answer, not a fresh evaluation against a head
-- that has since moved.
-- The one-time bootstrap secret, by hash only. The plaintext is generated at
-- startup or supplied in a file, and is never written here.
CREATE TABLE IF NOT EXISTS bootstrap (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    secret_hash BLOB NOT NULL,
    consumed_at TEXT
) STRICT;

-- Accepted request nonces, kept until expiry plus tolerance.
CREATE TABLE IF NOT EXISTS request_nonce (
    device_id  TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, nonce)
) STRICT;

CREATE INDEX IF NOT EXISTS request_nonce_expiry ON request_nonce (expires_at);

CREATE TABLE IF NOT EXISTS mutation (
    vault_id       TEXT NOT NULL,
    mutation_id    TEXT NOT NULL,
    request_digest BLOB NOT NULL,
    accepted       INTEGER NOT NULL,
    code           TEXT,
    seq            INTEGER,
    digest         BLOB,
    record_id      TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    PRIMARY KEY (vault_id, mutation_id)
) STRICT;
`

type Store struct {
	db   *sql.DB
	path string
	Now  func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("create relay directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return nil, fmt.Errorf("create relay database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("create relay database: %w", err)
	}
	if err := os.Chmod(path, filePerm); err != nil {
		return nil, fmt.Errorf("secure relay database: %w", err)
	}

	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open relay database: %w", err)
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
	if err := s.ensureHistory(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.backfillAncestors(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Path() string { return s.path }

func (s *Store) checkSchemaVersion() error {
	var got string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&got)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.Exec(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)`, SchemaVersion)
		return err
	case err != nil:
		return err
	case got != SchemaVersion:
		return fmt.Errorf("relay database is schema version %s, this build implements %s", got, SchemaVersion)
	}
	return nil
}

func counterToInt(c protocol.Counter, field string) (int64, error) {
	if uint64(c) > math.MaxInt64 {
		return 0, protocol.Errorf(protocol.CodeInvalidRequest, "%s is too large to store", field)
	}
	return int64(c), nil
}

func (s *Store) CreateVault(g *protocol.Genesis, root protocol.SignedMembershipEvent) error {
	if err := g.Validate(crypto.SuiteID); err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	chain, err := membership.Validate(g, []protocol.SignedMembershipEvent{root})
	if err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "membership root: %v", err)
	}
	canonGenesis, err := protocol.Canonical(g)
	if err != nil {
		return err
	}
	digest, err := g.Digest()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := createVaultTx(tx, g, string(canonGenesis), digest, chain, protocol.HistoryCreated); err != nil {
		return err
	}
	return tx.Commit()
}

func createVaultTx(tx *sql.Tx, g *protocol.Genesis, canonGenesis string, digest []byte, chain *membership.Chain, origin string) error {
	var existing int
	if err := tx.QueryRow(`SELECT count(*) FROM vault`).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return protocol.Errorf(protocol.CodeBootstrapConsumed, "this relay already holds a vault")
	}
	if _, err := tx.Exec(
		`INSERT INTO vault (vault_id, genesis, digest, key_epoch, created_at) VALUES (?, ?, ?, 1, ?)`,
		g.VaultID, canonGenesis, digest, g.CreatedAt); err != nil {
		return err
	}
	events := chain.Events()
	for i, ev := range events {
		prefix, err := membership.Validate(g, events[:i+1])
		if err != nil {
			return err
		}
		canon, err := protocol.Canonical(&ev)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO membership (vault_id, chain_seq, event, digest) VALUES (?, ?, ?, ?)`,
			g.VaultID, i+1, string(canon), prefix.HeadDigest()); err != nil {
			return err
		}
	}
	return startHistoryTx(tx, origin)
}

func (s *Store) Genesis(vaultID protocol.ID) (*protocol.Genesis, error) {
	var doc string
	err := s.db.QueryRow(`SELECT genesis FROM vault WHERE vault_id = ?`, vaultID).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, protocol.Errorf(protocol.CodeNotFound, "no such vault")
	}
	if err != nil {
		return nil, err
	}
	var g protocol.Genesis
	if err := protocol.StrictUnmarshal([]byte(doc), &g); err != nil {
		return nil, fmt.Errorf("stored genesis: %w", err)
	}
	return &g, nil
}

func (s *Store) Epoch(vaultID protocol.ID) (protocol.Counter, error) {
	var epoch int64
	err := s.db.QueryRow(`SELECT key_epoch FROM vault WHERE vault_id = ?`, vaultID).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, protocol.Errorf(protocol.CodeNotFound, "no such vault")
	}
	if err != nil {
		return 0, err
	}
	return protocol.Counter(epoch), nil
}

func (s *Store) VaultID() (protocol.ID, error) {
	var id protocol.ID
	err := s.db.QueryRow(`SELECT vault_id FROM vault`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", protocol.Errorf(protocol.CodeNotFound, "this relay holds no vault")
	}
	return id, err
}

func (s *Store) Membership(vaultID protocol.ID) ([]protocol.SignedMembershipEvent, error) {
	rows, err := s.db.Query(
		`SELECT event FROM membership WHERE vault_id = ? ORDER BY chain_seq`, vaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.SignedMembershipEvent
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var ev protocol.SignedMembershipEvent
		if err := protocol.StrictUnmarshal([]byte(doc), &ev); err != nil {
			return nil, fmt.Errorf("stored membership event: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *Store) Chain(vaultID protocol.ID) (*membership.Chain, error) {
	g, err := s.Genesis(vaultID)
	if err != nil {
		return nil, err
	}
	events, err := s.Membership(vaultID)
	if err != nil {
		return nil, err
	}
	chain, err := membership.Validate(g, events)
	if err != nil {
		return nil, fmt.Errorf("stored membership chain: %w", err)
	}
	return chain, nil
}

func (s *Store) AppendMembership(vaultID protocol.ID, ev protocol.SignedMembershipEvent) (*membership.Chain, error) {
	chain, err := s.Chain(vaultID)
	if err != nil {
		return nil, err
	}
	next, err := chain.Append(ev)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeChainMismatch, "%v", err).
			WithDetail("head_chain_seq", protocol.Counter(chain.Len()).String())
	}
	canon, err := protocol.Canonical(&ev)
	if err != nil {
		return nil, err
	}
	seq, err := counterToInt(ev.Event.ChainSeq, "chain_seq")
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO membership (vault_id, chain_seq, event, digest) VALUES (?, ?, ?, ?)`,
		vaultID, seq, string(canon), next.HeadDigest()); err != nil {
		return nil, protocol.Errorf(protocol.CodeChainMismatch, "another event was appended first")
	}
	return next, nil
}

func (s *Store) ResolveVerifyKey(vaultID, deviceID protocol.ID) (*crypto.VerifyKey, error) {
	chain, err := s.Chain(vaultID)
	if err != nil {
		return nil, err
	}
	d, ok := chain.Device(deviceID)
	if !ok {
		return nil, protocol.Errorf(protocol.CodeDeviceUnknown, "device %s is not in the membership chain", deviceID)
	}
	if d.Revoked {
		return nil, protocol.Errorf(protocol.CodeDeviceRevoked, "device %s was revoked", deviceID)
	}
	return d.VerifyKey, nil
}

type PutOutcome struct {
	Accepted bool
	Seq      protocol.Counter
	Digest   []byte
	Code     string
	Head     *protocol.Envelope
	Replayed bool
}

func (s *Store) PutRecord(vaultID protocol.ID, env *protocol.Envelope, now string) (*PutOutcome, error) {
	if err := env.Validate(); err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	if env.Context.VaultID != vaultID {
		return nil, protocol.Errorf(protocol.CodeIDMismatch, "envelope names another vault")
	}
	canon, err := protocol.Canonical(env)
	if err != nil {
		return nil, err
	}
	if len(canon) > protocol.MaxObjectBytes {
		return nil, protocol.Errorf(protocol.CodeBodyTooLarge,
			"record envelope is %d bytes, the limit is %d", len(canon), protocol.MaxObjectBytes)
	}
	digest, err := env.Digest()
	if err != nil {
		return nil, err
	}
	requestDigest := digest
	if err := s.verifyRecordSignature(vaultID, env); err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if out, found, err := replayOutcome(tx, vaultID, env, requestDigest); err != nil {
		return nil, err
	} else if found {
		if out.Head == nil && !out.Accepted {
			head, err := headTx(tx, vaultID, env.Context.RecordID)
			if err != nil {
				return nil, err
			}
			out.Head = head
		}
		return out, tx.Commit()
	}

	var epoch int64
	if err := tx.QueryRow(`SELECT key_epoch FROM vault WHERE vault_id = ?`, vaultID).Scan(&epoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, protocol.Errorf(protocol.CodeNotFound, "no such vault")
		}
		return nil, err
	}
	if env.Context.KeyEpoch != protocol.Counter(epoch) {
		return nil, protocol.Errorf(protocol.CodeEpochMismatch,
			"record is at epoch %s, the vault is at epoch %d", env.Context.KeyEpoch, epoch).
			WithDetail("current_epoch", protocol.Counter(epoch).String())
	}

	head, err := headTx(tx, vaultID, env.Context.RecordID)
	if err != nil {
		return nil, err
	}
	if reason := parentMismatch(env, head); reason != "" {
		out := &PutOutcome{Accepted: false, Code: protocol.CodeParentMismatch, Head: head}
		if err := recordOutcome(tx, vaultID, env, requestDigest, out, now); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return out, nil
	}

	var seq int64
	if err := tx.QueryRow(
		`SELECT coalesce(max(seq), 0) + 1 FROM change_log WHERE vault_id = ?`, vaultID).Scan(&seq); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(
		`INSERT INTO change_log (vault_id, seq, record_id, envelope) VALUES (?, ?, ?, ?)`,
		vaultID, seq, env.Context.RecordID, string(canon)); err != nil {
		return nil, err
	}
	rev, err := counterToInt(env.Context.Rev, "rev")
	if err != nil {
		return nil, err
	}
	deleted := 0
	if env.Context.Deleted {
		deleted = 1
	}
	if _, err := tx.Exec(
		`INSERT INTO record_head (vault_id, record_id, rev, digest, seq, deleted, envelope)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, record_id) DO UPDATE SET
		   rev = excluded.rev, digest = excluded.digest, seq = excluded.seq,
		   deleted = excluded.deleted, envelope = excluded.envelope`,
		vaultID, env.Context.RecordID, rev, digest, seq, deleted, string(canon)); err != nil {
		return nil, err
	}
	if err := rememberAncestorsTx(tx, vaultID, env.Context.RecordID, digest, env.Context.ParentDigest); err != nil {
		return nil, err
	}
	out := &PutOutcome{Accepted: true, Seq: protocol.Counter(seq), Digest: digest}
	if err := recordOutcome(tx, vaultID, env, requestDigest, out, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) verifyRecordSignature(vaultID protocol.ID, env *protocol.Envelope) error {
	chain, err := s.Chain(vaultID)
	if err != nil {
		return err
	}
	d, ok := chain.Device(env.Context.UpdatedBy)
	if !ok {
		return protocol.Errorf(protocol.CodeDeviceUnknown,
			"record names writer %s, which is not in the membership chain", env.Context.UpdatedBy)
	}
	if d.Revoked {
		return protocol.Errorf(protocol.CodeDeviceRevoked,
			"record names writer %s, which was revoked", env.Context.UpdatedBy)
	}
	msg, err := env.SigningInput()
	if err != nil {
		return err
	}
	if err := crypto.Verify(d.VerifyKey, protocol.RecordSignatureDomain, msg, env.Signature); err != nil {
		return protocol.Errorf(protocol.CodeSignatureInvalid, "record signature does not verify")
	}
	return nil
}

func parentMismatch(env *protocol.Envelope, head *protocol.Envelope) string {
	if head == nil {
		if env.Context.Rev != 1 {
			return "no such record"
		}
		return ""
	}
	if env.Context.Rev != head.Context.Rev+1 {
		return "rev is not one past the head"
	}
	headDigest, err := head.Digest()
	if err != nil {
		return "head is unreadable"
	}
	if !bytes.Equal(env.Context.ParentDigest, headDigest) {
		return "parent_digest is not the head's digest"
	}
	return ""
}

func replayOutcome(tx *sql.Tx, vaultID protocol.ID, env *protocol.Envelope, requestDigest []byte) (*PutOutcome, bool, error) {
	var (
		stored   []byte
		accepted int
		code     sql.NullString
		seq      sql.NullInt64
		digest   []byte
	)
	err := tx.QueryRow(
		`SELECT request_digest, accepted, code, seq, digest FROM mutation WHERE vault_id = ? AND mutation_id = ?`,
		vaultID, env.Context.MutationID).Scan(&stored, &accepted, &code, &seq, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(stored, requestDigest) {
		return nil, false, protocol.Errorf(protocol.CodeIdempotencyMismat,
			"mutation %s was already used for different content", env.Context.MutationID)
	}
	out := &PutOutcome{Accepted: accepted == 1, Digest: digest, Replayed: true}
	if code.Valid {
		out.Code = code.String
	}
	if seq.Valid {
		out.Seq = protocol.Counter(seq.Int64)
	}
	return out, true, nil
}

func recordOutcome(tx *sql.Tx, vaultID protocol.ID, env *protocol.Envelope, requestDigest []byte, out *PutOutcome, now string) error {
	accepted := 0
	if out.Accepted {
		accepted = 1
	}
	var code any
	if out.Code != "" {
		code = out.Code
	}
	var seq any
	if out.Accepted {
		v, err := counterToInt(out.Seq, "seq")
		if err != nil {
			return err
		}
		seq = v
	}
	_, err := tx.Exec(
		`INSERT INTO mutation (vault_id, mutation_id, request_digest, accepted, code, seq, digest, record_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vaultID, env.Context.MutationID, requestDigest, accepted, code, seq, out.Digest, env.Context.RecordID, now)
	return err
}

func headTx(tx *sql.Tx, vaultID, recordID protocol.ID) (*protocol.Envelope, error) {
	var doc string
	var seq int64
	err := tx.QueryRow(
		`SELECT envelope, seq FROM record_head WHERE vault_id = ? AND record_id = ?`,
		vaultID, recordID).Scan(&doc, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeEnvelope(doc, seq)
}

func (s *Store) Head(vaultID, recordID protocol.ID) (*protocol.Envelope, error) {
	var doc string
	var seq int64
	err := s.db.QueryRow(
		`SELECT envelope, seq FROM record_head WHERE vault_id = ? AND record_id = ?`,
		vaultID, recordID).Scan(&doc, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeEnvelope(doc, seq)
}

func decodeEnvelope(doc string, seq int64) (*protocol.Envelope, error) {
	var env protocol.Envelope
	if err := protocol.StrictUnmarshal([]byte(doc), &env); err != nil {
		return nil, fmt.Errorf("stored envelope: %w", err)
	}
	env.Seq = protocol.Counter(seq)
	return &env, nil
}

func (s *Store) CurrentSeq(vaultID protocol.ID) (protocol.Counter, error) {
	var seq int64
	if err := s.db.QueryRow(
		`SELECT coalesce(max(seq), 0) FROM change_log WHERE vault_id = ?`, vaultID).Scan(&seq); err != nil {
		return 0, err
	}
	return protocol.Counter(seq), nil
}

type Page struct {
	Changes        []*protocol.Envelope
	NextCursor     protocol.Counter
	SnapshotCursor protocol.Counter
	HasMore        bool
}

func (s *Store) Changes(vaultID protocol.ID, since, through protocol.Counter, limit int) (*Page, error) {
	current, err := s.CurrentSeq(vaultID)
	if err != nil {
		return nil, err
	}
	if through == 0 {
		through = current
	}
	if through > current {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest,
			"through=%s is past the current head %s", through, current)
	}
	if since > through {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest,
			"since=%s is past through=%s", since, through)
	}
	if limit <= 0 || limit > MaxPageLimit {
		limit = DefaultPageLimit
	}

	sinceInt, err := counterToInt(since, "since")
	if err != nil {
		return nil, err
	}
	throughInt, err := counterToInt(through, "through")
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(
		`SELECT seq, envelope FROM change_log
		 WHERE vault_id = ? AND seq > ? AND seq <= ?
		 ORDER BY seq LIMIT ?`,
		vaultID, sinceInt, throughInt, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	page := &Page{NextCursor: since, SnapshotCursor: through}
	bytesSoFar := 0
	for rows.Next() {
		var seq int64
		var doc string
		if err := rows.Scan(&seq, &doc); err != nil {
			return nil, err
		}
		if len(page.Changes) == limit {
			page.HasMore = true
			break
		}
		if bytesSoFar+len(doc) > MaxPageBytes && len(page.Changes) > 0 {
			page.HasMore = true
			break
		}
		env, err := decodeEnvelope(doc, seq)
		if err != nil {
			return nil, err
		}
		bytesSoFar += len(doc)
		page.Changes = append(page.Changes, env)
		page.NextCursor = protocol.Counter(seq)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return page, nil
}

const (
	DefaultPageLimit = 200
	MaxPageLimit     = 500
)
