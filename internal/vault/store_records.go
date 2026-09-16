// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

var ErrParentMismatch = errors.New("parent revision or digest does not match the stored head")

func (s *Store) PutRecord(env *protocol.Envelope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := putRecordTx(tx, env); err != nil {
		return err
	}
	return tx.Commit()
}

func putRecordTx(tx *sql.Tx, env *protocol.Envelope) error {
	if err := env.Validate(); err != nil {
		return fmt.Errorf("put record: %w", err)
	}
	digest, err := env.Digest()
	if err != nil {
		return err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}

	var haveRev int64
	var haveDigest []byte
	err = tx.QueryRow(`SELECT rev, digest FROM records WHERE record_id = ?`,
		string(env.Context.RecordID)).Scan(&haveRev, &haveDigest)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if env.Context.Rev != 1 {
			return fmt.Errorf("put record %s at rev %s: no stored head to build on: %w",
				env.Context.RecordID, env.Context.Rev, ErrParentMismatch)
		}
	case err != nil:
		return err
	default:
		if int64(env.Context.Rev) == haveRev && bytes.Equal(digest, haveDigest) {
			return nil
		}
		if int64(env.Context.Rev) != haveRev+1 {
			return fmt.Errorf("put record %s: stored head is rev %d, write is rev %s: %w",
				env.Context.RecordID, haveRev, env.Context.Rev, ErrParentMismatch)
		}
		if !bytes.Equal(env.Context.ParentDigest, haveDigest) {
			return fmt.Errorf("put record %s at rev %s: parent digest names a different revision: %w",
				env.Context.RecordID, env.Context.Rev, ErrParentMismatch)
		}
	}

	deleted := 0
	if env.Context.Deleted {
		deleted = 1
	}
	var seq any
	if env.Seq != 0 {
		seq = int64(env.Seq)
	}
	_, err = tx.Exec(
		`INSERT INTO records (record_id, record_type, rev, digest, deleted, envelope, seq)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(record_id) DO UPDATE SET
		   record_type = excluded.record_type,
		   rev         = excluded.rev,
		   digest      = excluded.digest,
		   deleted     = excluded.deleted,
		   envelope    = excluded.envelope,
		   seq         = excluded.seq`,
		string(env.Context.RecordID), string(env.Context.RecordType),
		int64(env.Context.Rev), digest, deleted, string(body), seq)
	return err
}

func (s *Store) Head(id protocol.ID) (*protocol.Envelope, []byte, error) {
	var body string
	var digest []byte
	err := s.db.QueryRow(`SELECT envelope, digest FROM records WHERE record_id = ?`, string(id)).
		Scan(&body, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("record %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, nil, err
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		return nil, nil, err
	}
	return env, digest, nil
}

func (s *Store) LiveRecords(t protocol.RecordType) ([]*protocol.Envelope, error) {
	return s.records(`SELECT envelope FROM records WHERE record_type = ? AND deleted = 0 ORDER BY record_id`, t)
}

func (s *Store) AllRecords(t protocol.RecordType) ([]*protocol.Envelope, error) {
	return s.records(`SELECT envelope FROM records WHERE record_type = ? ORDER BY record_id`, t)
}

func (s *Store) records(query string, t protocol.RecordType) ([]*protocol.Envelope, error) {
	rows, err := s.db.Query(query, string(t))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*protocol.Envelope
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		env, err := decodeEnvelope(body)
		if err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	return out, rows.Err()
}

func decodeEnvelope(body string) (*protocol.Envelope, error) {
	var env protocol.Envelope
	if err := protocol.StrictUnmarshal([]byte(body), &env); err != nil {
		return nil, fmt.Errorf("stored envelope is malformed: %w", err)
	}
	return &env, nil
}

func (s *Store) EnqueueOutbox(env *protocol.Envelope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := enqueueOutboxTx(tx, env); err != nil {
		return err
	}
	return tx.Commit()
}

func enqueueOutboxTx(tx *sql.Tx, env *protocol.Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		`INSERT INTO outbox (mutation_id, record_id, envelope, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(mutation_id) DO NOTHING`,
		string(env.Context.MutationID), string(env.Context.RecordID),
		string(body), time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) Outbox() ([]*protocol.Envelope, error) {
	rows, err := s.db.Query(`SELECT envelope FROM outbox`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*protocol.Envelope
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		env, err := decodeEnvelope(body)
		if err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Context.RecordID != out[j].Context.RecordID {
			return out[i].Context.RecordID < out[j].Context.RecordID
		}
		return out[i].Context.Rev < out[j].Context.Rev
	})
	return out, nil
}

func (s *Store) DequeueOutbox(mutationID protocol.ID) error {
	_, err := s.db.Exec(`DELETE FROM outbox WHERE mutation_id = ?`, string(mutationID))
	return err
}

func (s *Store) ApplyLocal(env *protocol.Envelope) error {
	return s.ApplyLocalBatch(env)
}

func (s *Store) ApplyLocalBatch(envs ...*protocol.Envelope) error {
	if len(envs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, env := range envs {
		if err := enqueueOutboxTx(tx, env); err != nil {
			return fmt.Errorf("persist outbound candidate: %w", err)
		}
		if err := putRecordTx(tx, env); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetCursor(name, value string) error {
	return setCursor(s.db, name, value)
}

func setCursor(db execer, name, value string) error {
	_, err := db.Exec(
		`INSERT INTO cursors (name, value) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET value = excluded.value`, name, value)
	return err
}

func (s *Store) Cursor(name string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM cursors WHERE name = ?`, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("cursor %q: %w", name, ErrNotFound)
	}
	return v, err
}

const (
	CursorRecords         = "records"
	CursorRevokedAtPrefix = "revoked-at:"
)

func (s *Store) ApplyRemoteBatch(cursor string, envs []*protocol.Envelope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, env := range envs {
		if err := putRecordTx(tx, env); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO cursors (name, value) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET value = excluded.value`,
		CursorRecords, cursor); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ResolveConflict(candidate protocol.ID, conflict, head *protocol.Envelope) error {
	if conflict == nil || head == nil {
		return errors.New("resolve conflict: both the preserved copy and the incoming head are required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := enqueueOutboxTx(tx, conflict); err != nil {
		return fmt.Errorf("persist the preserved candidate: %w", err)
	}
	if err := putRecordTx(tx, conflict); err != nil {
		return err
	}
	if err := replaceHeadTx(tx, head); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM outbox WHERE mutation_id = ?`, string(candidate)); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceHeadTx(tx *sql.Tx, env *protocol.Envelope) error {
	if err := env.Validate(); err != nil {
		return fmt.Errorf("replace head: %w", err)
	}
	digest, err := env.Digest()
	if err != nil {
		return err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	deleted := 0
	if env.Context.Deleted {
		deleted = 1
	}
	var seq any
	if env.Seq != 0 {
		seq = int64(env.Seq)
	}
	_, err = tx.Exec(
		`INSERT INTO records (record_id, record_type, rev, digest, deleted, envelope, seq)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(record_id) DO UPDATE SET
		   record_type = excluded.record_type,
		   rev         = excluded.rev,
		   digest      = excluded.digest,
		   deleted     = excluded.deleted,
		   envelope    = excluded.envelope,
		   seq         = excluded.seq`,
		string(env.Context.RecordID), string(env.Context.RecordType),
		int64(env.Context.Rev), digest, deleted, string(body), seq)
	return err
}

func (s *Store) AcceptOutbox(env *protocol.Envelope, seq protocol.Counter) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stamped := *env
	stamped.Seq = seq
	if err := replaceHeadTx(tx, &stamped); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM outbox WHERE mutation_id = ?`,
		string(env.Context.MutationID)); err != nil {
		return err
	}
	return tx.Commit()
}
