package relay

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	metaHistory           = "history"
	metaHistoryOrigin     = "history_origin"
	metaAncestorsRecorded = "ancestors_recorded"
)

func startHistoryTx(tx *sql.Tx, origin string) error {
	id, err := protocol.NewID()
	if err != nil {
		return err
	}
	for key, value := range map[string]string{metaHistory: id.String(), metaHistoryOrigin: origin} {
		if _, err := tx.Exec(
			`INSERT INTO meta (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureHistory() error {
	var id string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaHistory).Scan(&id)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := startHistoryTx(tx, protocol.HistoryCreated); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) History() (id, origin string, err error) {
	return historyOf(s.db)
}

type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

func historyOf(q queryer) (id, origin string, err error) {
	if err := q.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaHistory).Scan(&id); err != nil {
		return "", "", fmt.Errorf("relay history: %w", err)
	}
	if err := q.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaHistoryOrigin).Scan(&origin); err != nil {
		return "", "", fmt.Errorf("relay history origin: %w", err)
	}
	return id, origin, nil
}

func (s *Store) backfillAncestors() error {
	var done string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaAncestorsRecorded).Scan(&done)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT vault_id, envelope FROM change_log ORDER BY seq`)
	if err != nil {
		return err
	}
	type entry struct {
		vaultID protocol.ID
		env     *protocol.Envelope
	}
	var entries []entry
	for rows.Next() {
		var vaultID protocol.ID
		var doc string
		if err := rows.Scan(&vaultID, &doc); err != nil {
			rows.Close()
			return err
		}
		env, err := decodeEnvelope(doc, 0)
		if err != nil {
			rows.Close()
			return err
		}
		entries = append(entries, entry{vaultID, env})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, e := range entries {
		digest, err := e.env.Digest()
		if err != nil {
			return err
		}
		if err := rememberAncestorsTx(tx, e.vaultID, e.env.Context.RecordID, digest, e.env.Context.ParentDigest); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO meta (key, value) VALUES (?, '1')`, metaAncestorsRecorded); err != nil {
		return err
	}
	return tx.Commit()
}

func rememberAncestorsTx(tx *sql.Tx, vaultID, recordID protocol.ID, digests ...[]byte) error {
	for _, d := range digests {
		if len(d) == 0 {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO record_ancestor (vault_id, record_id, digest) VALUES (?, ?, ?)
			 ON CONFLICT DO NOTHING`, vaultID, recordID, d); err != nil {
			return err
		}
	}
	return nil
}

func isAncestorTx(tx *sql.Tx, vaultID, recordID protocol.ID, digest []byte) (bool, error) {
	var n int
	err := tx.QueryRow(
		`SELECT count(*) FROM record_ancestor WHERE vault_id = ? AND record_id = ? AND digest = ?`,
		vaultID, recordID, digest).Scan(&n)
	return n > 0, err
}

func (s *Store) BootstrapHistory(secret []byte, g *protocol.Genesis, events []protocol.SignedMembershipEvent, seeded bool) error {
	if err := g.Validate(crypto.SuiteID); err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	chain, err := membership.Validate(g, events)
	if err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "membership chain: %v", err)
	}
	if chain.AuthorizedCount() == 0 {
		return protocol.Errorf(protocol.CodeInvalidRequest, "membership chain authorizes no device")
	}
	canonGenesis, err := protocol.Canonical(g)
	if err != nil {
		return err
	}
	digest, err := g.Digest()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(secret)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var stored []byte
	var consumed sql.NullString
	err = tx.QueryRow(`SELECT secret_hash, consumed_at FROM bootstrap WHERE id = 1`).Scan(&stored, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.Errorf(protocol.CodeNotAuthorized, "this relay has no bootstrap secret configured")
	}
	if err != nil {
		return err
	}
	if consumed.Valid {
		return protocol.Errorf(protocol.CodeBootstrapConsumed, "bootstrap was already used")
	}
	if subtle.ConstantTimeCompare(stored, sum[:]) != 1 {
		return protocol.Errorf(protocol.CodeNotAuthorized, "the bootstrap secret does not match")
	}
	origin := protocol.HistoryCreated
	if seeded {
		origin = protocol.HistorySeeded
	}
	if err := createVaultTx(tx, g, string(canonGenesis), digest, chain, origin); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE bootstrap SET consumed_at = ? WHERE id = 1`, g.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

type ImportResult struct {
	History  string
	Outcomes []protocol.ImportOutcome
}

func (s *Store) ImportRecords(vaultID protocol.ID, req *protocol.ImportRequest, now string) (*ImportResult, error) {
	chain, err := s.Chain(vaultID)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var epoch int64
	if err := tx.QueryRow(`SELECT key_epoch FROM vault WHERE vault_id = ?`, vaultID).Scan(&epoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, protocol.Errorf(protocol.CodeNotFound, "no such vault")
		}
		return nil, err
	}
	history, _, err := historyOf(tx)
	if err != nil {
		return nil, err
	}

	result := &ImportResult{}
	seen := map[protocol.ID]bool{}
	imported := 0
	for i := range req.Records {
		item := &req.Records[i]
		env := &item.Envelope
		if seen[env.Context.RecordID] {
			return nil, protocol.Errorf(protocol.CodeInvalidRequest, "record %s appears twice", env.Context.RecordID)
		}
		seen[env.Context.RecordID] = true
		outcome, err := importOne(tx, chain, vaultID, protocol.Counter(epoch), item, now)
		if err != nil {
			return nil, fmt.Errorf("record %s: %w", env.Context.RecordID, err)
		}
		if outcome.Outcome == protocol.ImportImported {
			imported++
		}
		result.Outcomes = append(result.Outcomes, outcome)
	}
	if imported > 0 && req.History == history {
		if err := startHistoryTx(tx, protocol.HistoryRestarted); err != nil {
			return nil, err
		}
	}
	if result.History, _, err = historyOf(tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func importOne(tx *sql.Tx, chain *membership.Chain, vaultID protocol.ID, epoch protocol.Counter, item *protocol.ImportRecord, now string) (protocol.ImportOutcome, error) {
	env := &item.Envelope
	out := protocol.ImportOutcome{RecordID: env.Context.RecordID}
	if env.Seq != 0 {
		return out, protocol.Errorf(protocol.CodeInvalidRequest, "a submitted envelope must not carry a seq")
	}
	if err := env.Validate(); err != nil {
		return out, protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	if env.Context.VaultID != vaultID {
		return out, protocol.Errorf(protocol.CodeIDMismatch, "envelope names another vault")
	}
	if env.Context.KeyEpoch != epoch {
		return out, protocol.Errorf(protocol.CodeEpochMismatch,
			"record is at epoch %s, the vault is at epoch %s", env.Context.KeyEpoch, epoch)
	}
	canon, err := protocol.Canonical(env)
	if err != nil {
		return out, err
	}
	if len(canon) > protocol.MaxObjectBytes {
		return out, protocol.Errorf(protocol.CodeBodyTooLarge,
			"record envelope is %d bytes, the limit is %d", len(canon), protocol.MaxObjectBytes)
	}
	if err := verifyWrittenByMember(chain, env); err != nil {
		return out, err
	}
	digest, err := env.Digest()
	if err != nil {
		return out, err
	}

	head, err := headTx(tx, vaultID, env.Context.RecordID)
	if err != nil {
		return out, err
	}
	if head != nil {
		headDigest, err := head.Digest()
		if err != nil {
			return out, err
		}
		if bytes.Equal(headDigest, digest) {
			out.Outcome, out.Seq = protocol.ImportCurrent, head.Seq
			return out, rememberAncestorsTx(tx, vaultID, env.Context.RecordID, ancestorsOf(item, digest)...)
		}
		if !claimsAncestor(item, headDigest) {
			behind, err := isAncestorTx(tx, vaultID, env.Context.RecordID, digest)
			if err != nil {
				return out, err
			}
			if behind {
				out.Outcome = protocol.ImportBehind
				return out, nil
			}
			out.Outcome, out.Head = protocol.ImportDiverged, head
			return out, nil
		}
	}

	var seq int64
	if err := tx.QueryRow(
		`SELECT coalesce(max(seq), 0) + 1 FROM change_log WHERE vault_id = ?`, vaultID).Scan(&seq); err != nil {
		return out, err
	}
	if _, err := tx.Exec(
		`INSERT INTO change_log (vault_id, seq, record_id, envelope) VALUES (?, ?, ?, ?)`,
		vaultID, seq, env.Context.RecordID, string(canon)); err != nil {
		return out, err
	}
	rev, err := counterToInt(env.Context.Rev, "rev")
	if err != nil {
		return out, err
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
		return out, err
	}
	if err := rememberAncestorsTx(tx, vaultID, env.Context.RecordID, ancestorsOf(item, digest)...); err != nil {
		return out, err
	}
	if _, err := tx.Exec(
		`INSERT INTO mutation (vault_id, mutation_id, request_digest, accepted, code, seq, digest, record_id, created_at)
		 VALUES (?, ?, ?, 1, NULL, ?, ?, ?, ?)
		 ON CONFLICT DO NOTHING`,
		vaultID, env.Context.MutationID, digest, seq, digest, env.Context.RecordID, now); err != nil {
		return out, err
	}
	out.Outcome, out.Seq = protocol.ImportImported, protocol.Counter(seq)
	return out, nil
}

func ancestorsOf(item *protocol.ImportRecord, digest []byte) [][]byte {
	out := [][]byte{digest, item.Envelope.Context.ParentDigest}
	for _, a := range item.Ancestors {
		out = append(out, a)
	}
	return out
}

func claimsAncestor(item *protocol.ImportRecord, digest []byte) bool {
	if bytes.Equal(item.Envelope.Context.ParentDigest, digest) {
		return true
	}
	for _, a := range item.Ancestors {
		if bytes.Equal(a, digest) {
			return true
		}
	}
	return false
}

func verifyWrittenByMember(chain *membership.Chain, env *protocol.Envelope) error {
	d, ok := chain.Device(env.Context.UpdatedBy)
	if !ok {
		return protocol.Errorf(protocol.CodeDeviceUnknown,
			"record names writer %s, which is not in the membership chain", env.Context.UpdatedBy)
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
