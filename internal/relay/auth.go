// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const BootstrapSecretBytes = 32

func ReadBootstrapSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap secret: %w", err)
	}
	secret := []byte(strings.TrimSpace(string(raw)))
	if len(secret) == 0 {
		return nil, errors.New("the bootstrap secret file is empty")
	}
	return secret, nil
}

func (s *Store) SetBootstrapSecret(secret []byte) error {
	if len(secret) == 0 {
		return errors.New("the bootstrap secret is empty")
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
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO bootstrap (id, secret_hash) VALUES (1, ?)`, sum[:]); err != nil {
			return err
		}
		return tx.Commit()
	case err != nil:
		return err
	}
	if subtle.ConstantTimeCompare(stored, sum[:]) == 1 {
		return tx.Commit()
	}
	if consumed.Valid {
		return protocol.Errorf(protocol.CodeBootstrapConsumed,
			"bootstrap was already used; a new secret does not reopen registration")
	}
	if _, err := tx.Exec(`UPDATE bootstrap SET secret_hash = ? WHERE id = 1`, sum[:]); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BootstrapConsumed() (bool, error) {
	var consumed sql.NullString
	err := s.db.QueryRow(`SELECT consumed_at FROM bootstrap WHERE id = 1`).Scan(&consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return consumed.Valid, nil
}

func (s *Store) Bootstrap(secret []byte, g *protocol.Genesis, root protocol.SignedMembershipEvent) error {
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
	canonRoot, err := protocol.Canonical(&root)
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
	if err := createVaultTx(tx, g, string(canonGenesis), digest, string(canonRoot), chain.HeadDigest()); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE bootstrap SET consumed_at = ? WHERE id = 1`, g.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Use(deviceID protocol.ID, nonce string, until time.Time) (bool, error) {
	if nonce == "" {
		return false, errors.New("empty request nonce")
	}
	now := s.now()

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM request_nonce WHERE expires_at <= ?`, now.Unix()); err != nil {
		return false, err
	}
	res, err := tx.Exec(
		`INSERT INTO request_nonce (device_id, nonce, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT (device_id, nonce) DO NOTHING`,
		deviceID, nonce, until.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
}
