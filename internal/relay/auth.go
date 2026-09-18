package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

const BootstrapSecretBytes = protocol.BootstrapSecretBytes

var (
	EncodeBootstrapSecret = protocol.EncodeBootstrapSecret
	DecodeBootstrapSecret = protocol.DecodeBootstrapSecret
)

func ReadBootstrapSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap secret: %w", err)
	}
	return protocol.DecodeBootstrapSecret(string(raw))
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

func (s *Store) MintBootstrapSecret() (string, error) {
	secret := make([]byte, BootstrapSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	if err := s.SetBootstrapSecret(secret); err != nil {
		return "", err
	}
	return EncodeBootstrapSecret(secret), nil
}

func (s *Store) bootstrapConfigured() (bool, error) {
	var stored []byte
	err := s.db.QueryRow(`SELECT secret_hash FROM bootstrap WHERE id = 1`).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ConfigureBootstrap(secretPath string) (string, error) {
	consumed, err := s.BootstrapConsumed()
	if err != nil {
		return "", err
	}
	if consumed {
		if secretPath == "" {
			return "bootstrap is closed; this relay holds its vault", nil
		}
		return fmt.Sprintf("bootstrap is closed; this relay holds its vault and ignores %s", secretPath), nil
	}
	if secretPath != "" {
		secret, err := ReadBootstrapSecret(secretPath)
		if err != nil {
			return "", err
		}
		if err := s.SetBootstrapSecret(secret); err != nil {
			return "", err
		}
		return fmt.Sprintf("bootstrap is open; connect a vault with the secret in %s", secretPath), nil
	}
	configured, err := s.bootstrapConfigured()
	if err != nil {
		return "", err
	}
	if configured {
		return "bootstrap is open; connect a vault with the secret already issued, " +
			"or replace it with the new-bootstrap-secret command", nil
	}
	return "bootstrap is not configured; issue a one-time secret with the " +
		"new-bootstrap-secret command to let a vault connect", nil
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
	return s.BootstrapHistory(secret, g, []protocol.SignedMembershipEvent{root}, false)
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
