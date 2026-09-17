package relay

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"crypto/rand"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

type KeyEnvelope struct {
	ID                protocol.ID
	RecipientDeviceID protocol.ID
	Purpose           protocol.BundlePurpose
	KeyEpoch          protocol.Counter
	Ciphertext        []byte
	CreatedAt         string
}

func (s *Store) PutKeyEnvelope(vaultID protocol.ID, env KeyEnvelope) error {
	if !env.ID.Valid() {
		return protocol.Errorf(protocol.CodeInvalidRequest, "envelope id is not a 128-bit lowercase hex id")
	}
	if !env.Purpose.Valid() {
		return protocol.Errorf(protocol.CodeInvalidRequest, "unknown bundle purpose %q", env.Purpose)
	}
	if len(env.Ciphertext) == 0 {
		return protocol.Errorf(protocol.CodeInvalidRequest, "envelope has no ciphertext")
	}
	if env.KeyEpoch < 1 {
		return protocol.Errorf(protocol.CodeInvalidRequest, "key_epoch starts at 1")
	}
	var recipient any
	if env.RecipientDeviceID != "" {
		if !env.RecipientDeviceID.Valid() {
			return protocol.Errorf(protocol.CodeInvalidRequest, "recipient_device_id is not a 128-bit lowercase hex id")
		}
		chain, err := s.Chain(vaultID)
		if err != nil {
			return err
		}
		d, ok := chain.Device(env.RecipientDeviceID)
		if !ok {
			return protocol.Errorf(protocol.CodeDeviceUnknown,
				"device %s is not in the membership chain", env.RecipientDeviceID)
		}
		if d.Revoked {
			return protocol.Errorf(protocol.CodeDeviceRevoked,
				"device %s was revoked and must not receive new key material", env.RecipientDeviceID)
		}
		recipient = env.RecipientDeviceID.String()
	}
	epoch, err := counterToInt(env.KeyEpoch, "key_epoch")
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if recipient == nil && env.Purpose == protocol.PurposeRecovery {
		if _, err := tx.Exec(
			`DELETE FROM key_envelope
			 WHERE vault_id = ? AND recipient_device_id IS NULL AND purpose = ? AND key_epoch <= ? AND envelope_id != ?`,
			vaultID, string(env.Purpose), epoch, env.ID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO key_envelope (vault_id, envelope_id, recipient_device_id, purpose, key_epoch, ciphertext, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, envelope_id) DO UPDATE SET
		   recipient_device_id = excluded.recipient_device_id,
		   purpose = excluded.purpose, key_epoch = excluded.key_epoch,
		   ciphertext = excluded.ciphertext, created_at = excluded.created_at`,
		vaultID, env.ID, recipient, string(env.Purpose), epoch, env.Ciphertext, env.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) KeyEnvelopesFor(vaultID, deviceID protocol.ID) ([]KeyEnvelope, error) {
	rows, err := s.db.Query(
		`SELECT envelope_id, purpose, key_epoch, ciphertext, created_at
		 FROM key_envelope WHERE vault_id = ? AND recipient_device_id = ?
		 ORDER BY key_epoch, envelope_id`, vaultID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyEnvelope
	for rows.Next() {
		env := KeyEnvelope{RecipientDeviceID: deviceID}
		var purpose string
		var epoch int64
		if err := rows.Scan(&env.ID, &purpose, &epoch, &env.Ciphertext, &env.CreatedAt); err != nil {
			return nil, err
		}
		env.Purpose = protocol.BundlePurpose(purpose)
		env.KeyEpoch = protocol.Counter(epoch)
		out = append(out, env)
	}
	return out, rows.Err()
}

func (s *Store) RecoveryEnvelope(vaultID protocol.ID) (*KeyEnvelope, error) {
	var env KeyEnvelope
	var purpose string
	var epoch int64
	err := s.db.QueryRow(
		`SELECT envelope_id, purpose, key_epoch, ciphertext, created_at
		 FROM key_envelope WHERE vault_id = ? AND recipient_device_id IS NULL
		 ORDER BY key_epoch DESC, envelope_id DESC LIMIT 1`, vaultID).
		Scan(&env.ID, &purpose, &epoch, &env.Ciphertext, &env.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, protocol.Errorf(protocol.CodeNotFound, "this vault has no recovery envelope")
	}
	if err != nil {
		return nil, err
	}
	env.Purpose = protocol.BundlePurpose(purpose)
	env.KeyEpoch = protocol.Counter(epoch)
	return &env, nil
}

const RecoveryChallengeTTL = 10 * time.Minute

const RecoveryNonceBytes = 32

func (s *Store) NewRecoveryChallenge(vaultID protocol.ID) (string, time.Time, error) {
	if _, err := s.Genesis(vaultID); err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, RecoveryNonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	expires := s.now().Add(RecoveryChallengeTTL).UTC().Truncate(time.Second)

	tx, err := s.db.Begin()
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM recovery_nonce WHERE expires_at <= ?`, s.now().Unix()); err != nil {
		return "", time.Time{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO recovery_nonce (vault_id, nonce, expires_at) VALUES (?, ?, ?)`,
		vaultID, nonce, expires.Unix()); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return nonce, expires, nil
}

func (s *Store) ConsumeRecoveryChallenge(vaultID protocol.ID, nonce string) error {
	if nonce == "" {
		return protocol.Errorf(protocol.CodeInvalidRequest, "no recovery nonce")
	}
	res, err := s.db.Exec(
		`DELETE FROM recovery_nonce WHERE vault_id = ? AND nonce = ? AND expires_at > ?`,
		vaultID, nonce, s.now().Unix())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return protocol.Errorf(protocol.CodeNotAuthorized,
			"this recovery challenge is unknown, expired, or already used")
	}
	return nil
}
