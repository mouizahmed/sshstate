// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type PairingState string

const (
	PairingOffered    PairingState = "offered"
	PairingConfirming PairingState = "confirming"
	PairingConfirmed  PairingState = "confirmed"
	PairingCompleted  PairingState = "completed"
	PairingExpired    PairingState = "expired"
)

type PairingSession struct {
	SessionID            protocol.ID                         `json:"session_id"`
	VaultID              protocol.ID                         `json:"vault_id"`
	State                PairingState                        `json:"state"`
	Offer                protocol.SignedPairingOffer         `json:"offer"`
	Approver             *protocol.PairingApproval           `json:"approver"`
	ApproverConfirmation *protocol.SignedPairingConfirmation `json:"approver_confirmation"`
	JoinerConfirmation   *protocol.SignedPairingConfirmation `json:"joiner_confirmation"`
	MembershipEvent      *protocol.SignedMembershipEvent     `json:"membership_event"`
	Genesis              *protocol.Genesis                   `json:"genesis"`
	ExpiresAt            time.Time                           `json:"expires_at"`
	Bundle               []byte                              `json:"-"`
	Snapshot             []byte                              `json:"-"`
}

func (p *PairingSession) JoinerDeviceID() protocol.ID { return p.Offer.Offer.JoinerDeviceID }

func (p *PairingSession) TranscriptDigest() []byte {
	if p.ApproverConfirmation == nil {
		return nil
	}
	return p.ApproverConfirmation.Confirmation.TranscriptDigest
}

func (s *Store) CreatePairing(vaultID protocol.ID, offer protocol.SignedPairingOffer) (*PairingSession, error) {
	if err := offer.Offer.Validate(crypto.SuiteID); err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	if offer.Offer.VaultID != vaultID {
		return nil, protocol.Errorf(protocol.CodeIDMismatch, "the offer names another vault")
	}
	key, err := crypto.VerifyKeyFromBytes(offer.Offer.JoinerVerifyKey)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest, "joiner_verify_key: %v", err)
	}
	msg, err := offer.Offer.SigningInput()
	if err != nil {
		return nil, err
	}
	if err := crypto.Verify(key, protocol.PairingOfferDomain, msg, offer.Signature); err != nil {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "the offer is not signed by the key it offers")
	}
	chain, err := s.Chain(vaultID)
	if err != nil {
		return nil, err
	}
	if _, seen := chain.Device(offer.Offer.JoinerDeviceID); seen {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest,
			"device %s has already appeared in the membership chain", offer.Offer.JoinerDeviceID)
	}

	now := s.now()
	session := &PairingSession{
		SessionID: protocol.MustNewID(),
		VaultID:   vaultID,
		State:     PairingOffered,
		Offer:     offer,
		ExpiresAt: now.Add(protocol.PairingLifetime).UTC().Truncate(time.Second),
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var active int
	if err := tx.QueryRow(
		`SELECT count(*) FROM pairing
		 WHERE vault_id = ? AND joiner_device_id = ? AND state != ? AND expires_at > ?`,
		vaultID, offer.Offer.JoinerDeviceID, string(PairingCompleted), now.Unix()).Scan(&active); err != nil {
		return nil, err
	}
	if active > 0 {
		return nil, protocol.Errorf(protocol.CodeRateLimited,
			"device %s already has an active pairing attempt", offer.Offer.JoinerDeviceID)
	}
	if err := insertPairing(tx, session); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return session, nil
}

func insertPairing(tx *sql.Tx, p *PairingSession) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		`INSERT INTO pairing (session_id, vault_id, joiner_device_id, state, session, bundle, snapshot, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(session_id) DO UPDATE SET
		   state = excluded.state, session = excluded.session,
		   bundle = excluded.bundle, snapshot = excluded.snapshot`,
		p.SessionID, p.VaultID, p.JoinerDeviceID(), string(p.State), string(body),
		nullableBlob(p.Bundle), nullableBlob(p.Snapshot), p.ExpiresAt.Unix())
	return err
}

func nullableBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

func (s *Store) Pairing(sessionID protocol.ID) (*PairingSession, error) {
	return pairingTx(s.db, s.now(), sessionID)
}

func pairingTx(q rowQuerier, now time.Time, sessionID protocol.ID) (*PairingSession, error) {
	var body string
	var bundle, snapshot []byte
	var expires int64
	err := q.QueryRow(
		`SELECT session, bundle, snapshot, expires_at FROM pairing WHERE session_id = ?`,
		sessionID).Scan(&body, &bundle, &snapshot, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, protocol.Errorf(protocol.CodeNotFound, "no such pairing session")
	}
	if err != nil {
		return nil, err
	}
	var p PairingSession
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		return nil, err
	}
	p.Bundle, p.Snapshot = bundle, snapshot
	p.ExpiresAt = time.Unix(expires, 0).UTC()
	if p.State != PairingCompleted && !now.Before(p.ExpiresAt) {
		p.State = PairingExpired
	}
	return &p, nil
}

func writable(p *PairingSession) error {
	switch p.State {
	case PairingCompleted:
		return protocol.Errorf(protocol.CodePairingConsumed, "this pairing session already completed")
	case PairingExpired:
		return protocol.Errorf(protocol.CodePairingExpired, "this pairing session has expired")
	}
	return nil
}

func (s *Store) ConfirmApprover(sessionID protocol.ID, approval protocol.PairingApproval, conf protocol.SignedPairingConfirmation) (*PairingSession, error) {
	return s.advance(sessionID, func(p *PairingSession, chain *membership.Chain) error {
		if p.State != PairingOffered {
			return protocol.Errorf(protocol.CodePairingIncomplete, "this session already has an approver")
		}
		if err := approval.Validate(); err != nil {
			return protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
		}
		if approval.ApproverDeviceID != conf.Confirmation.DeviceID {
			return protocol.Errorf(protocol.CodeInvalidRequest, "the confirmation names a different device")
		}
		if err := authorized(chain, approval.ApproverDeviceID); err != nil {
			return err
		}
		if err := verifyConfirmation(chain, p, conf); err != nil {
			return err
		}
		p.Approver = &approval
		p.ApproverConfirmation = &conf
		p.State = PairingConfirming
		return nil
	})
}

func (s *Store) ConfirmJoiner(sessionID protocol.ID, conf protocol.SignedPairingConfirmation) (*PairingSession, error) {
	return s.advance(sessionID, func(p *PairingSession, chain *membership.Chain) error {
		if p.State != PairingConfirming {
			return protocol.Errorf(protocol.CodePairingIncomplete,
				"the approver has not confirmed this session yet")
		}
		if conf.Confirmation.DeviceID != p.JoinerDeviceID() {
			return protocol.Errorf(protocol.CodeNotAuthorized, "this confirmation is not the joiner's")
		}
		if err := verifyConfirmation(chain, p, conf); err != nil {
			return err
		}
		if !bytes.Equal(conf.Confirmation.TranscriptDigest, p.TranscriptDigest()) {
			return protocol.Errorf(protocol.CodeInvalidRequest,
				"the two devices confirmed different transcripts")
		}
		p.JoinerConfirmation = &conf
		p.State = PairingConfirmed
		return nil
	})
}

func (s *Store) Complete(sessionID protocol.ID, ev protocol.SignedMembershipEvent, bundle, snapshot []byte, genesis *protocol.Genesis) (*PairingSession, error) {
	return s.advance(sessionID, func(p *PairingSession, chain *membership.Chain) error {
		if p.State != PairingConfirmed {
			return protocol.Errorf(protocol.CodePairingIncomplete,
				"both devices must confirm before keys are delivered")
		}
		if p.Bundle != nil {
			return protocol.Errorf(protocol.CodePairingConsumed, "this session already carries a bundle")
		}
		if len(bundle) == 0 {
			return protocol.Errorf(protocol.CodeInvalidRequest, "no bundle")
		}
		if ev.Event.DeviceID != p.JoinerDeviceID() {
			return protocol.Errorf(protocol.CodeIDMismatch, "the membership event enrols a different device")
		}
		if !bytes.Equal(ev.Event.TranscriptDigest, p.TranscriptDigest()) {
			return protocol.Errorf(protocol.CodeInvalidRequest,
				"the membership event names a different transcript")
		}
		p.MembershipEvent = &ev
		p.Bundle = bundle
		p.Snapshot = snapshot
		p.Genesis = genesis
		return nil
	})
}

func (s *Store) Acknowledge(sessionID protocol.ID) (*PairingSession, error) {
	return s.advance(sessionID, func(p *PairingSession, chain *membership.Chain) error {
		if p.State != PairingConfirmed || p.Bundle == nil {
			return protocol.Errorf(protocol.CodePairingIncomplete, "there is nothing to acknowledge yet")
		}
		p.State = PairingCompleted
		return nil
	})
}

func verifyConfirmation(chain *membership.Chain, p *PairingSession, conf protocol.SignedPairingConfirmation) error {
	if err := conf.Confirmation.Validate(); err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	if conf.Confirmation.SessionID != p.SessionID || conf.Confirmation.VaultID != p.VaultID {
		return protocol.Errorf(protocol.CodeIDMismatch, "the confirmation names another session")
	}
	var key *crypto.VerifyKey
	if conf.Confirmation.DeviceID == p.JoinerDeviceID() {
		var err error
		key, err = crypto.VerifyKeyFromBytes(p.Offer.Offer.JoinerVerifyKey)
		if err != nil {
			return err
		}
	} else {
		if err := authorized(chain, conf.Confirmation.DeviceID); err != nil {
			return err
		}
		d, _ := chain.Device(conf.Confirmation.DeviceID)
		key = d.VerifyKey
	}
	msg, err := conf.Confirmation.SigningInput()
	if err != nil {
		return err
	}
	if err := crypto.Verify(key, protocol.PairingConfirmDomain, msg, conf.Signature); err != nil {
		return protocol.Errorf(protocol.CodeSignatureInvalid, "the confirmation signature does not verify")
	}
	return nil
}

func authorized(chain *membership.Chain, id protocol.ID) error {
	d, ok := chain.Device(id)
	if !ok {
		return protocol.Errorf(protocol.CodeDeviceUnknown, "device %s is not in the membership chain", id)
	}
	if d.Revoked {
		return protocol.Errorf(protocol.CodeDeviceRevoked, "device %s was revoked", id)
	}
	return nil
}

func (s *Store) advance(sessionID protocol.ID, step func(*PairingSession, *membership.Chain) error) (*PairingSession, error) {
	vaultID, err := s.VaultID()
	if err != nil {
		return nil, err
	}
	chain, err := s.Chain(vaultID)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	p, err := pairingTx(tx, s.now(), sessionID)
	if err != nil {
		return nil, err
	}
	if p.VaultID != vaultID {
		return nil, protocol.Errorf(protocol.CodeNotFound, "no such pairing session")
	}
	if err := writable(p); err != nil {
		return nil, err
	}
	if err := step(p, chain); err != nil {
		return nil, err
	}
	if err := insertPairing(tx, p); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}
