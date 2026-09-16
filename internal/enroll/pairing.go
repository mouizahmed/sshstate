// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relayclient"
)

type Identity struct {
	DeviceID   protocol.ID
	Signing    *crypto.SigningKey
	Encryption *crypto.EncryptionKey
}

func (i Identity) keys() membership.DeviceKeys {
	return membership.DeviceKeys{
		ID:        i.DeviceID,
		VerifyKey: i.Signing.Verifier().Bytes(),
		Recipient: i.Encryption.Recipient().String(),
	}
}

func challenge() (protocol.Bytes, error) {
	b := make(protocol.Bytes, protocol.ChallengeBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

type Joiner struct {
	client  *relayclient.Client
	id      Identity
	vaultID protocol.ID
	now     func() time.Time

	sessionID  protocol.ID
	offer      protocol.SignedPairingOffer
	transcript *protocol.PairingTranscript
}

func Begin(ctx context.Context, client *relayclient.Client, vaultID protocol.ID, id Identity, now func() time.Time) (*Joiner, error) {
	if now == nil {
		now = time.Now
	}
	c, err := challenge()
	if err != nil {
		return nil, err
	}
	offer := protocol.PairingOffer{
		Domain:          protocol.PairingOfferDomain,
		FormatVersion:   protocol.PairingFormatVersion,
		Suite:           crypto.SuiteID,
		VaultID:         vaultID,
		JoinerDeviceID:  id.DeviceID,
		JoinerVerifyKey: id.Signing.Verifier().Bytes(),
		JoinerRecipient: id.Encryption.Recipient().String(),
		JoinerChallenge: c,
		CreatedAt:       stamp(now()),
	}
	msg, err := offer.SigningInput()
	if err != nil {
		return nil, err
	}
	sig, err := id.Signing.Sign(protocol.PairingOfferDomain, msg)
	if err != nil {
		return nil, err
	}
	signed := protocol.SignedPairingOffer{Offer: offer, Signature: sig}
	out, err := client.CreatePairing(ctx, vaultID, signed)
	if err != nil {
		return nil, err
	}
	return &Joiner{
		client: client, id: id, vaultID: vaultID, now: now,
		sessionID: out.SessionID, offer: signed,
	}, nil
}

func (j *Joiner) SessionID() protocol.ID { return j.sessionID }

func (j *Joiner) Transcript(ctx context.Context) (*protocol.PairingTranscript, error) {
	session, err := j.client.Pairing(ctx, j.sessionID)
	if err != nil {
		return nil, err
	}
	if err := usable(session); err != nil {
		return nil, err
	}
	if session.Approver == nil {
		return nil, errors.New("the approving device has not confirmed yet")
	}
	tr, err := protocol.BuildTranscript(j.sessionID, j.offer.Offer, *session.Approver, crypto.SuiteID)
	if err != nil {
		return nil, err
	}
	if tr.Expired(j.now()) {
		return nil, protocol.Errorf(protocol.CodePairingExpired, "this pairing session has expired")
	}
	if session.ApproverConfirmation == nil {
		return nil, errors.New("the approving device has not confirmed yet")
	}
	digest, err := tr.Digest()
	if err != nil {
		return nil, err
	}
	if err := verifyConfirmation(*session.ApproverConfirmation, tr, digest,
		mustVerifyKey(session.Approver.ApproverVerifyKey)); err != nil {
		return nil, err
	}
	j.transcript = tr
	return tr, nil
}

func (j *Joiner) Fingerprint() (string, error) {
	if j.transcript == nil {
		return "", errors.New("no transcript yet")
	}
	return j.transcript.Fingerprint()
}

func (j *Joiner) Confirm(ctx context.Context) error {
	if j.transcript == nil {
		return errors.New("nothing has been compared yet")
	}
	conf, err := signConfirmation(j.transcript, j.id, j.now())
	if err != nil {
		return err
	}
	_, err = j.client.ConfirmPairing(ctx, j.sessionID, protocol.ConfirmPairingRequest{
		Confirmation: conf.Confirmation, Signature: conf.Signature,
	})
	return err
}

type Delivery struct {
	Genesis    *protocol.Genesis
	Bundle     *protocol.Bundle
	Snapshot   []*protocol.Envelope
	Event      protocol.SignedMembershipEvent
	Membership []protocol.SignedMembershipEvent
}

var ErrNotDelivered = errors.New("the approving device has not delivered the keys yet")

func (j *Joiner) Receive(ctx context.Context) (*Delivery, error) {
	if j.transcript == nil {
		return nil, errors.New("nothing has been compared yet")
	}
	session, err := j.client.Pairing(ctx, j.sessionID)
	if err != nil {
		return nil, err
	}
	if err := usable(session); err != nil {
		return nil, err
	}
	if session.MembershipEvent == nil || len(session.Bundle) == 0 {
		return nil, ErrNotDelivered
	}
	if session.Genesis == nil {
		return nil, errors.New("the delivery carries no genesis document")
	}
	genesis := session.Genesis
	if err := genesis.Validate(crypto.SuiteID); err != nil {
		return nil, fmt.Errorf("delivered genesis: %w", err)
	}
	if genesis.VaultID != j.vaultID {
		return nil, errors.New("the delivery is for a different vault")
	}
	digest, err := j.transcript.Digest()
	if err != nil {
		return nil, err
	}

	events, err := j.client.Membership(ctx)
	if protocol.CodeOf(err) == protocol.CodeDeviceUnknown {
		return nil, ErrNotDelivered
	}
	if err != nil {
		return nil, err
	}
	chain, err := membership.Validate(genesis, events)
	if err != nil {
		return nil, fmt.Errorf("membership chain: %w", err)
	}
	ev := *session.MembershipEvent
	if ev.Event.DeviceID != j.id.DeviceID {
		return nil, errors.New("the enrolment is for a different device")
	}
	if string(ev.Event.TranscriptDigest) != string(digest) {
		return nil, errors.New("the enrolment names a transcript this device did not confirm")
	}
	published, err := contains(events, ev)
	if err != nil {
		return nil, err
	}
	extended := chain
	if !published {
		extended, err = chain.Append(ev)
		if err != nil {
			return nil, fmt.Errorf("the enrolment does not extend the chain: %w", err)
		}
	}
	if !extended.Authorized(j.id.DeviceID) {
		return nil, errors.New("the chain does not authorize this device")
	}
	approver, ok := extended.Device(ev.Event.AuthorizedBy)
	if !ok {
		return nil, errors.New("the enrolment names an approver the chain does not know")
	}

	bundle, err := OpenBundle(session.Bundle, j.id.Encryption, approver.VerifyKey)
	if err != nil {
		return nil, err
	}
	if string(bundle.TranscriptDigest) != string(digest) {
		return nil, errors.New("the bundle names a transcript this device did not confirm")
	}
	if bundle.RecipientDeviceID == nil || *bundle.RecipientDeviceID != j.id.DeviceID {
		return nil, errors.New("the bundle is addressed to a different device")
	}
	genesisDigest, err := genesis.Digest()
	if err != nil {
		return nil, err
	}
	if string(bundle.GenesisDigest) != string(genesisDigest) {
		return nil, errors.New("the bundle pins a different vault")
	}

	delivery := &Delivery{
		Genesis:    genesis,
		Bundle:     bundle,
		Event:      ev,
		Membership: extended.Events(),
	}
	if bundle.SnapshotDigest != nil {
		if len(session.Snapshot) == 0 {
			return nil, errors.New("the bundle binds a snapshot that was not delivered")
		}
		records, err := OpenSnapshot(session.Snapshot, j.id.Encryption,
			bundle.SnapshotDigest, *bundle.SnapshotLength)
		if err != nil {
			return nil, err
		}
		delivery.Snapshot = records
	}
	return delivery, nil
}

func contains(events []protocol.SignedMembershipEvent, ev protocol.SignedMembershipEvent) (bool, error) {
	want, err := ev.Digest()
	if err != nil {
		return false, err
	}
	for i := range events {
		got, err := events[i].Digest()
		if err != nil {
			return false, err
		}
		if bytes.Equal(got, want) {
			return true, nil
		}
	}
	return false, nil
}

func (j *Joiner) Acknowledge(ctx context.Context) error {
	_, err := j.client.CompletePairing(ctx, j.sessionID,
		protocol.CompletePairingRequest{Acknowledged: true})
	return err
}

type Approver struct {
	client  *relayclient.Client
	id      Identity
	genesis *protocol.Genesis
	now     func() time.Time

	sessionID  protocol.ID
	session    *protocol.PairingResponse
	approval   protocol.PairingApproval
	transcript *protocol.PairingTranscript
}

func Approve(ctx context.Context, client *relayclient.Client, g *protocol.Genesis, sessionID protocol.ID, id Identity, now func() time.Time) (*Approver, error) {
	if now == nil {
		now = time.Now
	}
	session, err := client.Pairing(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if err := usable(session); err != nil {
		return nil, err
	}
	if session.Offer == nil {
		return nil, errors.New("the session has no offer")
	}
	offerKey, err := crypto.VerifyKeyFromBytes(session.Offer.JoinerVerifyKey)
	if err != nil {
		return nil, err
	}
	msg, err := session.Offer.SigningInput()
	if err != nil {
		return nil, err
	}
	if err := crypto.Verify(offerKey, protocol.PairingOfferDomain, msg, session.OfferSignature); err != nil {
		return nil, errors.New("the offer is not signed by the key it offers")
	}

	c, err := challenge()
	if err != nil {
		return nil, err
	}
	created := now().UTC().Truncate(time.Second)
	approval := protocol.PairingApproval{
		ApproverDeviceID:  id.DeviceID,
		ApproverVerifyKey: id.Signing.Verifier().Bytes(),
		ApproverRecipient: id.Encryption.Recipient().String(),
		ApproverChallenge: c,
		CreatedAt:         stamp(created),
		ExpiresAt:         stamp(created.Add(protocol.PairingLifetime)),
	}
	tr, err := protocol.BuildTranscript(sessionID, *session.Offer, approval, crypto.SuiteID)
	if err != nil {
		return nil, err
	}
	return &Approver{
		client: client, id: id, genesis: g, now: now,
		sessionID: sessionID, session: session, approval: approval, transcript: tr,
	}, nil
}

func (a *Approver) Fingerprint() (string, error) { return a.transcript.Fingerprint() }

func (a *Approver) Transcript() *protocol.PairingTranscript { return a.transcript }

func (a *Approver) JoinerKeys() membership.DeviceKeys {
	return membership.DeviceKeys{
		ID:        a.session.Offer.JoinerDeviceID,
		VerifyKey: a.session.Offer.JoinerVerifyKey,
		Recipient: a.session.Offer.JoinerRecipient,
	}
}

func (a *Approver) JoinerRecipient() (*crypto.Recipient, error) {
	return crypto.ParseRecipient(a.session.Offer.JoinerRecipient)
}

func (a *Approver) Confirm(ctx context.Context) error {
	if a.transcript.Expired(a.now()) {
		return protocol.Errorf(protocol.CodePairingExpired, "this pairing session has expired")
	}
	conf, err := signConfirmation(a.transcript, a.id, a.now())
	if err != nil {
		return err
	}
	approval := a.approval
	_, err = a.client.ConfirmPairing(ctx, a.sessionID, protocol.ConfirmPairingRequest{
		Approver:     &approval,
		Confirmation: conf.Confirmation,
		Signature:    conf.Signature,
	})
	return err
}

func (a *Approver) AwaitJoiner(ctx context.Context) (bool, error) {
	session, err := a.client.Pairing(ctx, a.sessionID)
	if err != nil {
		return false, err
	}
	if err := usable(session); err != nil {
		return false, err
	}
	if session.JoinerConfirmation == nil {
		return false, nil
	}
	digest, err := a.transcript.Digest()
	if err != nil {
		return false, err
	}
	joinerKey, err := crypto.VerifyKeyFromBytes(a.session.Offer.JoinerVerifyKey)
	if err != nil {
		return false, err
	}
	if err := verifyConfirmation(*session.JoinerConfirmation, a.transcript, digest, joinerKey); err != nil {
		return false, err
	}
	a.session = session
	return true, nil
}

func (a *Approver) Deliver(ctx context.Context, ev protocol.SignedMembershipEvent, bundle, snapshot []byte) error {
	if a.session.JoinerConfirmation == nil {
		return errors.New("the joining device has not confirmed the fingerprint")
	}
	if _, err := a.client.CompletePairing(ctx, a.sessionID, protocol.CompletePairingRequest{
		MembershipEvent: &ev,
		Bundle:          bundle,
		Snapshot:        snapshot,
		Genesis:         a.genesis,
	}); err != nil {
		return err
	}
	_, err := a.client.AppendMembership(ctx, ev)
	return err
}

func usable(s *protocol.PairingResponse) error {
	switch s.State {
	case "expired":
		return protocol.Errorf(protocol.CodePairingExpired, "this pairing session has expired")
	case "completed":
		return protocol.Errorf(protocol.CodePairingConsumed, "this pairing session already completed")
	}
	return nil
}

func signConfirmation(tr *protocol.PairingTranscript, id Identity, now time.Time) (*protocol.SignedPairingConfirmation, error) {
	digest, err := tr.Digest()
	if err != nil {
		return nil, err
	}
	c := protocol.PairingConfirmation{
		Domain:           protocol.PairingConfirmDomain,
		FormatVersion:    protocol.PairingFormatVersion,
		VaultID:          tr.VaultID,
		SessionID:        tr.SessionID,
		DeviceID:         id.DeviceID,
		TranscriptDigest: digest,
		CreatedAt:        stamp(now),
	}
	msg, err := c.SigningInput()
	if err != nil {
		return nil, err
	}
	sig, err := id.Signing.Sign(protocol.PairingConfirmDomain, msg)
	if err != nil {
		return nil, err
	}
	return &protocol.SignedPairingConfirmation{Confirmation: c, Signature: sig}, nil
}

func verifyConfirmation(conf protocol.SignedPairingConfirmation, tr *protocol.PairingTranscript, digest []byte, key *crypto.VerifyKey) error {
	if key == nil {
		return errors.New("no key to verify the confirmation against")
	}
	if err := conf.Confirmation.Validate(); err != nil {
		return err
	}
	if conf.Confirmation.SessionID != tr.SessionID || conf.Confirmation.VaultID != tr.VaultID {
		return errors.New("the confirmation names another session")
	}
	if string(conf.Confirmation.TranscriptDigest) != string(digest) {
		return errors.New("the other device confirmed a different transcript")
	}
	msg, err := conf.Confirmation.SigningInput()
	if err != nil {
		return err
	}
	if err := crypto.Verify(key, protocol.PairingConfirmDomain, msg, conf.Signature); err != nil {
		return errors.New("the confirmation signature does not verify")
	}
	return nil
}

func mustVerifyKey(raw []byte) *crypto.VerifyKey {
	key, err := crypto.VerifyKeyFromBytes(raw)
	if err != nil {
		return nil
	}
	return key
}
