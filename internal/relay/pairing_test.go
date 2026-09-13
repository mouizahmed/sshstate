// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

func challenge(seed byte) protocol.Bytes {
	b := make(protocol.Bytes, protocol.ChallengeBytes)
	for i := range b {
		b[i] = seed ^ byte(i)
	}
	return b
}

func (h *harness) offer(joiner device, vaultID protocol.ID) protocol.SignedPairingOffer {
	h.t.Helper()
	o := protocol.PairingOffer{
		Domain:          protocol.PairingOfferDomain,
		FormatVersion:   protocol.PairingFormatVersion,
		Suite:           crypto.SuiteID,
		VaultID:         vaultID,
		JoinerDeviceID:  joiner.id,
		JoinerVerifyKey: joiner.signing.Verifier().Bytes(),
		JoinerRecipient: joiner.enc.Recipient().String(),
		JoinerChallenge: challenge(0x11),
		CreatedAt:       stamp,
	}
	msg, err := o.SigningInput()
	if err != nil {
		h.t.Fatal(err)
	}
	sig, err := joiner.signing.Sign(protocol.PairingOfferDomain, msg)
	if err != nil {
		h.t.Fatal(err)
	}
	return protocol.SignedPairingOffer{Offer: o, Signature: sig}
}

func approval(approver device) protocol.PairingApproval {
	created := time.Date(2026, 9, 12, 0, 1, 0, 0, time.UTC)
	return protocol.PairingApproval{
		ApproverDeviceID:  approver.id,
		ApproverVerifyKey: approver.signing.Verifier().Bytes(),
		ApproverRecipient: approver.enc.Recipient().String(),
		ApproverChallenge: challenge(0x33),
		CreatedAt:         created.Format(time.RFC3339),
		ExpiresAt:         created.Add(protocol.PairingLifetime).Format(time.RFC3339),
	}
}

func (h *harness) confirmation(by device, session, vault protocol.ID, digest []byte) protocol.SignedPairingConfirmation {
	h.t.Helper()
	c := protocol.PairingConfirmation{
		Domain:           protocol.PairingConfirmDomain,
		FormatVersion:    protocol.PairingFormatVersion,
		VaultID:          vault,
		SessionID:        session,
		DeviceID:         by.id,
		TranscriptDigest: digest,
		CreatedAt:        stamp,
	}
	msg, err := c.SigningInput()
	if err != nil {
		h.t.Fatal(err)
	}
	sig, err := by.signing.Sign(protocol.PairingConfirmDomain, msg)
	if err != nil {
		h.t.Fatal(err)
	}
	return protocol.SignedPairingConfirmation{Confirmation: c, Signature: sig}
}

func (h *harness) transcriptDigest(session protocol.ID, offer protocol.SignedPairingOffer, a protocol.PairingApproval) []byte {
	h.t.Helper()
	tr, err := protocol.BuildTranscript(session, offer.Offer, a, crypto.SuiteID)
	if err != nil {
		h.t.Fatal(err)
	}
	d, err := tr.Digest()
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

func (h *harness) pairThrough(joiner device, state PairingState) (*PairingSession, []byte) {
	h.t.Helper()
	offer := h.offer(joiner, h.vaultID)
	session, err := h.store.CreatePairing(h.vaultID, offer)
	if err != nil {
		h.t.Fatal(err)
	}
	if state == PairingOffered {
		return session, nil
	}
	a := approval(h.first)
	digest := h.transcriptDigest(session.SessionID, offer, a)
	session, err = h.store.ConfirmApprover(session.SessionID, a,
		h.confirmation(h.first, session.SessionID, h.vaultID, digest))
	if err != nil {
		h.t.Fatal(err)
	}
	if state == PairingConfirming {
		return session, digest
	}
	session, err = h.store.ConfirmJoiner(session.SessionID,
		h.confirmation(joiner, session.SessionID, h.vaultID, digest))
	if err != nil {
		h.t.Fatal(err)
	}
	return session, digest
}

func (h *harness) enrolment(joiner device, digest []byte) protocol.SignedMembershipEvent {
	h.t.Helper()
	chain, err := h.store.Chain(h.vaultID)
	if err != nil {
		h.t.Fatal(err)
	}
	ev, err := chain.Enroll(signerFor(h.first), joiner.keys(), digest, h.tick())
	if err != nil {
		h.t.Fatal(err)
	}
	return ev
}

func TestPairingRunsToCompletion(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	session, digest := h.pairThrough(joiner, PairingConfirmed)
	if session.State != PairingConfirmed {
		t.Fatalf("session is %s", session.State)
	}

	ev := h.enrolment(joiner, digest)
	session, err := h.store.Complete(session.SessionID, ev, []byte("sealed-bundle"), []byte("sealed-snapshot"), h.genesis)
	if err != nil {
		t.Fatal(err)
	}
	if session.State != PairingConfirmed || session.Bundle == nil {
		t.Fatalf("after delivery the session is %s with bundle %v", session.State, session.Bundle != nil)
	}

	session, err = h.store.Acknowledge(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if session.State != PairingCompleted {
		t.Fatalf("session is %s after acknowledgement", session.State)
	}

	_, err = h.store.Acknowledge(session.SessionID)
	mustCode(t, err, protocol.CodePairingConsumed)

	reloaded, err := h.store.Pairing(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if string(reloaded.Bundle) != "sealed-bundle" || string(reloaded.Snapshot) != "sealed-snapshot" {
		t.Fatal("the sealed ciphertext did not survive a reload")
	}
}

func TestNoBundleBeforeBothConfirmations(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)

	session, _ := h.pairThrough(joiner, PairingOffered)
	ev := h.enrolment(joiner, bytes.Repeat([]byte{7}, 32))
	_, err := h.store.Complete(session.SessionID, ev, []byte("bundle"), nil, h.genesis)
	mustCode(t, err, protocol.CodePairingIncomplete)

	session, digest := h.pairThrough(newDevice(t), PairingConfirming)
	_ = digest
	_, err = h.store.Complete(session.SessionID, ev, []byte("bundle"), nil, h.genesis)
	mustCode(t, err, protocol.CodePairingIncomplete)
}

func TestBothDevicesMustConfirmTheSameTranscript(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	session, _ := h.pairThrough(joiner, PairingConfirming)

	other := bytes.Repeat([]byte{9}, 32)
	_, err := h.store.ConfirmJoiner(session.SessionID,
		h.confirmation(joiner, session.SessionID, h.vaultID, other))
	mustCode(t, err, protocol.CodeInvalidRequest)
}

func TestPairingStepOrderIsEnforced(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	session, _ := h.pairThrough(joiner, PairingOffered)

	_, err := h.store.ConfirmJoiner(session.SessionID,
		h.confirmation(joiner, session.SessionID, h.vaultID, bytes.Repeat([]byte{1}, 32)))
	mustCode(t, err, protocol.CodePairingIncomplete)

	a := approval(h.first)
	digest := h.transcriptDigest(session.SessionID, session.Offer, a)
	if _, err := h.store.ConfirmApprover(session.SessionID, a,
		h.confirmation(h.first, session.SessionID, h.vaultID, digest)); err != nil {
		t.Fatal(err)
	}
	_, err = h.store.ConfirmApprover(session.SessionID, a,
		h.confirmation(h.first, session.SessionID, h.vaultID, digest))
	mustCode(t, err, protocol.CodePairingIncomplete)
}

func TestOnlyTheJoinerCanConfirmAsTheJoiner(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	session, digest := h.pairThrough(joiner, PairingConfirming)

	impostor := newDevice(t)
	_, err := h.store.ConfirmJoiner(session.SessionID,
		h.confirmation(impostor, session.SessionID, h.vaultID, digest))
	mustCode(t, err, protocol.CodeNotAuthorized)
}

func TestApproverMustBeAuthorized(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	session, _ := h.pairThrough(joiner, PairingOffered)

	stranger := newDevice(t)
	a := approval(stranger)
	digest := h.transcriptDigest(session.SessionID, session.Offer, a)
	_, err := h.store.ConfirmApprover(session.SessionID, a,
		h.confirmation(stranger, session.SessionID, h.vaultID, digest))
	mustCode(t, err, protocol.CodeDeviceUnknown)
}

func TestOfferMustBeSelfSigned(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	offer := h.offer(joiner, h.vaultID)

	other := newDevice(t)
	msg, err := offer.Offer.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := other.signing.Sign(protocol.PairingOfferDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	offer.Signature = sig
	_, err = h.store.CreatePairing(h.vaultID, offer)
	mustCode(t, err, protocol.CodeSignatureInvalid)
}

func TestAKnownDeviceCannotPairIn(t *testing.T) {
	h := newHarness(t)
	_, err := h.store.CreatePairing(h.vaultID, h.offer(h.first, h.vaultID))
	mustCode(t, err, protocol.CodeInvalidRequest)
}

func TestOneActiveAttemptPerDevice(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	if _, err := h.store.CreatePairing(h.vaultID, h.offer(joiner, h.vaultID)); err != nil {
		t.Fatal(err)
	}
	_, err := h.store.CreatePairing(h.vaultID, h.offer(joiner, h.vaultID))
	mustCode(t, err, protocol.CodeRateLimited)

	if _, err := h.store.CreatePairing(h.vaultID, h.offer(newDevice(t), h.vaultID)); err != nil {
		t.Fatal(err)
	}
}

func TestPairingExpires(t *testing.T) {
	h := newHarness(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	h.store.Now = func() time.Time { return now }
	joiner := newDevice(t)
	session, _ := h.pairThrough(joiner, PairingOffered)

	now = now.Add(protocol.PairingLifetime + time.Second)
	got, err := h.store.Pairing(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != PairingExpired {
		t.Fatalf("an old session reads as %s", got.State)
	}
	a := approval(h.first)
	_, err = h.store.ConfirmApprover(session.SessionID, a,
		h.confirmation(h.first, session.SessionID, h.vaultID, bytes.Repeat([]byte{1}, 32)))
	mustCode(t, err, protocol.CodePairingExpired)

	if _, err := h.store.CreatePairing(h.vaultID, h.offer(joiner, h.vaultID)); err != nil {
		t.Fatalf("an expired attempt blocked a new one: %v", err)
	}
}

func TestCompleteChecksTheEnrolmentMatches(t *testing.T) {
	h := newHarness(t)
	joiner := newDevice(t)
	session, digest := h.pairThrough(joiner, PairingConfirmed)

	elsewhere := newDevice(t)
	wrongDevice := h.enrolment(elsewhere, digest)
	_, err := h.store.Complete(session.SessionID, wrongDevice, []byte("bundle"), nil, h.genesis)
	mustCode(t, err, protocol.CodeIDMismatch)

	wrongTranscript := h.enrolment(joiner, bytes.Repeat([]byte{9}, 32))
	_, err = h.store.Complete(session.SessionID, wrongTranscript, []byte("bundle"), nil, h.genesis)
	mustCode(t, err, protocol.CodeInvalidRequest)
}
