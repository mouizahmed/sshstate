// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net/http"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request, req *request) error {
	secret, err := bootstrapSecret(r)
	if err != nil {
		return err
	}
	var body protocol.BootstrapRequest
	if err := decode(req, &body); err != nil {
		return err
	}
	if err := s.store.Bootstrap(secret, &body.Genesis, body.MembershipRoot); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, protocol.BootstrapResponse{VaultID: body.Genesis.VaultID})
	return nil
}

func (s *Server) handleCreatePairing(w http.ResponseWriter, r *http.Request, req *request) error {
	var body protocol.CreatePairingRequest
	if err := decode(req, &body); err != nil {
		return err
	}
	vaultID, err := s.store.VaultID()
	if err != nil {
		return err
	}
	if body.VaultID != vaultID {
		return protocol.Errorf(protocol.CodeNotFound, "no such vault")
	}
	session, err := s.store.CreatePairing(vaultID, protocol.SignedPairingOffer{
		Offer: body.Offer, Signature: body.Signature,
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, protocol.CreatePairingResponse{
		SessionID: session.SessionID,
		ExpiresAt: stampOf(session.ExpiresAt),
	})
	return nil
}

func (s *Server) handleGetPairing(w http.ResponseWriter, r *http.Request, req *request) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	session, err := s.store.Pairing(id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, pairingResponse(session))
	return nil
}

func pairingResponse(p *PairingSession) protocol.PairingResponse {
	offer := p.Offer.Offer
	return protocol.PairingResponse{
		SessionID:            p.SessionID,
		State:                string(p.State),
		Offer:                &offer,
		OfferSignature:       p.Offer.Signature,
		Approver:             p.Approver,
		ApproverConfirmation: p.ApproverConfirmation,
		JoinerConfirmation:   p.JoinerConfirmation,
		Bundle:               p.Bundle,
		Snapshot:             p.Snapshot,
		MembershipEvent:      p.MembershipEvent,
		Genesis:              p.Genesis,
		ExpiresAt:            stampOf(p.ExpiresAt),
	}
}

func (s *Server) handleConfirmPairing(w http.ResponseWriter, r *http.Request, req *request) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var body protocol.ConfirmPairingRequest
	if err := decode(req, &body); err != nil {
		return err
	}
	conf := protocol.SignedPairingConfirmation{
		Confirmation: body.Confirmation,
		Signature:    body.Signature,
	}
	var session *PairingSession
	if body.Approver != nil {
		session, err = s.store.ConfirmApprover(id, *body.Approver, conf)
	} else {
		session, err = s.store.ConfirmJoiner(id, conf)
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, pairingResponse(session))
	return nil
}

func (s *Server) handleCompletePairing(w http.ResponseWriter, r *http.Request, req *request) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var body protocol.CompletePairingRequest
	if err := decode(req, &body); err != nil {
		return err
	}
	var session *PairingSession
	switch {
	case body.MembershipEvent != nil:
		session, err = s.store.Complete(id, *body.MembershipEvent, body.Bundle, body.Snapshot, body.Genesis)
	case body.Acknowledged:
		session, err = s.store.Acknowledge(id)
	default:
		return protocol.Errorf(protocol.CodeInvalidRequest,
			"a completion carries either a membership event and bundle, or an acknowledgement")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, pairingResponse(session))
	return nil
}

func (s *Server) handleGetMembership(w http.ResponseWriter, r *http.Request, req *request) error {
	events, err := s.store.Membership(req.Signed.VaultID)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, protocol.MembershipResponse{Events: events})
	return nil
}

func (s *Server) handleAppendMembership(w http.ResponseWriter, r *http.Request, req *request) error {
	var body protocol.AppendMembershipRequest
	if err := decode(req, &body); err != nil {
		return err
	}
	chain, err := s.store.AppendMembership(req.Signed.VaultID, body.Event)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, protocol.AppendMembershipResponse{
		ChainSeq:   protocol.Counter(chain.Len()),
		HeadDigest: chain.HeadDigest(),
	})
	return nil
}

func (s *Server) handleGetEnvelopes(w http.ResponseWriter, r *http.Request, req *request) error {
	envelopes, err := s.store.KeyEnvelopesFor(req.Signed.VaultID, req.Signed.DeviceID)
	if err != nil {
		return err
	}
	out := protocol.EnvelopesResponse{Envelopes: make([]protocol.EnvelopeBody, 0, len(envelopes))}
	for _, e := range envelopes {
		recipient := e.RecipientDeviceID
		out.Envelopes = append(out.Envelopes, protocol.EnvelopeBody{
			ID:                e.ID,
			RecipientDeviceID: &recipient,
			Purpose:           e.Purpose,
			KeyEpoch:          e.KeyEpoch,
			Ciphertext:        e.Ciphertext,
		})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handlePutEnvelope(w http.ResponseWriter, r *http.Request, req *request) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var body protocol.EnvelopeBody
	if err := decode(req, &body); err != nil {
		return err
	}
	if body.ID != id {
		return protocol.Errorf(protocol.CodeIDMismatch, "the path and the body name different envelopes")
	}
	env := KeyEnvelope{
		ID:         id,
		Purpose:    body.Purpose,
		KeyEpoch:   body.KeyEpoch,
		Ciphertext: body.Ciphertext,
		CreatedAt:  stampOf(s.store.now()),
	}
	if body.RecipientDeviceID != nil {
		env.RecipientDeviceID = *body.RecipientDeviceID
	}
	if err := s.store.PutKeyEnvelope(req.Signed.VaultID, env); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

func (s *Server) handleRecoveryChallenge(w http.ResponseWriter, r *http.Request, req *request) error {
	var body protocol.RecoveryChallengeRequest
	if err := decode(req, &body); err != nil {
		return err
	}
	vaultID, err := s.store.VaultID()
	if err != nil {
		return err
	}
	if body.VaultID != vaultID {
		return protocol.Errorf(protocol.CodeNotFound, "no such vault")
	}
	genesis, err := s.store.Genesis(vaultID)
	if err != nil {
		return err
	}
	nonce, expires, err := s.store.NewRecoveryChallenge(vaultID)
	if err != nil {
		return err
	}
	out := protocol.RecoveryChallengeResponse{
		Nonce:     nonce,
		ExpiresAt: stampOf(expires),
		Genesis:   genesis,
	}
	if env, err := s.store.RecoveryEnvelope(vaultID); err == nil {
		out.RecoveryEnvelope = env.Ciphertext
	} else if protocol.CodeOf(err) != protocol.CodeNotFound {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleRecoveryComplete(w http.ResponseWriter, r *http.Request, req *request) error {
	var body protocol.RecoveryCompleteRequest
	if err := decode(req, &body); err != nil {
		return err
	}
	vaultID, err := s.store.VaultID()
	if err != nil {
		return err
	}
	genesis, err := s.store.Genesis(vaultID)
	if err != nil {
		return err
	}
	admission := body.Admission
	if admission.Domain != protocol.RecoveryAdmitDomain ||
		admission.FormatVersion != protocol.RecoveryAdmitFormatVersion {
		return protocol.Errorf(protocol.CodeUnsupportedVer, "unrecognized recovery admission")
	}
	if admission.VaultID != vaultID {
		return protocol.Errorf(protocol.CodeNotFound, "no such vault")
	}
	digest, err := genesis.Digest()
	if err != nil {
		return err
	}
	if string(admission.GenesisDigest) != string(digest) {
		return protocol.Errorf(protocol.CodeNotAuthorized, "the admission pins a different genesis")
	}
	if err := s.store.ConsumeRecoveryChallenge(vaultID, admission.Nonce); err != nil {
		return err
	}
	key, err := crypto.VerifyKeyFromBytes(genesis.RecoveryVerifyKey)
	if err != nil {
		return err
	}
	msg, err := admission.SigningInput()
	if err != nil {
		return err
	}
	if err := crypto.Verify(key, protocol.RecoveryAdmitDomain, msg, body.Signature); err != nil {
		return protocol.Errorf(protocol.CodeNotAuthorized, "the admission is not signed by the recovery key")
	}

	ev := body.MembershipEvent
	if ev.Event.DeviceID != admission.DeviceID {
		return protocol.Errorf(protocol.CodeIDMismatch,
			"the enrolment names a different device than the admission")
	}
	if ev.Event.Authority != protocol.AuthorityRecovery {
		return protocol.Errorf(protocol.CodeNotAuthorized,
			"a recovery enrolment must carry recovery authority")
	}
	chain, err := s.store.AppendMembership(vaultID, ev)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, protocol.RecoveryCompleteResponse{
		DeviceID:            admission.DeviceID,
		MembershipHeadDiges: chain.HeadDigest(),
	})
	return nil
}

func (s *Server) handleGetRecords(w http.ResponseWriter, r *http.Request, req *request) error {
	since, err := queryCounter(r, "since")
	if err != nil {
		return err
	}
	through, err := queryCounter(r, "through")
	if err != nil {
		return err
	}
	limit, err := queryCounter(r, "limit")
	if err != nil {
		return err
	}
	page, err := s.store.Changes(req.Signed.VaultID, since, through, int(limit))
	if err != nil {
		return err
	}
	out := protocol.RecordsResponse{
		Changes:        make([]protocol.Envelope, 0, len(page.Changes)),
		NextCursor:     page.NextCursor,
		SnapshotCursor: page.SnapshotCursor,
		HasMore:        page.HasMore,
	}
	for _, env := range page.Changes {
		out.Changes = append(out.Changes, *env)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handlePutRecord(w http.ResponseWriter, r *http.Request, req *request) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	var env protocol.Envelope
	if err := decode(req, &env); err != nil {
		return err
	}
	if env.Context.RecordID != id {
		return protocol.Errorf(protocol.CodeIDMismatch, "the path and the envelope name different records")
	}
	if req.Signed.IdempotencyKey != env.Context.MutationID.String() {
		return protocol.Errorf(protocol.CodeIDMismatch,
			"Idempotency-Key must equal the envelope's mutation_id")
	}
	if env.Seq != 0 {
		return protocol.Errorf(protocol.CodeInvalidRequest, "a submitted envelope must not carry a seq")
	}
	out, err := s.store.PutRecord(req.Signed.VaultID, &env, stampOf(s.store.now()))
	if err != nil {
		return err
	}
	if !out.Accepted {
		writeJSON(w, http.StatusConflict, protocol.ErrorResponse{
			Error: protocol.ErrorBody{
				Code:    out.Code,
				Message: "this submission does not follow the current head",
			},
			Head: out.Head,
		})
		return nil
	}
	writeJSON(w, http.StatusOK, protocol.PutRecordResponse{
		Accepted: true, Seq: out.Seq, Digest: out.Digest,
	})
	return nil
}
