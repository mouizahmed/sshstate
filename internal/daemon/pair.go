// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/enroll"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const joinerWait = 2 * time.Minute

func (d *Daemon) handlePairApprove(w http.ResponseWriter, r *http.Request) {
	var req control.PairApproveRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	sessionID := protocol.ID(req.SessionID)
	if !sessionID.Valid() {
		writeError(w, fmt.Errorf("%q is not a pairing session id", req.SessionID))
		return
	}
	deviceID, signing, encryption, err := d.mgr.Identity()
	if err != nil {
		writeError(w, err)
		return
	}
	identity := enroll.Identity{DeviceID: deviceID, Signing: signing, Encryption: encryption}
	client, err := d.relayClient("")
	if err != nil {
		writeError(w, err)
		return
	}
	approver, err := enroll.Approve(r.Context(), client, d.mgr.Genesis(), sessionID, identity, d.mgr.Now)
	if err != nil {
		writeError(w, err)
		return
	}
	fingerprint, err := approver.Fingerprint()
	if err != nil {
		writeError(w, err)
		return
	}
	digest, err := approver.Transcript().Digest()
	if err != nil {
		writeError(w, err)
		return
	}
	groups, err := protocol.FingerprintGroups(digest)
	if err != nil {
		writeError(w, err)
		return
	}

	d.approvalsMu.Lock()
	if d.approvals == nil {
		d.approvals = map[protocol.ID]*enroll.Approver{}
	}
	d.approvals[sessionID] = approver
	d.approvalsMu.Unlock()

	writeJSON(w, http.StatusOK, control.PairApproveResponse{
		SessionID:      sessionID.String(),
		JoinerDeviceID: approver.JoinerKeys().ID.String(),
		Fingerprint:    fingerprint,
		Groups:         groups,
		ExpiresAt:      approver.Transcript().ExpiresAt,
	})
}

func (d *Daemon) handlePairDeliver(w http.ResponseWriter, r *http.Request) {
	var req control.PairDeliverRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	sessionID := protocol.ID(req.SessionID)
	d.approvalsMu.Lock()
	approver := d.approvals[sessionID]
	d.approvalsMu.Unlock()
	if approver == nil {
		writeError(w, errors.New("that pairing session was not started on this device"))
		return
	}
	ctx := r.Context()

	if err := approver.Confirm(ctx); err != nil {
		writeError(w, err)
		return
	}
	ready, err := d.awaitJoiner(ctx, approver)
	if err != nil {
		writeError(w, err)
		return
	}
	if !ready {
		writeError(w, errors.New("the other device did not confirm the fingerprint in time"))
		return
	}

	digest, err := approver.Transcript().Digest()
	if err != nil {
		writeError(w, err)
		return
	}
	chain, err := d.chain()
	if err != nil {
		writeError(w, err)
		return
	}
	signer, err := d.mgr.MembershipSigner()
	if err != nil {
		writeError(w, err)
		return
	}
	ev, err := chain.Enroll(signer, membership.DeviceKeys(approver.JoinerKeys()), digest, d.mgr.Now())
	if err != nil {
		writeError(w, err)
		return
	}

	snapshot, err := d.mgr.Snapshot(true)
	if err != nil {
		writeError(w, err)
		return
	}
	records := append(append([]*protocol.Envelope{}, snapshot.Records...), snapshot.Conflicts...)
	body, err := enroll.BuildSnapshot(records)
	if err != nil {
		writeError(w, err)
		return
	}
	recipient, err := approver.JoinerRecipient()
	if err != nil {
		writeError(w, err)
		return
	}
	var sealedSnapshot, snapshotDigest []byte
	var snapshotLength protocol.Counter
	if len(body) > 0 {
		sealedSnapshot, snapshotDigest, snapshotLength, err = enroll.SealSnapshot(body, recipient)
		if err != nil {
			writeError(w, err)
			return
		}
	}
	bundle, err := d.mgr.EnrollmentBundle(approver.JoinerKeys().ID, recipient.String(), digest,
		snapshotDigest, snapshotLength, chain.HeadDigest(), d.acceptedSeq())
	if err != nil {
		writeError(w, err)
		return
	}
	sealed, err := enroll.SealSignedBundle(bundle, recipient)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := approver.Deliver(ctx, ev, sealed, sealedSnapshot); err != nil {
		writeError(w, err)
		return
	}
	client, err := d.relayClient("")
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.syncAndRefresh(ctx, client); err != nil {
		writeError(w, err)
		return
	}

	d.approvalsMu.Lock()
	delete(d.approvals, sessionID)
	d.approvalsMu.Unlock()

	writeJSON(w, http.StatusOK, control.PairDeliverResponse{
		DeviceID: approver.JoinerKeys().ID.String(),
		Records:  vault.LiveCount(records),
	})
}

func (d *Daemon) awaitJoiner(ctx context.Context, approver *enroll.Approver) (bool, error) {
	deadline := time.Now().Add(joinerWait)
	for {
		ready, err := approver.AwaitJoiner(ctx)
		if err != nil || ready {
			return ready, err
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (d *Daemon) acceptedSeq() protocol.Counter {
	raw, err := d.mgr.Store().Cursor(vault.CursorRecords)
	if err != nil {
		return 0
	}
	seq, err := protocol.ParseCounter(raw)
	if err != nil {
		return 0
	}
	return seq
}
