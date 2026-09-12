// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"encoding/base64"
	"net/http"

	"github.com/mouizahmed/sshstate/internal/control"
)

func (d *Daemon) handleRecoveryChallenge(w http.ResponseWriter, r *http.Request) {
	nonce, err := d.mgr.RecoveryChallenge()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.RecoveryChallengeResponse{
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	})
}

func (d *Daemon) handleRecoveryConfirm(w http.ResponseWriter, r *http.Request) {
	var req control.RecoveryConfirmRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil {
		writeError(w, err)
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := d.mgr.ConfirmRecoveryProof(nonce, signature); err != nil {
		writeError(w, err)
		return
	}
	d.handleStatus(w, r)
}
