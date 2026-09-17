// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/sshkeys"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+control.RouteStatus, d.handleStatus)
	mux.HandleFunc("POST "+control.RouteUnlock, d.handleUnlock)
	mux.HandleFunc("POST "+control.RoutePassword, d.handleChangePassword)
	mux.HandleFunc("POST "+control.RouteLock, d.handleLock)
	mux.HandleFunc("GET "+control.RouteHosts, d.handleListHosts)
	mux.HandleFunc("POST "+control.RouteHosts, d.handleAddHost)
	mux.HandleFunc("POST "+control.RouteHostEdit, d.handleEditHost)
	mux.HandleFunc("POST "+control.RouteImport, d.handleImport)
	mux.HandleFunc("POST "+control.RouteHostRemove, d.handleRemoveHost)
	mux.HandleFunc("POST "+control.RouteKeyRemove, d.handleRemoveKey)
	mux.HandleFunc("GET "+control.RouteKeys, d.handleListKeys)
	mux.HandleFunc("POST "+control.RouteKeys, d.handleAddKey)
	mux.HandleFunc("POST "+control.RouteGenerate, d.handleGenerate)
	mux.HandleFunc("GET "+control.RouteDoctor, d.handleDoctor)
	mux.HandleFunc("GET "+control.RouteTrust, d.handleTrustPreview)
	mux.HandleFunc("POST "+control.RouteTrustImport, d.handleTrustImport)
	mux.HandleFunc("GET "+control.RouteTrustList, d.handleTrustList)
	mux.HandleFunc("POST "+control.RouteTrustApprove, d.handleTrustApprove)
	mux.HandleFunc("POST "+control.RouteTrustRevoke, d.handleTrustRevoke)
	mux.HandleFunc("POST "+control.RouteRecoveryChallenge, d.handleRecoveryChallenge)
	mux.HandleFunc("POST "+control.RouteRecoveryConfirm, d.handleRecoveryConfirm)
	mux.HandleFunc("POST "+control.RouteConnect, d.handleConnect)
	mux.HandleFunc("POST "+control.RouteSync, d.handleSync)
	mux.HandleFunc("GET "+control.RouteDevices, d.handleDevices)
	mux.HandleFunc("POST "+control.RouteRevoke, d.handleRevoke)
	mux.HandleFunc("POST "+control.RouteExport, d.handleExport)
	mux.HandleFunc("GET "+control.RouteConflicts, d.handleConflicts)
	mux.HandleFunc("POST "+control.RouteResolve, d.handleResolve)
	mux.HandleFunc("POST "+control.RoutePairApprove, d.handlePairApprove)
	mux.HandleFunc("POST "+control.RoutePairDeliver, d.handlePairDeliver)
	mux.HandleFunc("POST "+control.RouteShutdown, d.handleShutdown)
	return d.logRequests(mux)
}

func (d *Daemon) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		d.log.Debug("control request", "method", r.Method, "path", r.URL.Path, "status", rec.status)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vault.ErrLocked):
		writeJSON(w, http.StatusConflict, control.Error{Error: err.Error(), Code: control.CodeLocked})
	case errors.Is(err, vault.ErrRecoveryUnconfirmed):
		writeJSON(w, http.StatusConflict, control.Error{Error: err.Error(), Code: control.CodeRecoveryUnconfirmed})
	case errors.Is(err, vault.ErrNotInitialized):
		writeJSON(w, http.StatusConflict, control.Error{Error: err.Error(), Code: control.CodeNotInitialized})
	case errors.Is(err, vault.ErrParentMismatch):
		writeJSON(w, http.StatusConflict, control.Error{Error: err.Error(), Code: control.CodeConflict})
	default:
		writeJSON(w, http.StatusBadRequest, control.Error{Error: err.Error(), Code: control.CodeBadRequest})
	}
}

func decode(r *http.Request, out any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, control.MaxRequestBytes+1))
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if len(body) > control.MaxRequestBytes {
		return fmt.Errorf("request body exceeds %d bytes", control.MaxRequestBytes)
	}
	if len(body) == 0 {
		return errors.New("request body is empty")
	}
	return protocol.StrictUnmarshal(body, out)
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	st, err := d.mgr.Status()
	if err != nil {
		writeError(w, err)
		return
	}
	installed, err := sshconfig.IsInstalled(d.layout)
	if err != nil {
		writeError(w, err)
		return
	}
	var issues []control.HostIssue
	if st.Unlocked {
		if _, found, err := d.renderable(); err == nil {
			issues = found
		}
	}
	writeJSON(w, http.StatusOK, control.StatusResponse{
		VaultID:           string(st.VaultID),
		DeviceID:          string(st.DeviceID),
		DeviceLabel:       st.DeviceLabel,
		Unlocked:          st.Unlocked,
		KeyEpoch:          st.KeyEpoch.String(),
		RecoveryConfirmed: st.RecoveryConfirmed,
		IdleExpiresAt:     st.IdleExpiresAt,
		HardExpiresAt:     st.HardExpiresAt,
		Hosts:             st.Hosts,
		Keys:              st.Keys,
		KnownHosts:        st.KnownHosts,
		Pending:           st.Pending,
		Relay:             st.Relay,
		LastExportPath:    st.LastExportPath,
		LastExportAt:      st.LastExportAt,
		ConfigInstalled:   installed,
		ConfigPath:        d.layout.Config(),
		AgentSocket:       d.layout.AgentSocket(),
		Issues:            issues,
		RevokedHere:       d.revokedHere(),
	})
}

func (d *Daemon) revokedHere() bool {
	notice, err := d.mgr.Store().Meta(vault.MetaRevokedNotice)
	return err == nil && notice == "true"
}

func (d *Daemon) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req control.ChangePasswordRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	current, next := []byte(req.Current), []byte(req.Next)
	err := d.mgr.ChangePassword(current, next)
	clear(current)
	clear(next)
	if errors.Is(err, vault.ErrWrongPassword) {
		writeJSON(w, http.StatusUnauthorized, control.Error{Error: "the current password is wrong", Code: control.CodeBadRequest})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (d *Daemon) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req control.UnlockRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	password := []byte(req.Password)
	err := d.mgr.Unlock(password)
	clear(password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, control.Error{
			Error: "unlock failed: wrong password, or this vault does not belong to this device",
			Code:  control.CodeBadRequest,
		})
		return
	}
	if _, err := d.reconcileCapture(); err != nil {
		d.log.Warn("capture reconciliation failed after unlock", "error", err)
	}
	d.handleStatus(w, r)
}

func (d *Daemon) handleLock(w http.ResponseWriter, r *http.Request) {
	d.mgr.Lock()
	d.agent.Forget()
	d.handleStatus(w, r)
}

func (d *Daemon) handleListKeys(w http.ResponseWriter, r *http.Request) {
	views, err := d.mgr.Keys()
	if err != nil {
		writeError(w, err)
		return
	}
	items := make([]control.KeyResponse, 0, len(views))
	for _, v := range views {
		items = append(items, control.KeyResponse{
			RecordID:    string(v.RecordID),
			Fingerprint: v.Fingerprint,
			Algorithm:   v.Algorithm,
			Comment:     v.Comment,
			PublicKey:   v.PublicKey,
		})
	}
	writeJSON(w, http.StatusOK, control.ListResponse[control.KeyResponse]{Items: items})
}

func (d *Daemon) handleAddKey(w http.ResponseWriter, r *http.Request) {
	var req control.AddKeyRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	passphrase := []byte(req.Passphrase)
	k, err := sshkeys.Import([]byte(req.PrivateKey), passphrase, req.Comment)
	clear(passphrase)
	if err != nil {
		if errors.Is(err, sshkeys.ErrPassphraseRequired) {
			writeJSON(w, http.StatusUnauthorized, control.Error{
				Error: err.Error(), Code: control.CodeBadRequest,
			})
			return
		}
		writeError(w, err)
		return
	}
	id, err := d.mgr.AddKey(k)
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, control.KeyResponse{
		RecordID:    string(id),
		Fingerprint: k.Fingerprint,
		Algorithm:   k.Algorithm,
		Comment:     k.Comment,
		PublicKey:   k.PublicKey,
	})
}

func (d *Daemon) handleListHosts(w http.ResponseWriter, r *http.Request) {
	views, err := d.mgr.Hosts()
	if err != nil {
		writeError(w, err)
		return
	}
	_, issues, err := d.renderable()
	if err != nil {
		writeError(w, err)
		return
	}
	items := make([]control.HostResponse, 0, len(views))
	for _, v := range views {
		item := hostResponse(v)
		for _, issue := range issues {
			if issue.RecordID == item.RecordID {
				item.Issues = append(item.Issues, issue)
			}
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, control.ListResponse[control.HostResponse]{Items: items})
}

func hostResponse(v vault.HostView) control.HostResponse {
	ids := make([]string, 0, len(v.KeyIDs))
	for _, id := range v.KeyIDs {
		ids = append(ids, string(id))
	}
	return control.HostResponse{
		RecordID:  string(v.RecordID),
		Alias:     v.Alias,
		HostName:  v.HostName,
		User:      v.User,
		Port:      v.Port,
		ProxyJump: v.ProxyJump,
		KeyIDs:    ids,
	}
}

func (d *Daemon) handleAddHost(w http.ResponseWriter, r *http.Request) {
	var req control.AddHostRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	ids := make([]protocol.ID, 0, len(req.KeyIDs))
	for _, raw := range req.KeyIDs {
		id := protocol.ID(raw)
		if !id.Valid() {
			writeError(w, fmt.Errorf("key id %q is malformed", raw))
			return
		}
		ids = append(ids, id)
	}
	id, err := d.mgr.AddHost(vault.HostSpec{
		Alias:     strings.TrimSpace(req.Alias),
		HostName:  strings.TrimSpace(req.HostName),
		User:      strings.TrimSpace(req.User),
		Port:      req.Port,
		ProxyJump: req.ProxyJump,
		KeyIDs:    ids,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	hosts, err := d.mgr.Hosts()
	if err != nil {
		writeError(w, err)
		return
	}
	for _, h := range hosts {
		if h.RecordID == id {
			writeJSON(w, http.StatusCreated, hostResponse(h))
			return
		}
	}
	writeError(w, errors.New("host was created but could not be read back"))
}

func (d *Daemon) handleEditHost(w http.ResponseWriter, r *http.Request) {
	var req control.EditHostRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	recordID := protocol.ID(req.RecordID)
	if !recordID.Valid() {
		writeError(w, fmt.Errorf("%q is not a record id", req.RecordID))
		return
	}
	edit := vault.HostEdit{Port: req.Port}
	if req.Alias != nil {
		edit.Alias = trimmed(*req.Alias)
	}
	if req.HostName != nil {
		edit.HostName = trimmed(*req.HostName)
	}
	if req.User != nil {
		edit.User = trimmed(*req.User)
	}
	if req.ProxyJump != nil {
		edit.ProxyJump = trimmed(*req.ProxyJump)
	}
	if req.KeyIDs != nil {
		ids := make([]protocol.ID, 0, len(*req.KeyIDs))
		for _, raw := range *req.KeyIDs {
			id := protocol.ID(raw)
			if !id.Valid() {
				writeError(w, fmt.Errorf("key id %q is malformed", raw))
				return
			}
			ids = append(ids, id)
		}
		edit.KeyIDs = &ids
	}
	if err := d.mgr.EditHost(recordID, edit); err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	hosts, err := d.mgr.Hosts()
	if err != nil {
		writeError(w, err)
		return
	}
	for _, h := range hosts {
		if h.RecordID == recordID {
			writeJSON(w, http.StatusOK, hostResponse(h))
			return
		}
	}
	writeError(w, errors.New("host was edited but could not be read back"))
}

func (d *Daemon) handleImport(w http.ResponseWriter, r *http.Request) {
	var req control.ImportRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.Hosts) == 0 {
		writeError(w, errors.New("the import names no hosts"))
		return
	}
	specs := make([]vault.HostSpec, 0, len(req.Hosts))
	for _, h := range req.Hosts {
		ids := make([]protocol.ID, 0, len(h.KeyIDs))
		for _, raw := range h.KeyIDs {
			id := protocol.ID(raw)
			if !id.Valid() {
				writeError(w, fmt.Errorf("key id %q is malformed", raw))
				return
			}
			ids = append(ids, id)
		}
		specs = append(specs, vault.HostSpec{
			Alias:     strings.TrimSpace(h.Alias),
			HostName:  strings.TrimSpace(h.HostName),
			User:      strings.TrimSpace(h.User),
			Port:      h.Port,
			ProxyJump: h.ProxyJump,
			KeyIDs:    ids,
		})
	}
	outcomes, err := d.mgr.ImportHosts(specs, req.DryRun)
	if err != nil {
		writeError(w, err)
		return
	}
	if !req.DryRun {
		if _, err := d.regenerate(); err != nil {
			writeError(w, err)
			return
		}
	}
	out := control.ImportResponse{DryRun: req.DryRun}
	for _, o := range outcomes {
		out.Outcomes = append(out.Outcomes, control.ImportOutcome{
			Alias:    o.Alias,
			Action:   string(o.Action),
			RecordID: o.RecordID.String(),
			Detail:   o.Detail,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleRemoveHost(w http.ResponseWriter, r *http.Request) {
	id, ok := removeSubject(w, r)
	if !ok {
		return
	}
	hosts, err := d.mgr.Hosts()
	if err != nil {
		writeError(w, err)
		return
	}
	subject := ""
	for _, h := range hosts {
		if h.RecordID == id {
			subject = h.Alias
		}
	}
	if err := d.mgr.RemoveHost(id); err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.RemoveResponse{RecordID: id.String(), Subject: subject})
}

func (d *Daemon) handleRemoveKey(w http.ResponseWriter, r *http.Request) {
	id, ok := removeSubject(w, r)
	if !ok {
		return
	}
	keys, err := d.mgr.Keys()
	if err != nil {
		writeError(w, err)
		return
	}
	subject := ""
	for _, k := range keys {
		if k.RecordID == id {
			subject = k.Fingerprint
		}
	}
	if err := d.mgr.RemoveKey(id); err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.RemoveResponse{RecordID: id.String(), Subject: subject})
}

func removeSubject(w http.ResponseWriter, r *http.Request) (protocol.ID, bool) {
	var req control.RemoveRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return "", false
	}
	id := protocol.ID(req.RecordID)
	if !id.Valid() {
		writeError(w, fmt.Errorf("%q is not a record id", req.RecordID))
		return "", false
	}
	return id, true
}

func trimmed(s string) *string {
	t := strings.TrimSpace(s)
	return &t
}

func (d *Daemon) handleShutdown(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
	go d.Shutdown()
}
