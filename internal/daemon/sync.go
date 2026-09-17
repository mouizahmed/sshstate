// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/export"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relayclient"
	"github.com/mouizahmed/sshstate/internal/syncengine"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func (d *Daemon) relayClient(url string) (*relayclient.Client, error) {
	if url == "" {
		var err error
		url, err = d.mgr.RelayURL()
		if err != nil {
			return nil, err
		}
	}
	if url == "" {
		return nil, errors.New("this vault is not connected to a relay; run: sshstate connect <url>")
	}
	signer, err := d.mgr.RequestSigner()
	if err != nil {
		return nil, err
	}
	return relayclient.New(relayclient.Options{BaseURL: url, Signer: signer})
}

func (d *Daemon) engine(client *relayclient.Client) *syncengine.Engine {
	return &syncengine.Engine{
		Store:    d.mgr.Store(),
		Client:   client,
		Genesis:  d.mgr.Genesis(),
		Preserve: d.mgr.PreserveCandidate,
	}
}

func (d *Daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req control.ConnectRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.URL == "" {
		writeError(w, fmt.Errorf("a relay url is required"))
		return
	}
	client, err := d.relayClient(req.URL)
	if err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()

	out := control.ConnectResponse{URL: req.URL, VaultID: d.mgr.VaultID().String()}
	if req.BootstrapSecret != "" {
		current, err := d.mgr.RelayURL()
		if err != nil {
			writeError(w, err)
			return
		}
		if current != "" {
			writeError(w, fmt.Errorf("this vault already lives on %s; moving it to another relay is not supported\n"+
				"the bootstrap secret was not used\n"+
				"if that relay only moved to a new address, run: sshstate connect <new-url>", current))
			return
		}
		chain, err := d.chain()
		if err != nil {
			writeError(w, err)
			return
		}
		if chain.Len() > 1 {
			writeError(w, errors.New("this vault came from a restore, a recovery, or a pairing, so it cannot start a new relay\n"+
				"a new relay needs every host from its first revision, which only the machine that created the vault has before it first connects\n"+
				"the bootstrap secret was not used"))
			return
		}
		secret, err := protocol.DecodeBootstrapSecret(req.BootstrapSecret)
		if err != nil {
			writeError(w, fmt.Errorf("%v", err))
			return
		}
		root, err := d.membershipRoot()
		if err != nil {
			writeError(w, err)
			return
		}
		if _, err := client.Bootstrap(ctx, secret, d.mgr.Genesis(), root); err != nil {
			writeError(w, err)
			return
		}
		out.Bootstrap = true
		if err := d.mgr.SetRelayURL(req.URL); err != nil {
			writeError(w, err)
			return
		}
	}

	report, err := d.engine(client).Sync(ctx)
	if err != nil {
		writeError(w, err)
		return
	}
	if !out.Bootstrap {
		if err := d.mgr.SetRelayURL(req.URL); err != nil {
			writeError(w, err)
			return
		}
	}
	out.Uploaded = report.Pushed
	if err := d.refreshRecovery(ctx, client); err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) syncAndRefresh(ctx context.Context, client *relayclient.Client) (*syncengine.Report, error) {
	report, err := d.engine(client).Sync(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.refreshRecovery(ctx, client); err != nil {
		return nil, fmt.Errorf("synced, but the relay's recovery copy was not refreshed: %w", err)
	}
	return report, nil
}

func (d *Daemon) refreshRecovery(ctx context.Context, client *relayclient.Client) error {
	chain, err := d.chain()
	if err != nil {
		return err
	}
	cursor, err := d.mgr.Store().Cursor(vault.CursorRecords)
	if errors.Is(err, vault.ErrNotFound) {
		cursor = "0"
	} else if err != nil {
		return err
	}
	state := hex.EncodeToString(chain.HeadDigest()) + ":" + cursor
	if published, err := d.mgr.Store().Meta(vault.MetaRecoveryPublished); err == nil && published == state {
		return nil
	}
	if err := d.publishRecovery(ctx, client); err != nil {
		return err
	}
	return d.mgr.Store().SetMeta(vault.MetaRecoveryPublished, state)
}

func (d *Daemon) publishRecovery(ctx context.Context, client *relayclient.Client) error {
	sealed, _, err := d.buildExport()
	if err != nil {
		return err
	}
	return client.PutRecoveryArchive(ctx, 1, sealed)
}

func (d *Daemon) membershipRoot() (protocol.SignedMembershipEvent, error) {
	events, err := d.mgr.Store().MembershipEvents()
	if err != nil {
		return protocol.SignedMembershipEvent{}, err
	}
	if len(events) == 0 {
		return protocol.SignedMembershipEvent{}, errors.New("this vault has no membership chain")
	}
	return events[0], nil
}

func (d *Daemon) handleSync(w http.ResponseWriter, r *http.Request) {
	if _, err := d.reconcileCapture(); err != nil {
		d.log.Warn("capture reconciliation failed before sync", "error", err)
	}
	client, err := d.relayClient("")
	if err != nil {
		writeError(w, err)
		return
	}
	report, err := d.syncAndRefresh(r.Context(), client)
	if err != nil {
		writeError(w, err)
		return
	}
	if report.Complete {
		if _, err := d.regenerate(); err != nil {
			writeError(w, err)
			return
		}
	}
	_, issues, err := d.renderable()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.SyncResponse{
		Issues:    issues,
		Pushed:    report.Pushed,
		Preserved: report.Preserved,
		Applied:   report.Applied,
		Cursor:    report.Cursor.String(),
		Devices:   report.MembershipEvents,
		Learned:   report.MembershipLearned,
		Complete:  report.Complete,
	})
}

func (d *Daemon) chain() (*membership.Chain, error) {
	events, err := d.mgr.Store().MembershipEvents()
	if err != nil {
		return nil, err
	}
	return membership.Validate(d.mgr.Genesis(), events)
}

func (d *Daemon) handleDevices(w http.ResponseWriter, r *http.Request) {
	chain, err := d.chain()
	if err != nil {
		writeError(w, err)
		return
	}
	out := control.DevicesResponse{}
	for _, dev := range chain.Devices() {
		view := control.DeviceView{
			DeviceID:   dev.ID.String(),
			ThisDevice: dev.ID == d.mgr.DeviceID(),
			Status:     "active",
			EnrolledAt: dev.EnrolledAt,
			EnrolledBy: dev.EnrolledBy.String(),
			ChainSeq:   dev.EnrollSeq.String(),
		}
		if dev.Revoked {
			view.Status = "revoked"
			view.RevokedAt = dev.RevokedAt
			view.ChainSeq = dev.RevokeSeq.String()
		}
		out.Devices = append(out.Devices, view)
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req control.RevokeRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	target := protocol.ID(req.DeviceID)
	if !target.Valid() {
		writeError(w, fmt.Errorf("%q is not a device id", req.DeviceID))
		return
	}
	self := target == d.mgr.DeviceID()
	if self && !req.Confirm {
		writeError(w, fmt.Errorf("that is this device; pass --yes to deregister it"))
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
	ev, err := chain.Revoke(signer, target, d.mgr.Now())
	if err != nil {
		writeError(w, fmt.Errorf("%v", err))
		return
	}

	client, err := d.relayClient("")
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := client.AppendMembership(r.Context(), ev); err != nil {
		writeError(w, err)
		return
	}
	if self {
		next, err := chain.Append(ev)
		if err != nil {
			writeError(w, err)
			return
		}
		if err := d.mgr.Store().PutMembershipEvents(next.Events()); err != nil {
			writeError(w, err)
			return
		}
		if err := d.mgr.Store().PutDevice(vault.Device{
			ID:         target,
			VerifyKey:  mustDeviceKey(next, target),
			Recipient:  mustDeviceRecipient(next, target),
			Status:     vault.DeviceRevoked,
			EnrolledAt: mustDeviceEnrolledAt(next, target),
		}); err != nil {
			writeError(w, err)
			return
		}
	} else if _, err := d.syncAndRefresh(r.Context(), client); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.RevokeResponse{
		DeviceID:   target.String(),
		ChainSeq:   ev.Event.ChainSeq.String(),
		ThisDevice: self,
	})
}

func (d *Daemon) buildExport() ([]byte, *vault.ExportSnapshot, error) {
	snapshot, err := d.mgr.Snapshot(false)
	if err != nil {
		return nil, nil, err
	}
	chain, err := d.chain()
	if err != nil {
		return nil, nil, err
	}
	seq, err := d.mgr.Store().Cursor(vault.CursorRecords)
	cursor := protocol.Counter(0)
	if err == nil {
		cursor, err = protocol.ParseCounter(seq)
		if err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, vault.ErrNotFound) {
		return nil, nil, err
	}
	checkpoint, err := d.mgr.Checkpoint(chain.HeadDigest(), cursor, snapshot)
	if err != nil {
		return nil, nil, err
	}
	recipient, err := d.mgr.RecoveryRecipient()
	if err != nil {
		return nil, nil, err
	}
	bundle, err := d.mgr.RecoveryBundle(checkpoint)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := export.Build(export.Contents{
		Genesis:    d.mgr.Genesis(),
		Membership: chain.Events(),
		Records:    snapshot.Records,
		Conflicts:  snapshot.Conflicts,
		Bundle:     bundle,
	}, checkpoint, d.mgr.DeviceID(), exportSigner(d.mgr.SignExport), recipient,
		d.mgr.Now().UTC().Truncate(time.Second).Format(time.RFC3339))
	if err != nil {
		return nil, nil, err
	}
	return sealed, snapshot, nil
}

func (d *Daemon) handleExport(w http.ResponseWriter, r *http.Request) {
	sealed, snapshot, err := d.buildExport()
	if err != nil {
		writeError(w, err)
		return
	}
	if len(sealed) > control.MaxExportBytes {
		writeError(w, fmt.Errorf("this export is %d bytes, the limit is %d", len(sealed), control.MaxExportBytes))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(sealed)))
	w.Header().Set(control.HeaderExportRecords, strconv.Itoa(vault.LiveCount(snapshot.Records)))
	w.Header().Set(control.HeaderExportConflicts, strconv.Itoa(len(snapshot.Conflicts)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (d *Daemon) handleExportRecord(w http.ResponseWriter, r *http.Request) {
	var req control.ExportRecordRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Path == "" {
		writeError(w, fmt.Errorf("a destination path is required"))
		return
	}
	if err := d.mgr.RecordExport(req.Path); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (d *Daemon) handleConflicts(w http.ResponseWriter, r *http.Request) {
	conflicts, err := d.mgr.Conflicts()
	if err != nil {
		writeError(w, err)
		return
	}
	out := control.ConflictsResponse{}
	for _, c := range conflicts {
		out.Conflicts = append(out.Conflicts, control.ConflictView{
			RecordID:         c.RecordID.String(),
			SourceRecordID:   c.SourceRecordID.String(),
			SourceRecordType: string(c.SourceRecordType),
			PreservedAt:      c.PreservedAt,
			Subject:          c.Subject,
			Changes:          c.Changes,
			SourceRemoved:    c.SourceRemoved,
			Removal:          c.Removal,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type exportSigner func([]byte) ([]byte, error)

func (f exportSigner) Sign(domain string, msg []byte) ([]byte, error) {
	if domain != protocol.ExportSignatureDomain {
		return nil, fmt.Errorf("unexpected signing domain %q", domain)
	}
	return f(msg)
}

func (d *Daemon) handleResolve(w http.ResponseWriter, r *http.Request) {
	var req control.ResolveRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	id := protocol.ID(req.RecordID)
	if !id.Valid() {
		writeError(w, fmt.Errorf("%q is not a conflict record id", req.RecordID))
		return
	}
	var source protocol.ID
	var err error
	if req.Discard {
		source, err = d.mgr.DiscardConflict(id)
	} else {
		source, err = d.mgr.ResolveConflict(id, req.Resurrect)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.ResolveResponse{
		RecordID:       id.String(),
		SourceRecordID: source.String(),
	})
}

func mustDeviceKey(chain *membership.Chain, id protocol.ID) []byte {
	d, ok := chain.Device(id)
	if !ok {
		return nil
	}
	return d.VerifyKey.Bytes()
}

func mustDeviceRecipient(chain *membership.Chain, id protocol.ID) string {
	d, _ := chain.Device(id)
	return d.Recipient
}

func mustDeviceEnrolledAt(chain *membership.Chain, id protocol.ID) string {
	d, _ := chain.Device(id)
	return d.EnrolledAt
}
