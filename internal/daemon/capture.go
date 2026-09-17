package daemon

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/protocol"

	"github.com/mouizahmed/sshstate/internal/knownhosts"
	"github.com/mouizahmed/sshstate/internal/vault"
)

type CaptureResult struct {
	Approved int
	Pending  int
	Skipped  int
	Ignored  int
}

func (d *Daemon) reconcileCapture() (CaptureResult, error) {
	var result CaptureResult
	if st, err := d.mgr.Status(); err != nil || !st.Unlocked {
		return result, err
	}
	raw, err := os.ReadFile(d.layout.CaptureFile())
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	text := string(raw)
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = text[:i+1]
	} else {
		return result, nil
	}

	entries, problems := knownhosts.Parse(text)
	result.Ignored = len(problems)

	hosts, err := d.mgr.Hosts()
	if err != nil {
		return result, err
	}
	destinations := make([]string, 0, len(hosts))
	for _, h := range hosts {
		destinations = append(destinations, knownhosts.Destination(h.HostName, h.Port))
	}

	stored, err := d.mgr.KnownHosts()
	if err != nil {
		return result, err
	}
	seen := make(map[string]bool, len(stored))
	approvedFor := map[string][]vault.KnownHostView{}
	for _, s := range stored {
		seen[string(s.LineDigest)] = true
		if s.Status == vault.TrustApproved {
			approvedFor[s.KeyType] = append(approvedFor[s.KeyType], s)
		}
	}

	var specs []vault.KnownHostSpec
	for _, e := range entries {
		matched := ""
		for _, dest := range destinations {
			if e.Matches(dest) {
				matched = dest
				break
			}
		}
		if matched == "" {
			result.Ignored++
			continue
		}
		digest := e.Digest
		if seen[string(digest[:])] || revokedFor(e, matched, approvedFor[e.KeyType]) {
			result.Skipped++
			continue
		}
		status := vault.TrustApproved
		if disagreesWithApproved(e, matched, approvedFor[e.KeyType]) {
			status = vault.TrustPending
		}
		if status == vault.TrustApproved {
			result.Approved++
			approvedFor[e.KeyType] = append(approvedFor[e.KeyType], vault.KnownHostView{
				Line:        e.Line,
				KeyType:     e.KeyType,
				Fingerprint: e.Fingerprint,
				Marker:      e.Marker,
				Status:      vault.TrustApproved,
			})
		} else {
			result.Pending++
		}
		seen[string(digest[:])] = true
		specs = append(specs, vault.KnownHostSpec{
			Line:        e.Line,
			KeyType:     e.KeyType,
			Fingerprint: e.Fingerprint,
			Marker:      e.Marker,
			Status:      status,
			LineDigest:  digest[:],
		})
	}
	if len(specs) == 0 {
		return result, nil
	}
	if _, _, err := d.mgr.AddKnownHosts(specs); err != nil {
		return CaptureResult{}, err
	}
	return result, nil
}

func revokedFor(e knownhosts.Entry, dest string, approved []vault.KnownHostView) bool {
	for _, a := range approved {
		if a.Marker != knownhosts.MarkerRevoked || a.Fingerprint != e.Fingerprint {
			continue
		}
		if prior, err := knownhosts.ParseLine(a.Line); err == nil && prior.Matches(dest) {
			return true
		}
	}
	return false
}

func disagreesWithApproved(e knownhosts.Entry, dest string, approved []vault.KnownHostView) bool {
	for _, a := range approved {
		if a.Fingerprint == e.Fingerprint {
			return false
		}
	}
	for _, a := range approved {
		prior, err := knownhosts.ParseLine(a.Line)
		if err != nil {
			continue
		}
		if prior.Marker != e.Marker {
			continue
		}
		if prior.Matches(dest) {
			return true
		}
	}
	return false
}

func (d *Daemon) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if _, err := d.reconcileCapture(); err != nil {
		d.log.Warn("capture reconciliation failed before listing trust", "error", err)
	}
	views, err := d.mgr.KnownHosts()
	if err != nil {
		writeError(w, err)
		return
	}
	hosts, err := d.mgr.Hosts()
	if err != nil {
		writeError(w, err)
		return
	}
	published := map[string]bool{}
	if _, lines, _, err := d.plan(); err == nil {
		for _, line := range lines {
			published[line] = true
		}
	}
	out := control.TrustListResponse{}
	for _, v := range views {
		var named []string
		if entry, err := knownhosts.ParseLine(v.Line); err == nil {
			for _, h := range hosts {
				if entry.Matches(knownhosts.Destination(h.HostName, h.Port)) {
					named = append(named, h.Alias)
				}
			}
		}
		out.Entries = append(out.Entries, control.TrustEntry{
			Withheld:    v.Status == vault.TrustApproved && !published[v.Line],
			Hosts:       named,
			RecordID:    v.RecordID.String(),
			Line:        v.Line,
			KeyType:     v.KeyType,
			Fingerprint: v.Fingerprint,
			Marker:      v.Marker,
			Status:      string(v.Status),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Daemon) handleTrustApprove(w http.ResponseWriter, r *http.Request) {
	var req control.TrustApproveRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	var ids []protocol.ID
	if req.All {
		views, err := d.mgr.KnownHosts()
		if err != nil {
			writeError(w, err)
			return
		}
		for _, v := range views {
			if v.Status == vault.TrustPending && v.Marker != "@revoked" {
				ids = append(ids, v.RecordID)
			}
		}
	}
	for _, raw := range req.RecordIDs {
		id := protocol.ID(raw)
		if !id.Valid() {
			writeError(w, fmt.Errorf("%q is not a record id", raw))
			return
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		writeError(w, errors.New("nothing to approve"))
		return
	}
	for _, id := range ids {
		if err := d.mgr.ApproveKnownHost(id); err != nil {
			writeError(w, err)
			return
		}
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.TrustApproveResponse{Approved: len(ids)})
}

func (d *Daemon) handleTrustRevoke(w http.ResponseWriter, r *http.Request) {
	var req control.TrustRevokeRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.RecordIDs) == 0 {
		writeError(w, errors.New("nothing to revoke"))
		return
	}
	for _, raw := range req.RecordIDs {
		id := protocol.ID(raw)
		if !id.Valid() {
			writeError(w, fmt.Errorf("%q is not a record id", raw))
			return
		}
		if err := d.mgr.RevokeKnownHost(id); err != nil {
			writeError(w, err)
			return
		}
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.TrustRevokeResponse{Revoked: len(req.RecordIDs)})
}
