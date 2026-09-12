// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/knownhosts"
	"github.com/mouizahmed/sshstate/internal/vault"
)

type candidate struct {
	entry        knownhosts.Entry
	destinations []string
	aliases      []string
	status       string
	note         string
}

func (d *Daemon) trustPreview() (*control.TrustPreviewResponse, []candidate, error) {
	hosts, err := d.mgr.Hosts()
	if err != nil {
		return nil, nil, err
	}
	stored, err := d.mgr.KnownHosts()
	if err != nil {
		return nil, nil, err
	}
	source := d.layout.UserKnownHosts()
	entries, problems, err := knownhosts.ParseFile(source)
	if err != nil {
		return nil, nil, err
	}

	aliasesFor := map[string][]string{}
	var addresses []string
	for _, h := range hosts {
		addr := knownhosts.Destination(h.HostName, h.Port)
		if _, ok := aliasesFor[addr]; !ok {
			addresses = append(addresses, addr)
		}
		aliasesFor[addr] = append(aliasesFor[addr], h.Alias)
	}
	sort.Strings(addresses)

	haveDigest := make(map[string]bool, len(stored))
	for _, s := range stored {
		haveDigest[hex.EncodeToString(s.LineDigest)] = true
	}

	resp := &control.TrustPreviewResponse{SourcePath: source}
	for _, p := range problems {
		resp.Problems = append(resp.Problems, p.String())
	}

	var candidates []candidate
	for _, e := range entries {
		c := candidate{entry: e}
		for _, addr := range addresses {
			if e.Matches(addr) {
				c.destinations = append(c.destinations, addr)
				c.aliases = append(c.aliases, aliasesFor[addr]...)
			}
		}
		if len(c.destinations) == 0 {
			if e.Hashed {
				resp.Opaque++
			} else {
				resp.Unrelated++
			}
			continue
		}
		digest := hex.EncodeToString(e.Digest[:])
		switch {
		case haveDigest[digest]:
			c.status = control.TrustStatusImported
			c.note = "already in the vault"
		default:
			c.status = control.TrustStatusNew
			if conflict := conflictWith(e, c.destinations, stored); conflict != "" {
				c.status = control.TrustStatusConflict
				c.note = conflict
			}
		}
		if e.Marker == knownhosts.MarkerRevoked {
			c.note = appendNote(c.note, "revoked key: importing preserves the prohibition")
		}
		if e.Marker == knownhosts.MarkerCertAuthority {
			c.note = appendNote(c.note, "certificate authority, not a single host key")
		}
		candidates = append(candidates, c)
		resp.Candidates = append(resp.Candidates, control.TrustCandidate{
			Digest:       digest,
			Line:         e.Line,
			LineNo:       e.LineNo,
			Destinations: c.destinations,
			Aliases:      c.aliases,
			KeyType:      e.KeyType,
			Fingerprint:  e.Fingerprint,
			Marker:       e.Marker,
			Status:       c.status,
			Note:         c.note,
		})
	}
	return resp, candidates, nil
}

func conflictWith(e knownhosts.Entry, destinations []string, stored []vault.KnownHostView) string {
	for _, s := range stored {
		if s.Status != vault.TrustApproved || s.KeyType != e.KeyType || s.Marker != e.Marker {
			continue
		}
		if s.Fingerprint == e.Fingerprint {
			continue
		}
		existing, err := knownhosts.ParseLine(s.Line)
		if err != nil {
			continue
		}
		for _, dest := range destinations {
			if existing.Matches(dest) {
				return fmt.Sprintf("%s already has an approved %s key with fingerprint %s",
					dest, s.KeyType, s.Fingerprint)
			}
		}
	}
	return ""
}

func appendNote(note, extra string) string {
	if note == "" {
		return extra
	}
	return note + "; " + extra
}

func (d *Daemon) handleTrustPreview(w http.ResponseWriter, r *http.Request) {
	resp, _, err := d.trustPreview()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Daemon) handleTrustImport(w http.ResponseWriter, r *http.Request) {
	var req control.TrustImportRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	_, candidates, err := d.trustPreview()
	if err != nil {
		writeError(w, err)
		return
	}
	byDigest := make(map[string]candidate, len(candidates))
	for _, c := range candidates {
		byDigest[hex.EncodeToString(c.entry.Digest[:])] = c
	}

	var specs []vault.KnownHostSpec
	var pending int
	seen := map[string]bool{}
	for _, digest := range req.Digests {
		c, ok := byDigest[digest]
		if !ok {
			writeError(w, fmt.Errorf("no reviewable known_hosts entry has digest %s; "+
				"the file changed since it was previewed", digest))
			return
		}
		if seen[digest] {
			continue
		}
		seen[digest] = true
		status := vault.TrustApproved
		if c.status == control.TrustStatusConflict {
			status = vault.TrustPending
			pending++
		}
		specs = append(specs, vault.KnownHostSpec{
			Line:        c.entry.Line,
			KeyType:     c.entry.KeyType,
			Fingerprint: c.entry.Fingerprint,
			Marker:      c.entry.Marker,
			Status:      status,
			LineDigest:  append([]byte(nil), c.entry.Digest[:]...),
		})
	}

	added, skipped, err := d.mgr.AddKnownHosts(specs)
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := d.regenerate(); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.TrustImportResponse{
		Imported:       added,
		Pending:        pending,
		Skipped:        skipped,
		KnownHostsPath: d.layout.KnownHosts(),
	})
}
