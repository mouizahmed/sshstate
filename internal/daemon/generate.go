// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/sshkeys"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func (d *Daemon) renderable() ([]sshconfig.Host, []control.HostIssue, error) {
	hosts, err := d.mgr.Hosts()
	if err != nil {
		return nil, nil, err
	}
	keys, err := d.mgr.Keys()
	if err != nil {
		return nil, nil, err
	}
	return planHosts(hosts, keys)
}

func planHosts(hosts []vault.HostView, keys []vault.KeyView) ([]sshconfig.Host, []control.HostIssue, error) {
	byID := make(map[protocol.ID]vault.KeyView, len(keys))
	for _, k := range keys {
		byID[k.RecordID] = k
	}
	aliasCount := make(map[string]int, len(hosts))
	for _, h := range hosts {
		aliasCount[h.Alias]++
	}

	var issues []control.HostIssue
	report := func(h vault.HostView, omitted bool, problem, remedy string) {
		issues = append(issues, control.HostIssue{
			RecordID: string(h.RecordID),
			Alias:    h.Alias,
			Problem:  problem,
			Remedy:   remedy,
			Omitted:  omitted,
		})
	}
	subject := func(h vault.HostView) string {
		if aliasCount[h.Alias] > 1 {
			return string(h.RecordID)
		}
		return h.Alias
	}

	generated := make([]sshconfig.Host, len(hosts))
	omitted := make(map[protocol.ID]bool)
	unique := make(map[string]vault.HostView, len(hosts))
	for i, h := range hosts {
		gen := sshconfig.Host{
			Alias:     h.Alias,
			HostName:  h.HostName,
			User:      h.User,
			Port:      h.Port,
			ProxyJump: h.ProxyJump,
		}
		for _, id := range h.KeyIDs {
			k, ok := byID[id]
			if !ok {
				report(h, false, fmt.Sprintf("offers key %s, which is no longer in the vault", id),
					fmt.Sprintf("choose its keys again: sshstate edit %s --key <key>", subject(h)))
				continue
			}
			digest, err := sshkeys.PublicKeyDigest(k.PublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("host %q key %s: %w", h.Alias, id, err)
			}
			gen.Identities = append(gen.Identities, sshconfig.Identity{
				Slot:      len(gen.Identities) + 1,
				Digest:    digest,
				PublicKey: k.PublicKey,
			})
		}
		generated[i] = gen
		if aliasCount[h.Alias] > 1 {
			omitted[h.RecordID] = true
			report(h, true, fmt.Sprintf("shares the alias %q with another host, so ssh cannot tell them apart", h.Alias),
				fmt.Sprintf("rename one of them: sshstate edit %s --alias <new-alias>", h.RecordID))
			continue
		}
		unique[h.Alias] = h
	}

	for changed := true; changed; {
		changed = false
		for _, h := range hosts {
			if omitted[h.RecordID] || h.ProxyJump == nil {
				continue
			}
			jump := *h.ProxyJump
			target, ok := unique[jump]
			var problem string
			switch {
			case aliasCount[jump] > 1:
				problem = fmt.Sprintf("jumps through %q, which more than one host is named", jump)
			case !ok:
				problem = fmt.Sprintf("jumps through %q, which is not a host in this vault", jump)
			case jumpLoops(h, unique):
				problem = "is part of a ProxyJump loop"
			case omitted[target.RecordID]:
				problem = fmt.Sprintf("jumps through %q, which is itself left out of the SSH config", jump)
			default:
				continue
			}
			omitted[h.RecordID] = true
			changed = true
			report(h, true, problem, fmt.Sprintf("choose its jump host again: sshstate edit %s --jump <alias|none>", subject(h)))
		}
	}

	out := make([]sshconfig.Host, 0, len(hosts))
	for i, h := range hosts {
		if !omitted[h.RecordID] {
			out = append(out, generated[i])
		}
	}
	return out, issues, nil
}

func jumpLoops(start vault.HostView, unique map[string]vault.HostView) bool {
	seen := map[protocol.ID]bool{start.RecordID: true}
	for at := start; at.ProxyJump != nil; {
		next, ok := unique[*at.ProxyJump]
		if !ok {
			return false
		}
		if next.RecordID == start.RecordID {
			return true
		}
		if seen[next.RecordID] {
			return false
		}
		seen[next.RecordID] = true
		at = next
	}
	return false
}

func (d *Daemon) regenerate() ([]sshconfig.Host, error) {
	if _, err := d.reconcileCapture(); err != nil {
		d.log.Warn("capture reconciliation failed before generating", "error", err)
	}
	hosts, _, err := d.renderable()
	if err != nil {
		return nil, err
	}
	if err := sshconfig.Publish(hosts, d.layout); err != nil {
		return nil, err
	}
	lines, err := d.mgr.ApprovedTrustLines()
	if err != nil {
		return nil, err
	}
	if err := sshconfig.PublishKnownHosts(lines, d.layout); err != nil {
		return nil, err
	}
	return hosts, nil
}

func (d *Daemon) handleGenerate(w http.ResponseWriter, r *http.Request) {
	hosts, err := d.regenerate()
	if err != nil {
		writeError(w, err)
		return
	}
	stale, err := sshconfig.ObsoletePublicFiles(hosts, d.layout)
	if err != nil {
		writeError(w, err)
		return
	}
	var published []string
	for _, h := range hosts {
		for _, id := range h.Identities {
			published = append(published, h.PublicFileName(id))
		}
	}
	kept := make([]string, 0, len(stale))
	for _, p := range stale {
		kept = append(kept, filepath.Base(p))
	}
	writeJSON(w, http.StatusOK, control.GenerateResponse{
		ConfigPath:   d.layout.Config(),
		Hosts:        len(hosts),
		PublicFiles:  published,
		ObsoleteKept: kept,
	})
}
