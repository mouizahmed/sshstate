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

func (d *Daemon) renderable() ([]sshconfig.Host, error) {
	hosts, err := d.mgr.Hosts()
	if err != nil {
		return nil, err
	}
	keys, err := d.mgr.Keys()
	if err != nil {
		return nil, err
	}
	byID := make(map[protocol.ID]vault.KeyView, len(keys))
	for _, k := range keys {
		byID[k.RecordID] = k
	}

	out := make([]sshconfig.Host, 0, len(hosts))
	for _, h := range hosts {
		gen := sshconfig.Host{
			Alias:     h.Alias,
			HostName:  h.HostName,
			User:      h.User,
			Port:      h.Port,
			ProxyJump: h.ProxyJump,
		}
		for i, id := range h.KeyIDs {
			k, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("host %q references key %s, which is not in the vault", h.Alias, id)
			}
			digest, err := sshkeys.PublicKeyDigest(k.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("host %q key %s: %w", h.Alias, id, err)
			}
			gen.Identities = append(gen.Identities, sshconfig.Identity{
				Slot:      i + 1,
				Digest:    digest,
				PublicKey: k.PublicKey,
			})
		}
		out = append(out, gen)
	}
	if err := checkJumpGraph(out); err != nil {
		return nil, err
	}
	return out, nil
}

func checkJumpGraph(hosts []sshconfig.Host) error {
	next := make(map[string]string, len(hosts))
	known := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		known[h.Alias] = true
		if h.ProxyJump != nil {
			next[h.Alias] = *h.ProxyJump
		}
	}
	for alias := range next {
		seen := map[string]bool{}
		for at := alias; ; {
			if seen[at] {
				return fmt.Errorf("ProxyJump chain starting at %q is a cycle", alias)
			}
			seen[at] = true
			jump, ok := next[at]
			if !ok {
				break
			}
			if !known[jump] {
				return fmt.Errorf("host %q jumps through %q, which is not a host in this vault", at, jump)
			}
			at = jump
		}
	}
	return nil
}

func (d *Daemon) regenerate() error {
	hosts, err := d.renderable()
	if err != nil {
		return err
	}
	return sshconfig.Publish(hosts, d.layout)
}

func (d *Daemon) handleGenerate(w http.ResponseWriter, r *http.Request) {
	hosts, err := d.renderable()
	if err != nil {
		writeError(w, err)
		return
	}
	if err := sshconfig.Publish(hosts, d.layout); err != nil {
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
