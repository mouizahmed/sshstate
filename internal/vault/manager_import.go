// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

type ImportAction string

const (
	ImportCreated   ImportAction = "created"
	ImportUnchanged ImportAction = "unchanged"
	ImportConflict  ImportAction = "conflict"
)

type ImportOutcome struct {
	Alias    string
	Action   ImportAction
	RecordID protocol.ID
	Detail   string
}

func (m *Manager) ImportHosts(specs []HostSpec, dryRun bool) ([]ImportOutcome, error) {
	var outcomes []ImportOutcome
	err := m.mutate(func(s *session, w *Writer, r *Reader) error {
		outcomes = nil
		hosts, err := m.hostsLocked(r)
		if err != nil {
			return err
		}
		keys, err := m.keysLocked(r)
		if err != nil {
			return err
		}
		known := make(map[protocol.ID]bool, len(keys))
		for _, k := range keys {
			known[k.RecordID] = true
		}
		existing := make(map[string]HostView, len(hosts))
		for _, h := range hosts {
			existing[h.Alias] = h
		}

		payloads := make([]*HostPayload, 0, len(specs))
		seen := map[string]bool{}
		var problems []string
		for _, spec := range specs {
			if seen[spec.Alias] {
				problems = append(problems, fmt.Sprintf("host %q appears twice in the import", spec.Alias))
				continue
			}
			seen[spec.Alias] = true
			port := spec.Port
			if port == 0 {
				port = DefaultPort
			}
			p := &HostPayload{
				FormatVersion: PayloadFormatVersion,
				Alias:         spec.Alias,
				HostName:      spec.HostName,
				User:          spec.User,
				Port:          port,
				ProxyJump:     spec.ProxyJump,
				KeyIDs:        spec.KeyIDs,
			}
			if err := p.Validate(); err != nil {
				problems = append(problems, err.Error())
				continue
			}
			for _, id := range p.KeyIDs {
				if !known[id] {
					problems = append(problems, fmt.Sprintf("host %q references key %s, which is not in the vault", p.Alias, id))
				}
			}
			payloads = append(payloads, p)
		}
		for _, p := range payloads {
			if p.ProxyJump == nil {
				continue
			}
			if _, ok := existing[*p.ProxyJump]; ok {
				continue
			}
			if !seen[*p.ProxyJump] {
				problems = append(problems, fmt.Sprintf("host %q jumps through %q, which is neither in the vault nor in this import", p.Alias, *p.ProxyJump))
			}
		}
		jumps := make(map[string]*string, len(existing)+len(payloads))
		for alias, h := range existing {
			jumps[alias] = h.ProxyJump
		}
		for _, p := range payloads {
			if _, ok := existing[p.Alias]; !ok {
				jumps[p.Alias] = p.ProxyJump
			}
		}
		for _, p := range payloads {
			if _, ok := existing[p.Alias]; ok || p.ProxyJump == nil {
				continue
			}
			if jumpCycle(p.Alias, jumps) {
				problems = append(problems, fmt.Sprintf("host %q is part of a ProxyJump loop", p.Alias))
			}
		}
		if len(problems) > 0 {
			return fmt.Errorf("nothing was imported:\n  %s", strings.Join(problems, "\n  "))
		}

		var envelopes []*protocol.Envelope
		for _, p := range payloads {
			current, ok := existing[p.Alias]
			if !ok {
				recordID, err := protocol.NewID()
				if err != nil {
					return err
				}
				mutationID, err := protocol.NewID()
				if err != nil {
					return err
				}
				env, err := w.Seal(Mutation{
					RecordID:   recordID,
					RecordType: protocol.RecordHost,
					Rev:        1,
					MutationID: mutationID,
				}, p)
				if err != nil {
					return err
				}
				envelopes = append(envelopes, env)
				outcomes = append(outcomes, ImportOutcome{Alias: p.Alias, Action: ImportCreated, RecordID: recordID})
				continue
			}
			if sameHost(current, p) {
				outcomes = append(outcomes, ImportOutcome{Alias: p.Alias, Action: ImportUnchanged, RecordID: current.RecordID})
				continue
			}
			candidate, err := json.Marshal(p)
			if err != nil {
				return err
			}
			duplicate, err := m.conflictAlreadyPreserved(r, current.RecordID, candidate)
			if err != nil {
				return err
			}
			if duplicate {
				outcomes = append(outcomes, ImportOutcome{
					Alias:    p.Alias,
					Action:   ImportConflict,
					RecordID: current.RecordID,
					Detail:   "already preserved; resolve it with: sshstate conflicts",
				})
				continue
			}
			env, err := m.preserveImported(w, current.RecordID, candidate)
			if err != nil {
				return err
			}
			envelopes = append(envelopes, env)
			outcomes = append(outcomes, ImportOutcome{
				Alias:    p.Alias,
				Action:   ImportConflict,
				RecordID: current.RecordID,
				Detail:   "the vault's version was kept; review with: sshstate conflicts",
			})
		}
		if dryRun {
			return nil
		}
		for _, env := range envelopes {
			if err := m.store.ApplyLocal(env); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return outcomes, nil
}

func sameHost(h HostView, p *HostPayload) bool {
	if h.HostName != p.HostName || h.User != p.User || h.Port != p.Port {
		return false
	}
	if (h.ProxyJump == nil) != (p.ProxyJump == nil) {
		return false
	}
	if h.ProxyJump != nil && *h.ProxyJump != *p.ProxyJump {
		return false
	}
	if len(h.KeyIDs) != len(p.KeyIDs) {
		return false
	}
	for i := range h.KeyIDs {
		if h.KeyIDs[i] != p.KeyIDs[i] {
			return false
		}
	}
	return true
}

func (m *Manager) conflictAlreadyPreserved(r *Reader, sourceID protocol.ID, candidate []byte) (bool, error) {
	envs, err := m.store.LiveRecords(protocol.RecordConflictMetadata)
	if err != nil {
		return false, err
	}
	for _, env := range envs {
		var p ConflictPayload
		if err := r.Open(env, &p); err != nil {
			return false, err
		}
		if p.SourceRecordID != sourceID {
			continue
		}
		same, err := sameCanonicalJSON(p.Candidate, candidate)
		if err != nil {
			return false, err
		}
		if same {
			return true, nil
		}
	}
	return false, nil
}

func sameCanonicalJSON(a, b []byte) (bool, error) {
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false, err
	}
	ca, err := protocol.Canonical(av)
	if err != nil {
		return false, err
	}
	cb, err := protocol.Canonical(bv)
	if err != nil {
		return false, err
	}
	return string(ca) == string(cb), nil
}

func (m *Manager) preserveImported(w *Writer, sourceID protocol.ID, candidate []byte) (*protocol.Envelope, error) {
	head, headDigest, err := m.store.Head(sourceID)
	if err != nil {
		return nil, err
	}
	candidateMutation, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	conflictID, err := protocol.ConflictID(m.vaultID, sourceID, candidateMutation)
	if err != nil {
		return nil, err
	}
	payload := &ConflictPayload{
		FormatVersion:      PayloadFormatVersion,
		SourceRecordID:     sourceID,
		SourceRecordType:   head.Context.RecordType,
		SourceMutationID:   candidateMutation,
		ObservedHeadDigest: headDigest,
		PreservedAt:        stampOf(m.clock()),
		Candidate:          candidate,
	}
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	rev := protocol.Counter(1)
	var parent []byte
	if prior, digest, err := m.store.Head(conflictID); err == nil {
		rev = prior.Context.Rev + 1
		parent = digest
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	mutationID, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	return w.Seal(Mutation{
		RecordID:     conflictID,
		RecordType:   protocol.RecordConflictMetadata,
		Rev:          rev,
		ParentDigest: parent,
		MutationID:   mutationID,
	}, payload)
}
