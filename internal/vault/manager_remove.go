// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

func (m *Manager) RemoveHost(recordID protocol.ID) error {
	return m.mutate(func(s *session, w *Writer, r *Reader) error {
		head, headDigest, err := m.store.Head(recordID)
		if err != nil {
			return fmt.Errorf("no such host %s: %w", recordID, err)
		}
		if head.Context.RecordType != protocol.RecordHost {
			return fmt.Errorf("record %s is not a host", recordID)
		}
		if head.Context.Deleted {
			return nil
		}
		var payload HostPayload
		if err := r.Open(head, &payload); err != nil {
			return err
		}
		hosts, err := m.hostsLocked(r)
		if err != nil {
			return err
		}
		var jumpers []string
		for _, h := range hosts {
			if h.RecordID != recordID && h.ProxyJump != nil && *h.ProxyJump == payload.Alias {
				jumpers = append(jumpers, h.Alias)
			}
		}
		if len(jumpers) > 0 {
			return fmt.Errorf("host %q is the ProxyJump for %s; change or remove %s first",
				payload.Alias, strings.Join(jumpers, ", "), plural(len(jumpers), "that host", "those hosts"))
		}
		return m.tombstone(w, recordID, head.Context.RecordType, head.Context.Rev, headDigest)
	})
}

func (m *Manager) RemoveKey(recordID protocol.ID) error {
	return m.mutate(func(s *session, w *Writer, r *Reader) error {
		head, headDigest, err := m.store.Head(recordID)
		if err != nil {
			return fmt.Errorf("no such key %s: %w", recordID, err)
		}
		if head.Context.RecordType != protocol.RecordKey {
			return fmt.Errorf("record %s is not a key", recordID)
		}
		if head.Context.Deleted {
			return nil
		}
		hosts, err := m.hostsLocked(r)
		if err != nil {
			return err
		}
		var users []string
		for _, h := range hosts {
			for _, id := range h.KeyIDs {
				if id == recordID {
					users = append(users, h.Alias)
					break
				}
			}
		}
		if len(users) > 0 {
			return fmt.Errorf("key %s is offered by %s; remove it from %s first with: sshstate edit <alias> --key ...",
				recordID, strings.Join(users, ", "), plural(len(users), "that host", "those hosts"))
		}
		return m.tombstone(w, recordID, head.Context.RecordType, head.Context.Rev, headDigest)
	})
}

func (m *Manager) tombstone(w *Writer, recordID protocol.ID, recordType protocol.RecordType, rev protocol.Counter, parent []byte) error {
	mutationID, err := protocol.NewID()
	if err != nil {
		return err
	}
	env, err := w.Seal(Mutation{
		RecordID:     recordID,
		RecordType:   recordType,
		Rev:          rev + 1,
		ParentDigest: parent,
		MutationID:   mutationID,
		Deleted:      true,
	}, nil)
	if err != nil {
		return err
	}
	return m.store.ApplyLocal(env)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
