package vault

import (
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

func (m *Manager) RemoveHost(recordID protocol.ID) error {
	return m.remove(recordID, protocol.RecordHost)
}

func (m *Manager) RemoveKey(recordID protocol.ID) error {
	return m.remove(recordID, protocol.RecordKey)
}

func (m *Manager) remove(recordID protocol.ID, want protocol.RecordType) error {
	return m.mutate(func(s *session, w *Writer, r *Reader) error {
		env, err := m.removal(w, r, recordID, want)
		if err != nil || env == nil {
			return err
		}
		return m.store.ApplyLocal(env)
	})
}

func (m *Manager) removal(w *Writer, r *Reader, recordID protocol.ID, want protocol.RecordType) (*protocol.Envelope, error) {
	noun := map[protocol.RecordType]string{protocol.RecordHost: "host", protocol.RecordKey: "key"}[want]
	if noun == "" {
		return nil, fmt.Errorf("%s records are not removed this way", want)
	}
	head, headDigest, err := m.store.Head(recordID)
	if err != nil {
		return nil, fmt.Errorf("no such %s %s: %w", noun, recordID, err)
	}
	if head.Context.RecordType != want {
		return nil, fmt.Errorf("record %s is not a %s", recordID, noun)
	}
	if head.Context.Deleted {
		return nil, nil
	}
	hosts, err := m.hostsLocked(r)
	if err != nil {
		return nil, err
	}
	switch want {
	case protocol.RecordHost:
		var payload HostPayload
		if err := r.Open(head, &payload); err != nil {
			return nil, err
		}
		var jumpers []string
		for _, h := range hosts {
			if h.RecordID != recordID && h.ProxyJump != nil && *h.ProxyJump == payload.Alias {
				jumpers = append(jumpers, h.Alias)
			}
		}
		if len(jumpers) > 0 {
			return nil, fmt.Errorf("host %q is the ProxyJump for %s; change or remove %s first",
				payload.Alias, strings.Join(jumpers, ", "), plural(len(jumpers), "that host", "those hosts"))
		}
	case protocol.RecordKey:
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
			return nil, fmt.Errorf("key %s is offered by %s; edit %s to remove that key first",
				recordID, strings.Join(users, ", "), plural(len(users), "that host", "those hosts"))
		}
	}
	mutationID, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	return w.Seal(Mutation{
		RecordID:     recordID,
		RecordType:   head.Context.RecordType,
		Rev:          head.Context.Rev + 1,
		ParentDigest: headDigest,
		MutationID:   mutationID,
		Deleted:      true,
	}, nil)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
