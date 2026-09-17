package vault

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

type KnownHostView struct {
	RecordID    protocol.ID
	Line        string
	KeyType     string
	Fingerprint string
	Marker      string
	Status      TrustStatus
	LineDigest  []byte
}

type KnownHostSpec struct {
	Line        string
	KeyType     string
	Fingerprint string
	Marker      string
	Status      TrustStatus
	LineDigest  []byte
}

func (m *Manager) KnownHosts() ([]KnownHostView, error) {
	var out []KnownHostView
	err := m.read(func(s *session, r *Reader) error {
		var err error
		out, err = m.knownHostsLocked(r)
		return err
	})
	return out, err
}

func (m *Manager) AddKnownHosts(specs []KnownHostSpec) (added, skipped int, err error) {
	err = m.mutate(func(s *session, w *Writer, r *Reader) error {
		existing, err := m.knownHostsLocked(r)
		if err != nil {
			return err
		}
		have := make(map[string]bool, len(existing))
		for _, e := range existing {
			have[string(e.LineDigest)] = true
		}
		var envelopes []*protocol.Envelope
		for _, spec := range specs {
			if have[string(spec.LineDigest)] {
				skipped++
				continue
			}
			payload := &KnownHostPayload{
				FormatVersion: PayloadFormatVersion,
				Line:          spec.Line,
				KeyType:       spec.KeyType,
				Fingerprint:   spec.Fingerprint,
				Marker:        spec.Marker,
				Status:        spec.Status,
				LineDigest:    protocol.Bytes(spec.LineDigest),
			}
			if err := payload.Validate(); err != nil {
				return err
			}
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
				RecordType: protocol.RecordKnownHost,
				Rev:        1,
				MutationID: mutationID,
			}, payload)
			if err != nil {
				return err
			}
			envelopes = append(envelopes, env)
			have[string(spec.LineDigest)] = true
			added++
		}
		if err := m.store.ApplyLocalBatch(envelopes...); err != nil {
			added = 0
			return err
		}
		return nil
	})
	return added, skipped, err
}

func (m *Manager) ApprovedTrustLines() ([]string, error) {
	views, err := m.KnownHosts()
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, v := range views {
		if v.Status == TrustApproved {
			lines = append(lines, v.Line)
		}
	}
	sort.Strings(lines)
	return lines, nil
}

func (m *Manager) knownHostsLocked(r *Reader) ([]KnownHostView, error) {
	envs, err := m.store.LiveRecords(protocol.RecordKnownHost)
	if err != nil {
		return nil, err
	}
	out := make([]KnownHostView, 0, len(envs))
	for _, env := range envs {
		var p KnownHostPayload
		if err := r.Open(env, &p); err != nil {
			return nil, fmt.Errorf("known_host record %s: %w", env.Context.RecordID, err)
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("known_host record %s: %w", env.Context.RecordID, err)
		}
		out = append(out, KnownHostView{
			RecordID:    env.Context.RecordID,
			Line:        p.Line,
			KeyType:     p.KeyType,
			Fingerprint: p.Fingerprint,
			Marker:      p.Marker,
			Status:      p.Status,
			LineDigest:  p.LineDigest,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].LineDigest, out[j].LineDigest) < 0
	})
	return out, nil
}

func (m *Manager) ApproveKnownHost(recordID protocol.ID) error {
	return m.mutate(func(s *session, w *Writer, r *Reader) error {
		head, headDigest, err := m.store.Head(recordID)
		if err != nil {
			return fmt.Errorf("no such observation %s: %w", recordID, err)
		}
		if head.Context.RecordType != protocol.RecordKnownHost {
			return fmt.Errorf("record %s is not a host-key observation", recordID)
		}
		if head.Context.Deleted {
			return fmt.Errorf("observation %s was removed", recordID)
		}
		var payload KnownHostPayload
		if err := r.Open(head, &payload); err != nil {
			return err
		}
		if payload.Marker == "@revoked" {
			return fmt.Errorf("observation %s is @revoked; approving it would turn a prohibition into permission", recordID)
		}
		if payload.Status == TrustApproved {
			return nil
		}
		payload.Status = TrustApproved
		if err := payload.Validate(); err != nil {
			return err
		}
		mutationID, err := protocol.NewID()
		if err != nil {
			return err
		}
		env, err := w.Seal(Mutation{
			RecordID:     recordID,
			RecordType:   protocol.RecordKnownHost,
			Rev:          head.Context.Rev + 1,
			ParentDigest: headDigest,
			MutationID:   mutationID,
		}, &payload)
		if err != nil {
			return err
		}
		return m.store.ApplyLocal(env)
	})
}

func (m *Manager) RevokeKnownHost(recordID protocol.ID) error {
	return m.mutate(func(s *session, w *Writer, r *Reader) error {
		head, headDigest, err := m.store.Head(recordID)
		if err != nil {
			return fmt.Errorf("no such observation %s: %w", recordID, err)
		}
		if head.Context.RecordType != protocol.RecordKnownHost {
			return fmt.Errorf("record %s is not a host-key observation", recordID)
		}
		if head.Context.Deleted {
			return fmt.Errorf("observation %s was removed", recordID)
		}
		var payload KnownHostPayload
		if err := r.Open(head, &payload); err != nil {
			return err
		}
		if payload.Marker == "@revoked" && payload.Status == TrustApproved {
			return nil
		}
		fields := strings.Fields(payload.Line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
			fields = fields[1:]
		}
		payload.Line = strings.Join(append([]string{"@revoked"}, fields...), " ")
		payload.Marker = "@revoked"
		payload.Status = TrustApproved
		if err := payload.Validate(); err != nil {
			return err
		}
		mutationID, err := protocol.NewID()
		if err != nil {
			return err
		}
		env, err := w.Seal(Mutation{
			RecordID:     recordID,
			RecordType:   protocol.RecordKnownHost,
			Rev:          head.Context.Rev + 1,
			ParentDigest: headDigest,
			MutationID:   mutationID,
		}, &payload)
		if err != nil {
			return err
		}
		return m.store.ApplyLocal(env)
	})
}

func (m *Manager) SetKnownHostPending(recordID protocol.ID) error {
	return m.mutate(func(s *session, w *Writer, r *Reader) error {
		head, headDigest, err := m.store.Head(recordID)
		if err != nil {
			return err
		}
		var payload KnownHostPayload
		if err := r.Open(head, &payload); err != nil {
			return err
		}
		payload.Status = TrustPending
		if err := payload.Validate(); err != nil {
			return err
		}
		mutationID, err := protocol.NewID()
		if err != nil {
			return err
		}
		env, err := w.Seal(Mutation{
			RecordID:     recordID,
			RecordType:   protocol.RecordKnownHost,
			Rev:          head.Context.Rev + 1,
			ParentDigest: headDigest,
			MutationID:   mutationID,
		}, &payload)
		if err != nil {
			return err
		}
		return m.store.ApplyLocal(env)
	})
}
