// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"errors"
	"fmt"
	"sort"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/sshkeys"
)

func (m *Manager) verifier(device protocol.ID) (*crypto.VerifyKey, error) {
	d, err := m.store.Device(device)
	if err != nil {
		return nil, fmt.Errorf("not an enrolled device: %w", err)
	}
	return crypto.VerifyKeyFromBytes(d.VerifyKey)
}

func (m *Manager) writerFor(s *session) *Writer {
	return &Writer{VaultID: m.vaultID, DeviceID: m.deviceID, Signing: s.signing, Keys: s.keys}
}

func (m *Manager) readerFor(s *session) *Reader {
	return &Reader{VaultID: m.vaultID, Keys: s.keys, Verifier: m.verifier}
}

func (m *Manager) mutate(fn func(s *session, w *Writer, r *Reader) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.RecoveryConfirmed() {
		return ErrRecoveryUnconfirmed
	}
	s, err := m.session()
	if err != nil {
		return err
	}
	if err := fn(s, m.writerFor(s), m.readerFor(s)); err != nil {
		return err
	}
	m.current.idleDeadline = m.clock().Add(IdleTimeout)
	return nil
}

func (m *Manager) read(fn func(s *session, r *Reader) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.session()
	if err != nil {
		return err
	}
	return fn(s, m.readerFor(s))
}

type KeyView struct {
	RecordID    protocol.ID
	Fingerprint string
	Algorithm   string
	Comment     string
	PublicKey   string
}

type HostView struct {
	RecordID  protocol.ID
	Alias     string
	HostName  string
	User      string
	Port      int
	ProxyJump *string
	KeyIDs    []protocol.ID
}

func (m *Manager) AddKey(k *sshkeys.Key) (protocol.ID, error) {
	var id protocol.ID
	err := m.mutate(func(s *session, w *Writer, r *Reader) error {
		existing, err := m.keysLocked(r)
		if err != nil {
			return err
		}
		for _, e := range existing {
			if e.Fingerprint == k.Fingerprint {
				id = e.RecordID
				return fmt.Errorf("key %s is already in the vault as record %s", k.Fingerprint, e.RecordID)
			}
		}
		payload := &KeyPayload{
			FormatVersion: PayloadFormatVersion,
			PrivateKey:    k.PrivateKey,
			PublicKey:     k.PublicKey,
			Fingerprint:   k.Fingerprint,
			Algorithm:     k.Algorithm,
			Comment:       k.Comment,
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
			RecordType: protocol.RecordKey,
			Rev:        1,
			MutationID: mutationID,
		}, payload)
		if err != nil {
			return err
		}
		if err := m.store.ApplyLocal(env); err != nil {
			return err
		}
		id = recordID
		return nil
	})
	return id, err
}

type HostSpec struct {
	Alias     string
	HostName  string
	User      string
	Port      int
	ProxyJump *string
	KeyIDs    []protocol.ID
}

func (m *Manager) AddHost(spec HostSpec) (protocol.ID, error) {
	var id protocol.ID
	err := m.mutate(func(s *session, w *Writer, r *Reader) error {
		hosts, err := m.hostsLocked(r)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			if h.Alias == spec.Alias {
				return fmt.Errorf("host %q already exists as record %s", spec.Alias, h.RecordID)
			}
		}
		keys, err := m.keysLocked(r)
		if err != nil {
			return err
		}
		known := make(map[protocol.ID]bool, len(keys))
		for _, k := range keys {
			known[k.RecordID] = true
		}
		for _, id := range spec.KeyIDs {
			if !known[id] {
				return fmt.Errorf("host %q references key %s, which is not in the vault", spec.Alias, id)
			}
		}
		port := spec.Port
		if port == 0 {
			port = DefaultPort
		}
		payload := &HostPayload{
			FormatVersion: PayloadFormatVersion,
			Alias:         spec.Alias,
			HostName:      spec.HostName,
			User:          spec.User,
			Port:          port,
			ProxyJump:     spec.ProxyJump,
			KeyIDs:        spec.KeyIDs,
		}
		if err := payload.Validate(); err != nil {
			return err
		}
		if payload.ProxyJump != nil {
			found := false
			for _, h := range hosts {
				if h.Alias == *payload.ProxyJump {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("ProxyJump %q is not a host in this vault", *payload.ProxyJump)
			}
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
			RecordType: protocol.RecordHost,
			Rev:        1,
			MutationID: mutationID,
		}, payload)
		if err != nil {
			return err
		}
		if err := m.store.ApplyLocal(env); err != nil {
			return err
		}
		id = recordID
		return nil
	})
	return id, err
}

func (m *Manager) Hosts() ([]HostView, error) {
	var out []HostView
	err := m.read(func(s *session, r *Reader) error {
		var err error
		out, err = m.hostsLocked(r)
		return err
	})
	return out, err
}

func (m *Manager) Keys() ([]KeyView, error) {
	var out []KeyView
	err := m.read(func(s *session, r *Reader) error {
		var err error
		out, err = m.keysLocked(r)
		return err
	})
	return out, err
}

func (m *Manager) hostsLocked(r *Reader) ([]HostView, error) {
	envs, err := m.store.LiveRecords(protocol.RecordHost)
	if err != nil {
		return nil, err
	}
	out := make([]HostView, 0, len(envs))
	for _, env := range envs {
		var p HostPayload
		if err := r.Open(env, &p); err != nil {
			return nil, fmt.Errorf("host record %s: %w", env.Context.RecordID, err)
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("host record %s: %w", env.Context.RecordID, err)
		}
		out = append(out, HostView{
			RecordID:  env.Context.RecordID,
			Alias:     p.Alias,
			HostName:  p.HostName,
			User:      p.User,
			Port:      p.Port,
			ProxyJump: p.ProxyJump,
			KeyIDs:    p.KeyIDs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out, nil
}

func (m *Manager) keysLocked(r *Reader) ([]KeyView, error) {
	envs, err := m.store.LiveRecords(protocol.RecordKey)
	if err != nil {
		return nil, err
	}
	out := make([]KeyView, 0, len(envs))
	for _, env := range envs {
		var p KeyPayload
		if err := r.Open(env, &p); err != nil {
			return nil, fmt.Errorf("key record %s: %w", env.Context.RecordID, err)
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("key record %s: %w", env.Context.RecordID, err)
		}
		out = append(out, KeyView{
			RecordID:    env.Context.RecordID,
			Fingerprint: p.Fingerprint,
			Algorithm:   p.Algorithm,
			Comment:     p.Comment,
			PublicKey:   p.PublicKey,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, nil
}

func (m *Manager) PrivateKey(id protocol.ID) (string, error) {
	var out string
	err := m.read(func(s *session, r *Reader) error {
		env, _, err := m.store.Head(id)
		if err != nil {
			return err
		}
		if env.Context.RecordType != protocol.RecordKey {
			return errors.New("record is not a key")
		}
		if env.Context.Deleted {
			return fmt.Errorf("key %s has been deleted", id)
		}
		var p KeyPayload
		if err := r.Open(env, &p); err != nil {
			return err
		}
		out = p.PrivateKey
		return nil
	})
	return out, err
}
