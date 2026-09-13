// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

func conflicted(t *testing.T) (*Manager, protocol.ID, protocol.ID) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	m, _, err := Init(store, InitOptions{Password: []byte("pw"), DeviceLabel: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryKitForTest(); err != nil {
		t.Fatal(err)
	}
	hostID, err := m.AddHost(HostSpec{Alias: "prod", HostName: "10.0.0.5", User: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}

	candidate := m.sealForTest(t, hostID, 2, headDigestOf(t, m, hostID), &HostPayload{
		FormatVersion: PayloadFormatVersion,
		Alias:         "prod", HostName: "10.0.0.99", User: "mine", Port: 22,
	}, false)
	winner := m.sealForTest(t, hostID, 2, headDigestOf(t, m, hostID), &HostPayload{
		FormatVersion: PayloadFormatVersion,
		Alias:         "prod", HostName: "10.0.0.50", User: "theirs", Port: 22,
	}, false)

	conflict, err := m.PreserveCandidate(candidate, winner)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveConflict(candidate.Context.MutationID, conflict, winner); err != nil {
		t.Fatal(err)
	}
	return m, hostID, conflict.Context.RecordID
}

func headDigestOf(t *testing.T, m *Manager, id protocol.ID) []byte {
	t.Helper()
	_, digest, err := m.store.Head(id)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func (m *Manager) sealForTest(t *testing.T, recordID protocol.ID, rev protocol.Counter, parent []byte, payload any, deleted bool) *protocol.Envelope {
	t.Helper()
	var out *protocol.Envelope
	err := m.read(func(s *session, r *Reader) error {
		w := m.writerFor(s)
		mutationID, err := protocol.NewID()
		if err != nil {
			return err
		}
		env, err := w.Seal(Mutation{
			RecordID:     recordID,
			RecordType:   protocol.RecordHost,
			Rev:          rev,
			ParentDigest: parent,
			MutationID:   mutationID,
			Deleted:      deleted,
		}, payload)
		out = env
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (m *Manager) ConfirmRecoveryKitForTest() error {
	return m.store.SetMeta(MetaRecoveryConfirmed, "true")
}

func TestResolveAppliesTheCandidateAndRetiresTheConflict(t *testing.T) {
	m, hostID, conflictID := conflicted(t)

	hosts, err := m.Hosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].HostName != "10.0.0.50" {
		t.Fatalf("unexpected head before resolving: %+v", hosts)
	}
	conflicts, err := m.Conflicts()
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 || conflicts[0].RecordID != conflictID {
		t.Fatalf("unexpected conflicts: %+v", conflicts)
	}

	source, err := m.ResolveConflict(conflictID, false)
	if err != nil {
		t.Fatal(err)
	}
	if source != hostID {
		t.Fatalf("resolve reported source %s, want %s", source, hostID)
	}

	hosts, err = m.Hosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].HostName != "10.0.0.99" || hosts[0].User != "mine" {
		t.Fatalf("the preserved edit was not applied: %+v", hosts)
	}
	head, _, err := m.store.Head(hostID)
	if err != nil {
		t.Fatal(err)
	}
	if head.Context.Rev != 3 {
		t.Fatalf("the resolved head is rev %s, want 3", head.Context.Rev)
	}
	pending, err := m.store.Outbox()
	if err != nil {
		t.Fatal(err)
	}
	var sawReplacement, sawRetirement bool
	for _, env := range pending {
		switch env.Context.RecordID {
		case hostID:
			sawReplacement = true
		case conflictID:
			sawRetirement = env.Context.Deleted
		}
	}
	if !sawReplacement || !sawRetirement {
		t.Fatalf("resolution was not queued for publication: %+v", pending)
	}

	conflicts, err = m.Conflicts()
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("the conflict was not retired: %+v", conflicts)
	}
	if _, err := m.ResolveConflict(conflictID, false); err == nil {
		t.Fatal("a retired conflict was resolved again")
	}
}

func TestResolveWillNotResurrectWithoutBeingTold(t *testing.T) {
	m, hostID, conflictID := conflicted(t)

	head, digest, err := m.store.Head(hostID)
	if err != nil {
		t.Fatal(err)
	}
	tombstone := m.sealForTest(t, hostID, head.Context.Rev+1, digest, nil, true)
	if err := m.store.ApplyLocalBatch(tombstone); err != nil {
		t.Fatal(err)
	}

	_, err = m.ResolveConflict(conflictID, false)
	if !errors.Is(err, ErrConflictSourceDeleted) {
		t.Fatalf("resolving into a deleted record returned %v", err)
	}
	conflicts, err := m.Conflicts()
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("the refused resolution retired the conflict anyway: %+v", conflicts)
	}

	if _, err := m.ResolveConflict(conflictID, true); err != nil {
		t.Fatal(err)
	}
	hosts, err := m.Hosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].HostName != "10.0.0.99" {
		t.Fatalf("the record did not come back with the kept edit: %+v", hosts)
	}
}
