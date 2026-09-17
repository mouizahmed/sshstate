// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/httpsig"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	MetaRelayURL          = "relay_url"
	MetaRecoveryPublished = "recovery_published"
	MetaRevokedNotice     = "revoked_notice"
)

func stampOf(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

func (m *Manager) RelayURL() (string, error) {
	url, err := m.store.Meta(MetaRelayURL)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	return url, err
}

const (
	MetaLastExportAt   = "last_export_at"
	MetaLastExportPath = "last_export_path"
)

func (m *Manager) RecordExport(path string) error {
	if err := m.store.SetMeta(MetaLastExportPath, path); err != nil {
		return err
	}
	return m.store.SetMeta(MetaLastExportAt, stampOf(m.clock()))
}

func (m *Manager) LastExport() (path, at string) {
	if p, err := m.store.Meta(MetaLastExportPath); err == nil {
		path = p
	}
	if a, err := m.store.Meta(MetaLastExportAt); err == nil {
		at = a
	}
	return path, at
}

func (m *Manager) SetRelayURL(url string) error { return m.store.SetMeta(MetaRelayURL, url) }

func (m *Manager) RequestSigner() (*httpsig.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.session()
	if err != nil {
		return nil, err
	}
	return &httpsig.Signer{
		VaultID:  m.vaultID,
		DeviceID: m.deviceID,
		Key:      s.signing,
	}, nil
}

func (m *Manager) PreserveCandidate(candidate, head *protocol.Envelope) (*protocol.Envelope, error) {
	if candidate == nil || head == nil {
		return nil, errors.New("preserve: both the candidate and the head it lost to are required")
	}
	var out *protocol.Envelope
	err := m.mutate(func(s *session, w *Writer, r *Reader) error {
		var plaintext json.RawMessage
		if err := r.Open(candidate, &plaintext); err != nil {
			return fmt.Errorf("preserve: read the rejected candidate: %w", err)
		}
		headDigest, err := head.Digest()
		if err != nil {
			return err
		}
		conflictID, err := protocol.ConflictID(m.vaultID,
			candidate.Context.RecordID, candidate.Context.MutationID)
		if err != nil {
			return err
		}
		payload := &ConflictPayload{
			FormatVersion:      PayloadFormatVersion,
			SourceRecordID:     candidate.Context.RecordID,
			SourceRecordType:   candidate.Context.RecordType,
			SourceMutationID:   candidate.Context.MutationID,
			ObservedHeadDigest: headDigest,
			PreservedAt:        stampOf(m.clock()),
			Candidate:          plaintext,
		}
		if err := payload.Validate(); err != nil {
			return err
		}

		rev := protocol.Counter(1)
		var parent []byte
		if existing, digest, err := m.store.Head(conflictID); err == nil {
			rev = existing.Context.Rev + 1
			parent = digest
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		mutationID, err := protocol.NewID()
		if err != nil {
			return err
		}
		env, err := w.Seal(Mutation{
			RecordID:     conflictID,
			RecordType:   ConflictType(candidate.Context.RecordType),
			Rev:          rev,
			ParentDigest: parent,
			MutationID:   mutationID,
		}, payload)
		if err != nil {
			return err
		}
		out = env
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type Conflict struct {
	RecordID         protocol.ID
	SourceRecordID   protocol.ID
	SourceRecordType protocol.RecordType
	PreservedAt      string
}

func (m *Manager) Conflicts() ([]Conflict, error) {
	var out []Conflict
	err := m.read(func(s *session, r *Reader) error {
		for _, t := range []protocol.RecordType{protocol.RecordConflictMetadata, protocol.RecordConflictSecret} {
			envs, err := m.store.LiveRecords(t)
			if err != nil {
				return err
			}
			for _, env := range envs {
				var p ConflictPayload
				if err := r.Open(env, &p); err != nil {
					return err
				}
				out = append(out, Conflict{
					RecordID:         env.Context.RecordID,
					SourceRecordID:   p.SourceRecordID,
					SourceRecordType: p.SourceRecordType,
					PreservedAt:      p.PreservedAt,
				})
			}
		}
		return nil
	})
	return out, err
}

type ExportSnapshot struct {
	Records   []*protocol.Envelope
	Conflicts []*protocol.Envelope
	Heads     []protocol.Head
}

var ErrUnsyncedEdit = errors.New("an edit to an existing record has not synced yet")

func (m *Manager) Snapshot(acceptedOnly bool) (*ExportSnapshot, error) {
	out := &ExportSnapshot{}
	unpublished := map[protocol.ID]bool{}
	if acceptedOnly {
		pending, err := m.store.Outbox()
		if err != nil {
			return nil, err
		}
		for _, env := range pending {
			unpublished[env.Context.MutationID] = true
		}
	}
	for _, t := range []protocol.RecordType{
		protocol.RecordHost, protocol.RecordKey, protocol.RecordKnownHost,
		protocol.RecordConflictMetadata, protocol.RecordConflictSecret,
	} {
		envs, err := m.store.AllRecords(t)
		if err != nil {
			return nil, err
		}
		for _, env := range envs {
			if unpublished[env.Context.MutationID] {
				if env.Context.Rev > 1 {
					return nil, fmt.Errorf("record %s: %w", env.Context.RecordID, ErrUnsyncedEdit)
				}
				continue
			}
			digest, err := env.Digest()
			if err != nil {
				return nil, err
			}
			out.Heads = append(out.Heads, protocol.Head{
				RecordID: env.Context.RecordID,
				Rev:      env.Context.Rev,
				Digest:   digest,
				Deleted:  env.Context.Deleted,
			})
			if t == protocol.RecordConflictMetadata || t == protocol.RecordConflictSecret {
				out.Conflicts = append(out.Conflicts, env)
			} else {
				out.Records = append(out.Records, env)
			}
		}
	}
	protocol.SortHeads(out.Heads)
	return out, nil
}

func LiveCount(envs []*protocol.Envelope) int {
	n := 0
	for _, env := range envs {
		if !env.Context.Deleted {
			n++
		}
	}
	return n
}

func (m *Manager) Checkpoint(membershipDigest []byte, seq protocol.Counter, snapshot *ExportSnapshot) (protocol.Checkpoint, error) {
	if m.genesis == nil {
		return protocol.Checkpoint{}, errors.New("checkpoint: no genesis")
	}
	epoch := protocol.Counter(1)
	if raw, err := m.store.Meta(MetaKeyEpoch); err == nil {
		parsed, err := protocol.ParseCounter(raw)
		if err != nil {
			return protocol.Checkpoint{}, err
		}
		epoch = parsed
	} else if !errors.Is(err, ErrNotFound) {
		return protocol.Checkpoint{}, err
	}
	return protocol.Checkpoint{
		Domain:           protocol.CheckpointDomain,
		FormatVersion:    protocol.CheckpointFormatVer,
		VaultID:          m.vaultID,
		KeyEpoch:         epoch,
		Seq:              seq,
		MembershipDigest: membershipDigest,
		Heads:            snapshot.Heads,
		CreatedAt:        stampOf(m.clock()),
	}, nil
}

func (m *Manager) SignExport(signingInput []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.session()
	if err != nil {
		return nil, err
	}
	return s.signing.Sign(protocol.ExportSignatureDomain, signingInput)
}

func (m *Manager) RecoveryRecipient() (*crypto.Recipient, error) {
	if m.genesis == nil {
		return nil, errors.New("no genesis")
	}
	return crypto.ParseRecipient(m.genesis.RecoveryRecipient)
}

func (m *Manager) RecoveryBundle(checkpoint protocol.Checkpoint) (*protocol.SignedBundle, error) {
	if m.genesis == nil {
		return nil, errors.New("recovery bundle: no genesis")
	}
	genesisDigest, err := m.genesis.Digest()
	if err != nil {
		return nil, err
	}
	var out *protocol.SignedBundle
	err = m.read(func(s *session, r *Reader) error {
		if s.keys == nil {
			return ErrLocked
		}
		b := protocol.Bundle{
			Domain:        protocol.BundleDomain,
			FormatVersion: protocol.BundleFormatVersion,
			Suite:         crypto.SuiteID,
			VaultID:       m.vaultID,
			GenesisDigest: genesisDigest,
			Purpose:       protocol.PurposeRecovery,
			Recipient:     m.genesis.RecoveryRecipient,
			KeyEpoch:      s.keys.Epoch,
			MetadataKey:   append([]byte(nil), s.keys.Metadata[:]...),
			SecretKey:     append([]byte(nil), s.keys.Secret[:]...),
			Checkpoint:    checkpoint,
			CreatedAt:     stampOf(m.clock()),
		}
		if err := b.Validate(crypto.SuiteID); err != nil {
			return err
		}
		msg, err := b.SigningInput()
		if err != nil {
			return err
		}
		sig, err := s.signing.Sign(protocol.BundleSignatureDomain, msg)
		if err != nil {
			return err
		}
		out = &protocol.SignedBundle{Bundle: b, Signature: sig}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (m *Manager) EnrollmentBundle(recipientID protocol.ID, recipient string, transcriptDigest, snapshotDigest []byte, snapshotLength protocol.Counter, membershipDigest []byte, seq protocol.Counter, snapshot *ExportSnapshot) (*protocol.SignedBundle, error) {
	if m.genesis == nil {
		return nil, errors.New("enrollment bundle: no genesis")
	}
	genesisDigest, err := m.genesis.Digest()
	if err != nil {
		return nil, err
	}
	checkpoint, err := m.Checkpoint(membershipDigest, seq, snapshot)
	if err != nil {
		return nil, err
	}
	var out *protocol.SignedBundle
	err = m.read(func(s *session, r *Reader) error {
		if s.keys == nil {
			return ErrLocked
		}
		id := recipientID
		var length *protocol.Counter
		if snapshotDigest != nil {
			length = &snapshotLength
		}
		b := protocol.Bundle{
			Domain:            protocol.BundleDomain,
			FormatVersion:     protocol.BundleFormatVersion,
			Suite:             crypto.SuiteID,
			VaultID:           m.vaultID,
			GenesisDigest:     genesisDigest,
			Purpose:           protocol.PurposeEnrollment,
			RecipientDeviceID: &id,
			Recipient:         recipient,
			KeyEpoch:          s.keys.Epoch,
			MetadataKey:       append([]byte(nil), s.keys.Metadata[:]...),
			SecretKey:         append([]byte(nil), s.keys.Secret[:]...),
			TranscriptDigest:  transcriptDigest,
			Checkpoint:        checkpoint,
			SnapshotDigest:    snapshotDigest,
			SnapshotLength:    length,
			CreatedAt:         stampOf(m.clock()),
		}
		if err := b.Validate(crypto.SuiteID); err != nil {
			return err
		}
		msg, err := b.SigningInput()
		if err != nil {
			return err
		}
		sig, err := s.signing.Sign(protocol.BundleSignatureDomain, msg)
		if err != nil {
			return err
		}
		out = &protocol.SignedBundle{Bundle: b, Signature: sig}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (m *Manager) Identity() (protocol.ID, *crypto.SigningKey, *crypto.EncryptionKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.session()
	if err != nil {
		return "", nil, nil, err
	}
	return m.deviceID, s.signing, s.encryption, nil
}

var ErrConflictSourceDeleted = errors.New("the record this edit belonged to has been deleted")

func (m *Manager) ResolveConflict(conflictID protocol.ID, resurrect bool) (protocol.ID, error) {
	var sourceID protocol.ID
	err := m.mutate(func(s *session, w *Writer, r *Reader) error {
		conflictEnv, conflictDigest, err := m.store.Head(conflictID)
		if err != nil {
			return fmt.Errorf("no such conflict %s: %w", conflictID, err)
		}
		if conflictEnv.Context.Deleted {
			return fmt.Errorf("conflict %s was already resolved", conflictID)
		}
		var payload ConflictPayload
		if err := r.Open(conflictEnv, &payload); err != nil {
			return err
		}
		if err := payload.Validate(); err != nil {
			return err
		}
		sourceID = payload.SourceRecordID

		head, headDigest, err := m.store.Head(payload.SourceRecordID)
		if err != nil {
			return fmt.Errorf("the record this edit belonged to is not here: %w", err)
		}
		if head.Context.Deleted && !resurrect {
			return ErrConflictSourceDeleted
		}

		replacementID, err := protocol.NewID()
		if err != nil {
			return err
		}
		replacement, err := w.Seal(Mutation{
			RecordID:     payload.SourceRecordID,
			RecordType:   payload.SourceRecordType,
			Rev:          head.Context.Rev + 1,
			ParentDigest: headDigest,
			MutationID:   replacementID,
		}, payload.Candidate)
		if err != nil {
			return err
		}

		retireID, err := protocol.NewID()
		if err != nil {
			return err
		}
		retire, err := w.Seal(Mutation{
			RecordID:     conflictID,
			RecordType:   conflictEnv.Context.RecordType,
			Rev:          conflictEnv.Context.Rev + 1,
			ParentDigest: conflictDigest,
			MutationID:   retireID,
			Deleted:      true,
		}, nil)
		if err != nil {
			return err
		}
		return m.store.ApplyLocalBatch(replacement, retire)
	})
	return sourceID, err
}
