// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	CheckpointDomain      = "sshstate.checkpoint.v1"
	BundleDomain          = "sshstate.bundle.v1"
	BundleSignatureDomain = "sshstate.bundle-sig.v1"
	CheckpointFormatVer   = 1
	BundleFormatVersion   = 1
)

const VaultKeyBytes = 32

type BundlePurpose string

const (
	PurposeEnrollment BundlePurpose = "enrollment"
	PurposeRecovery   BundlePurpose = "recovery"
	PurposeRotation   BundlePurpose = "rotation"
)

func (p BundlePurpose) Valid() bool {
	switch p {
	case PurposeEnrollment, PurposeRecovery, PurposeRotation:
		return true
	}
	return false
}

type Head struct {
	RecordID ID      `json:"record_id"`
	Rev      Counter `json:"rev"`
	Digest   Bytes   `json:"digest"`
	Deleted  bool    `json:"deleted"`
}

func SortHeads(heads []Head) {
	sort.Slice(heads, func(i, j int) bool { return heads[i].RecordID < heads[j].RecordID })
}

type Checkpoint struct {
	Domain           string  `json:"domain"`
	FormatVersion    int     `json:"format_version"`
	VaultID          ID      `json:"vault_id"`
	KeyEpoch         Counter `json:"key_epoch"`
	Seq              Counter `json:"seq"`
	MembershipDigest Bytes   `json:"membership_digest"`
	Heads            []Head  `json:"heads"`
	CreatedAt        string  `json:"created_at"`
}

func (c *Checkpoint) Validate() error {
	if c.Domain != CheckpointDomain {
		return fmt.Errorf("checkpoint domain %q is not %q", c.Domain, CheckpointDomain)
	}
	if c.FormatVersion != CheckpointFormatVer {
		return fmt.Errorf("unsupported checkpoint format version %d", c.FormatVersion)
	}
	if err := c.VaultID.check("vault_id"); err != nil {
		return err
	}
	if c.KeyEpoch < 1 {
		return errors.New("key_epoch starts at 1")
	}
	if len(c.MembershipDigest) != sha256.Size {
		return fmt.Errorf("membership_digest must be %d bytes", sha256.Size)
	}
	if _, err := time.Parse(time.RFC3339, c.CreatedAt); err != nil {
		return fmt.Errorf("checkpoint created_at is not RFC 3339: %w", err)
	}
	seen := make(map[ID]bool, len(c.Heads))
	for i, h := range c.Heads {
		if err := h.RecordID.check("head record_id"); err != nil {
			return err
		}
		if seen[h.RecordID] {
			return fmt.Errorf("record %s appears twice in the checkpoint", h.RecordID)
		}
		seen[h.RecordID] = true
		if i > 0 && !(c.Heads[i-1].RecordID < h.RecordID) {
			return errors.New("checkpoint heads are not sorted by record_id")
		}
		if h.Rev < 1 {
			return fmt.Errorf("record %s has rev %s", h.RecordID, h.Rev)
		}
		if len(h.Digest) != sha256.Size {
			return fmt.Errorf("record %s has a %d-byte digest", h.RecordID, len(h.Digest))
		}
	}
	return nil
}

func (c *Checkpoint) Digest() ([]byte, error) {
	canon, err := Canonical(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}

type EpochKeys struct {
	KeyEpoch    Counter `json:"key_epoch"`
	MetadataKey Bytes   `json:"metadata_key"`
	SecretKey   Bytes   `json:"secret_key"`
}

type Bundle struct {
	Domain            string        `json:"domain"`
	FormatVersion     int           `json:"format_version"`
	Suite             string        `json:"suite"`
	VaultID           ID            `json:"vault_id"`
	GenesisDigest     Bytes         `json:"genesis_digest"`
	Purpose           BundlePurpose `json:"purpose"`
	RecipientDeviceID *ID           `json:"recipient_device_id"`
	Recipient         string        `json:"recipient"`
	KeyEpoch          Counter       `json:"key_epoch"`
	MetadataKey       Bytes         `json:"metadata_key"`
	SecretKey         Bytes         `json:"secret_key"`
	TranscriptDigest  Bytes         `json:"transcript_digest"`
	Checkpoint        Checkpoint    `json:"checkpoint"`
	SnapshotDigest    Bytes         `json:"snapshot_digest"`
	SnapshotLength    *Counter      `json:"snapshot_length"`
	RotationID        *ID           `json:"rotation_id"`
	EpochHistory      []EpochKeys   `json:"epoch_history"`
	CreatedAt         string        `json:"created_at"`
}

type SignedBundle struct {
	Bundle    Bundle `json:"bundle"`
	Signature Bytes  `json:"signature"`
}

func (b *Bundle) SigningInput() ([]byte, error) { return Canonical(b) }

func (b *Bundle) Validate(expectSuite string) error {
	if b.Domain != BundleDomain {
		return fmt.Errorf("bundle domain %q is not %q", b.Domain, BundleDomain)
	}
	if b.FormatVersion != BundleFormatVersion {
		return fmt.Errorf("unsupported bundle format version %d", b.FormatVersion)
	}
	if b.Suite != expectSuite {
		return fmt.Errorf("bundle uses suite %q, this build implements %q", b.Suite, expectSuite)
	}
	if err := b.VaultID.check("vault_id"); err != nil {
		return err
	}
	if len(b.GenesisDigest) != sha256.Size {
		return fmt.Errorf("genesis_digest must be %d bytes", sha256.Size)
	}
	if !b.Purpose.Valid() {
		return fmt.Errorf("unknown bundle purpose %q", b.Purpose)
	}
	if b.Recipient == "" {
		return errors.New("bundle names no recipient")
	}
	if b.RecipientDeviceID != nil {
		if err := b.RecipientDeviceID.check("recipient_device_id"); err != nil {
			return err
		}
	}
	if b.KeyEpoch < 1 {
		return errors.New("key_epoch starts at 1")
	}
	if len(b.MetadataKey) != VaultKeyBytes || len(b.SecretKey) != VaultKeyBytes {
		return fmt.Errorf("vault keys must be %d bytes each", VaultKeyBytes)
	}
	if _, err := time.Parse(time.RFC3339, b.CreatedAt); err != nil {
		return fmt.Errorf("bundle created_at is not RFC 3339: %w", err)
	}
	if err := b.Checkpoint.Validate(); err != nil {
		return fmt.Errorf("bundle checkpoint: %w", err)
	}
	if b.Checkpoint.VaultID != b.VaultID {
		return errors.New("the bundle's checkpoint names another vault")
	}
	if b.Checkpoint.KeyEpoch != b.KeyEpoch {
		return errors.New("the bundle's checkpoint is at another epoch")
	}
	if (b.SnapshotDigest == nil) != (b.SnapshotLength == nil) {
		return errors.New("a snapshot needs both a digest and a length, or neither")
	}
	if b.SnapshotDigest != nil && len(b.SnapshotDigest) != sha256.Size {
		return fmt.Errorf("snapshot_digest must be %d bytes", sha256.Size)
	}
	if b.SnapshotLength != nil && *b.SnapshotLength == 0 {
		return errors.New("snapshot_length is zero")
	}
	return b.validatePurpose()
}

func (b *Bundle) validatePurpose() error {
	switch b.Purpose {
	case PurposeEnrollment:
		if len(b.TranscriptDigest) != sha256.Size {
			return fmt.Errorf("an enrollment bundle needs a %d-byte transcript_digest", sha256.Size)
		}
		if b.RecipientDeviceID == nil {
			return errors.New("an enrollment bundle must name the receiving device")
		}
	case PurposeRecovery:
		if b.TranscriptDigest != nil {
			return errors.New("a recovery bundle has no pairing transcript")
		}
	case PurposeRotation:
		if b.TranscriptDigest != nil {
			return errors.New("a rotation bundle has no pairing transcript")
		}
		if b.RotationID == nil {
			return errors.New("a rotation bundle must name its rotation")
		}
		if err := b.RotationID.check("rotation_id"); err != nil {
			return err
		}
		if b.KeyEpoch < 2 {
			return fmt.Errorf("a rotation bundle cannot be at epoch %s", b.KeyEpoch)
		}
		if want := int(b.KeyEpoch) - 1; len(b.EpochHistory) != want {
			return fmt.Errorf("a rotation bundle to epoch %s needs %d historical epochs, got %d",
				b.KeyEpoch, want, len(b.EpochHistory))
		}
		for i, e := range b.EpochHistory {
			if e.KeyEpoch != Counter(i+1) {
				return fmt.Errorf("epoch_history[%d] is epoch %s, expected %d", i, e.KeyEpoch, i+1)
			}
			if len(e.MetadataKey) != VaultKeyBytes || len(e.SecretKey) != VaultKeyBytes {
				return fmt.Errorf("epoch %s keys must be %d bytes each", e.KeyEpoch, VaultKeyBytes)
			}
		}
		return nil
	}
	if b.RotationID != nil || len(b.EpochHistory) != 0 {
		return fmt.Errorf("a %s bundle carries no rotation history", b.Purpose)
	}
	return nil
}

const (
	ExportDomain          = "sshstate.export.v1"
	ExportSignatureDomain = "sshstate.export-sig.v1"
	ExportFormatVersion   = 1
)

const (
	MemberGenesis    = "genesis.json"
	MemberMembership = "membership.jsonl"
	MemberRecords    = "records.jsonl"
	MemberConflicts  = "conflicts.jsonl"
)

type ExportMember struct {
	Name   string  `json:"name"`
	Length Counter `json:"length"`
	Digest Bytes   `json:"digest"`
}

type ExportManifest struct {
	Domain        string         `json:"domain"`
	FormatVersion int            `json:"format_version"`
	Suite         string         `json:"suite"`
	VaultID       ID             `json:"vault_id"`
	GenesisDigest Bytes          `json:"genesis_digest"`
	KeyEpoch      Counter        `json:"key_epoch"`
	ExportedBy    ID             `json:"exported_by"`
	CreatedAt     string         `json:"created_at"`
	Checkpoint    Checkpoint     `json:"checkpoint"`
	Members       []ExportMember `json:"members"`
}

type SignedExportManifest struct {
	Manifest  ExportManifest `json:"manifest"`
	Signature Bytes          `json:"signature"`
}

func (m *ExportManifest) SigningInput() ([]byte, error) { return Canonical(m) }

func (m *ExportManifest) Validate(expectSuite string) error {
	if m.Domain != ExportDomain {
		return fmt.Errorf("export domain %q is not %q", m.Domain, ExportDomain)
	}
	if m.FormatVersion != ExportFormatVersion {
		return fmt.Errorf("unsupported export format version %d", m.FormatVersion)
	}
	if m.Suite != expectSuite {
		return fmt.Errorf("export uses suite %q, this build implements %q", m.Suite, expectSuite)
	}
	if err := m.VaultID.check("vault_id"); err != nil {
		return err
	}
	if err := m.ExportedBy.check("exported_by"); err != nil {
		return err
	}
	if len(m.GenesisDigest) != sha256.Size {
		return fmt.Errorf("genesis_digest must be %d bytes", sha256.Size)
	}
	if m.KeyEpoch < 1 {
		return errors.New("key_epoch starts at 1")
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("export created_at is not RFC 3339: %w", err)
	}
	if err := m.Checkpoint.Validate(); err != nil {
		return fmt.Errorf("export checkpoint: %w", err)
	}
	if m.Checkpoint.VaultID != m.VaultID {
		return errors.New("the export's checkpoint names another vault")
	}
	if m.Checkpoint.KeyEpoch != m.KeyEpoch {
		return errors.New("the export's checkpoint is at another epoch")
	}
	required := map[string]bool{
		MemberGenesis: false, MemberMembership: false,
		MemberRecords: false, MemberConflicts: false,
	}
	for i, member := range m.Members {
		seen, known := required[member.Name]
		if !known {
			return fmt.Errorf("unknown export member %q", member.Name)
		}
		if seen {
			return fmt.Errorf("export member %q is named twice", member.Name)
		}
		required[member.Name] = true
		if i > 0 && !(m.Members[i-1].Name < member.Name) {
			return fmt.Errorf("export members are not sorted: %q follows %q", member.Name, m.Members[i-1].Name)
		}
		if len(member.Digest) != sha256.Size {
			return fmt.Errorf("export member %q has a %d-byte digest", member.Name, len(member.Digest))
		}
	}
	for name, seen := range required {
		if !seen {
			return fmt.Errorf("the export does not name %q", name)
		}
	}
	return nil
}
