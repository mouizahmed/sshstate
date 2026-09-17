package protocol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	RotationDomain          = "sshstate.rotation.v1"
	RotationSignatureDomain = "sshstate.rotation-sig.v1"
	RotationFormatVersion   = 1

	RotationStagingTimeout = 24 * time.Hour

	ItemPrefixRecord       = "record:"
	ItemPrefixDeviceBundle = "bundle:device:"
	ItemRecoveryBundle     = "bundle:recovery"
)

type RotationState string

const (
	RotationStaging   RotationState = "staging"
	RotationCommitted RotationState = "committed"
	RotationAborted   RotationState = "aborted"
)

func (s RotationState) Valid() bool {
	switch s {
	case RotationStaging, RotationCommitted, RotationAborted:
		return true
	}
	return false
}

func (s RotationState) Terminal() bool {
	return s == RotationCommitted || s == RotationAborted
}

var serverTransitions = map[RotationState][]RotationState{
	RotationStaging:   {RotationCommitted, RotationAborted},
	RotationCommitted: nil,
	RotationAborted:   nil,
}

func (s RotationState) CanTransition(to RotationState) bool {
	for _, allowed := range serverTransitions[s] {
		if allowed == to {
			return true
		}
	}
	return false
}

type RotationPhase string

const (
	RotationPlanning       RotationPhase = "planning"
	RotationStagingLocal   RotationPhase = "staging"
	RotationStaged         RotationPhase = "staged"
	RotationCommitting     RotationPhase = "committing"
	RotationCommittedLocal RotationPhase = "committed"
	RotationFinalizing     RotationPhase = "finalizing"
	RotationFinalized      RotationPhase = "finalized"
	RotationAborting       RotationPhase = "aborting"
	RotationAbortedLocal   RotationPhase = "aborted"
)

var clientTransitions = map[RotationPhase][]RotationPhase{
	RotationPlanning:       {RotationStagingLocal, RotationAborting},
	RotationStagingLocal:   {RotationStaged, RotationAborting},
	RotationStaged:         {RotationCommitting, RotationAborting},
	RotationCommitting:     {RotationCommittedLocal, RotationAbortedLocal},
	RotationCommittedLocal: {RotationFinalizing},
	RotationFinalizing:     {RotationFinalized},
	RotationFinalized:      nil,
	RotationAborting:       {RotationAbortedLocal},
	RotationAbortedLocal:   nil,
}

func (p RotationPhase) Valid() bool {
	_, ok := clientTransitions[p]
	return ok
}

func (p RotationPhase) Terminal() bool {
	return p == RotationFinalized || p == RotationAbortedLocal
}

func (p RotationPhase) CanTransition(to RotationPhase) bool {
	for _, allowed := range clientTransitions[p] {
		if allowed == to {
			return true
		}
	}
	return false
}

func RecordItem(recordID ID) string { return ItemPrefixRecord + recordID.String() }

func DeviceBundleItem(deviceID ID) string { return ItemPrefixDeviceBundle + deviceID.String() }

type ItemKind string

const (
	ItemKindRecord         ItemKind = "record"
	ItemKindDeviceBundle   ItemKind = "device_bundle"
	ItemKindRecoveryBundle ItemKind = "recovery_bundle"
)

func ParseItemName(name string) (ItemKind, ID, error) {
	switch {
	case name == ItemRecoveryBundle:
		return ItemKindRecoveryBundle, "", nil
	case strings.HasPrefix(name, ItemPrefixRecord):
		id := ID(strings.TrimPrefix(name, ItemPrefixRecord))
		if err := id.check("record item"); err != nil {
			return "", "", err
		}
		return ItemKindRecord, id, nil
	case strings.HasPrefix(name, ItemPrefixDeviceBundle):
		id := ID(strings.TrimPrefix(name, ItemPrefixDeviceBundle))
		if err := id.check("device bundle item"); err != nil {
			return "", "", err
		}
		return ItemKindDeviceBundle, id, nil
	}
	return "", "", fmt.Errorf("unknown staged item name %q", name)
}

type RotationPreconditions struct {
	MembershipDigest Bytes   `json:"membership_digest"`
	CheckpointDigest Bytes   `json:"checkpoint_digest"`
	Seq              Counter `json:"seq"`
}

type ManifestItem struct {
	Name   string  `json:"name"`
	Digest Bytes   `json:"digest"`
	Length Counter `json:"length"`
}

type TransitionManifest struct {
	Domain        string                `json:"domain"`
	FormatVersion int                   `json:"format_version"`
	Suite         string                `json:"suite"`
	VaultID       ID                    `json:"vault_id"`
	GenesisDigest Bytes                 `json:"genesis_digest"`
	RotationID    ID                    `json:"rotation_id"`
	FromEpoch     Counter               `json:"from_epoch"`
	ToEpoch       Counter               `json:"to_epoch"`
	InitiatedBy   ID                    `json:"initiated_by"`
	CreatedAt     string                `json:"created_at"`
	Preconditions RotationPreconditions `json:"preconditions"`
	Items         []ManifestItem        `json:"items"`
}

type SignedTransitionManifest struct {
	Manifest  TransitionManifest `json:"manifest"`
	Signature Bytes              `json:"signature"`
}

func (m *TransitionManifest) SigningInput() ([]byte, error) { return Canonical(m) }

func (s *SignedTransitionManifest) Digest() ([]byte, error) {
	if len(s.Signature) == 0 {
		return nil, errors.New("digest: transition manifest is unsigned")
	}
	canon, err := Canonical(s)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}

func (m *TransitionManifest) Validate(expectSuite string) error {
	if m.Domain != RotationDomain {
		return fmt.Errorf("rotation domain %q is not %q", m.Domain, RotationDomain)
	}
	if m.FormatVersion != RotationFormatVersion {
		return fmt.Errorf("unsupported rotation format version %d", m.FormatVersion)
	}
	if m.Suite != expectSuite {
		return fmt.Errorf("rotation manifest uses suite %q, this build implements %q", m.Suite, expectSuite)
	}
	if err := m.VaultID.check("vault_id"); err != nil {
		return err
	}
	if err := m.RotationID.check("rotation_id"); err != nil {
		return err
	}
	if err := m.InitiatedBy.check("initiated_by"); err != nil {
		return err
	}
	if len(m.GenesisDigest) != sha256.Size {
		return fmt.Errorf("genesis_digest must be %d bytes", sha256.Size)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("rotation created_at is not RFC 3339: %w", err)
	}
	if m.FromEpoch < 1 {
		return errors.New("from_epoch starts at 1")
	}
	if m.ToEpoch != m.FromEpoch+1 {
		return fmt.Errorf("to_epoch is %s, expected %s", m.ToEpoch, m.FromEpoch+1)
	}
	if len(m.Preconditions.MembershipDigest) != sha256.Size {
		return fmt.Errorf("preconditions.membership_digest must be %d bytes", sha256.Size)
	}
	if len(m.Preconditions.CheckpointDigest) != sha256.Size {
		return fmt.Errorf("preconditions.checkpoint_digest must be %d bytes", sha256.Size)
	}
	return m.validateItems()
}

func (m *TransitionManifest) validateItems() error {
	if len(m.Items) == 0 {
		return errors.New("a transition manifest names no items")
	}
	seen := make(map[string]bool, len(m.Items))
	recovery := 0
	devices := 0
	for i, item := range m.Items {
		kind, _, err := ParseItemName(item.Name)
		if err != nil {
			return err
		}
		if seen[item.Name] {
			return fmt.Errorf("item %q is named twice", item.Name)
		}
		seen[item.Name] = true
		if i > 0 && !(m.Items[i-1].Name < item.Name) {
			return fmt.Errorf("items are not sorted: %q follows %q", item.Name, m.Items[i-1].Name)
		}
		if len(item.Digest) != sha256.Size {
			return fmt.Errorf("item %q has a %d-byte digest", item.Name, len(item.Digest))
		}
		if item.Length == 0 {
			return fmt.Errorf("item %q has zero length", item.Name)
		}
		switch kind {
		case ItemKindRecoveryBundle:
			recovery++
		case ItemKindDeviceBundle:
			devices++
		}
	}
	if recovery != 1 {
		return fmt.Errorf("a transition manifest needs exactly one %s, found %d", ItemRecoveryBundle, recovery)
	}
	if devices < 1 {
		return errors.New("a transition manifest names no device bundles")
	}
	return nil
}

func SortItems(items []ManifestItem) {
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
}
