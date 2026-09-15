// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func digest(seed string) Bytes {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

func sampleManifest() TransitionManifest {
	items := []ManifestItem{
		{Name: RecordItem("22222222222222222222222222222222"), Digest: digest("record a"), Length: 1184},
		{Name: DeviceBundleItem("44444444444444444444444444444444"), Digest: digest("bundle a"), Length: 2043},
		{Name: ItemRecoveryBundle, Digest: digest("bundle recovery"), Length: 2043},
	}
	SortItems(items)
	return TransitionManifest{
		Domain:        RotationDomain,
		FormatVersion: RotationFormatVersion,
		Suite:         testSuite,
		VaultID:       "11111111111111111111111111111111",
		GenesisDigest: digest("genesis"),
		RotationID:    "33333333333333333333333333333333",
		FromEpoch:     1,
		ToEpoch:       2,
		InitiatedBy:   "44444444444444444444444444444444",
		CreatedAt:     "2026-09-12T00:00:00Z",
		Preconditions: RotationPreconditions{
			MembershipDigest: digest("membership head"),
			CheckpointDigest: digest("checkpoint"),
			Seq:              441,
		},
		Items: items,
	}
}

func TestManifestValidates(t *testing.T) {
	m := sampleManifest()
	if err := m.Validate(testSuite); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRejections(t *testing.T) {
	cases := map[string]func(*TransitionManifest){
		"wrong domain":       func(m *TransitionManifest) { m.Domain = "sshstate.record.v1" },
		"unknown suite":      func(m *TransitionManifest) { m.Suite = "sshstate.suite.v2" },
		"bad version":        func(m *TransitionManifest) { m.FormatVersion = 2 },
		"zero from epoch":    func(m *TransitionManifest) { m.FromEpoch = 0; m.ToEpoch = 1 },
		"skipped epoch":      func(m *TransitionManifest) { m.ToEpoch = 3 },
		"backwards epoch":    func(m *TransitionManifest) { m.FromEpoch = 3; m.ToEpoch = 2 },
		"short genesis":      func(m *TransitionManifest) { m.GenesisDigest = Bytes("short") },
		"short membership":   func(m *TransitionManifest) { m.Preconditions.MembershipDigest = Bytes("x") },
		"short checkpoint":   func(m *TransitionManifest) { m.Preconditions.CheckpointDigest = Bytes("x") },
		"bad timestamp":      func(m *TransitionManifest) { m.CreatedAt = "yesterday" },
		"malformed vault":    func(m *TransitionManifest) { m.VaultID = "nope" },
		"no items":           func(m *TransitionManifest) { m.Items = nil },
		"unknown item":       func(m *TransitionManifest) { m.Items[0].Name = "something:else" },
		"short item digest":  func(m *TransitionManifest) { m.Items[0].Digest = Bytes("x") },
		"zero item length":   func(m *TransitionManifest) { m.Items[0].Length = 0 },
		"unsorted items":     func(m *TransitionManifest) { m.Items[0], m.Items[2] = m.Items[2], m.Items[0] },
		"duplicate item":     func(m *TransitionManifest) { m.Items[1] = m.Items[0] },
		"malformed recordid": func(m *TransitionManifest) { m.Items[2].Name = ItemPrefixRecord + "nope" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := sampleManifest()
			mutate(&m)
			if err := m.Validate(testSuite); err == nil {
				t.Fatal("the manifest validated")
			}
		})
	}
}

func TestManifestNeedsRecoveryAndADevice(t *testing.T) {
	m := sampleManifest()
	var withoutRecovery []ManifestItem
	for _, item := range m.Items {
		if item.Name != ItemRecoveryBundle {
			withoutRecovery = append(withoutRecovery, item)
		}
	}
	m.Items = withoutRecovery
	err := m.Validate(testSuite)
	if err == nil || !strings.Contains(err.Error(), ItemRecoveryBundle) {
		t.Fatalf("a manifest with no recovery bundle was accepted: %v", err)
	}

	m = sampleManifest()
	var withoutDevices []ManifestItem
	for _, item := range m.Items {
		if !strings.HasPrefix(item.Name, ItemPrefixDeviceBundle) {
			withoutDevices = append(withoutDevices, item)
		}
	}
	m.Items = withoutDevices
	if err := m.Validate(testSuite); err == nil {
		t.Fatal("a manifest with no device bundles was accepted")
	}
}

func TestManifestWithNoRecordsIsLegal(t *testing.T) {
	m := sampleManifest()
	var noRecords []ManifestItem
	for _, item := range m.Items {
		if !strings.HasPrefix(item.Name, ItemPrefixRecord) {
			noRecords = append(noRecords, item)
		}
	}
	m.Items = noRecords
	if err := m.Validate(testSuite); err != nil {
		t.Fatalf("an empty vault could not rotate: %v", err)
	}
}

func TestItemNames(t *testing.T) {
	const record ID = "22222222222222222222222222222222"
	const device ID = "44444444444444444444444444444444"
	for name, want := range map[string]struct {
		kind ItemKind
		id   ID
	}{
		RecordItem(record):       {ItemKindRecord, record},
		DeviceBundleItem(device): {ItemKindDeviceBundle, device},
		ItemRecoveryBundle:       {ItemKindRecoveryBundle, ""},
	} {
		kind, id, err := ParseItemName(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if kind != want.kind || id != want.id {
			t.Fatalf("%s parsed as (%s, %s), want (%s, %s)", name, kind, id, want.kind, want.id)
		}
	}
	for _, bad := range []string{"", "record:", "bundle:device:", "bundle:", "records:2222", ItemPrefixRecord + "NOT_HEX_AT_ALL_NOT_HEX_AT_ALL_XX"} {
		if _, _, err := ParseItemName(bad); err == nil {
			t.Errorf("%q parsed as a staged item name", bad)
		}
	}
}

func TestServerStateMachine(t *testing.T) {
	if !RotationStaging.CanTransition(RotationCommitted) || !RotationStaging.CanTransition(RotationAborted) {
		t.Fatal("staging cannot reach its own outcomes")
	}
	for _, terminal := range []RotationState{RotationCommitted, RotationAborted} {
		if !terminal.Terminal() {
			t.Fatalf("%s is not terminal", terminal)
		}
		for _, to := range []RotationState{RotationStaging, RotationCommitted, RotationAborted} {
			if terminal.CanTransition(to) {
				t.Fatalf("%s -> %s is allowed", terminal, to)
			}
		}
	}
	if RotationState("rolling").Valid() {
		t.Fatal("an unknown rotation state is valid")
	}
}

func TestCommittedRotationCannotBeAborted(t *testing.T) {
	for _, phase := range []RotationPhase{RotationCommittedLocal, RotationFinalizing, RotationFinalized} {
		for _, to := range []RotationPhase{RotationAborting, RotationAbortedLocal} {
			if phase.CanTransition(to) {
				t.Fatalf("%s -> %s is allowed after the relay committed", phase, to)
			}
		}
	}
}

func TestClientPhasesAreReachableAndProductive(t *testing.T) {
	all := []RotationPhase{
		RotationPlanning, RotationStagingLocal, RotationStaged, RotationCommitting,
		RotationCommittedLocal, RotationFinalizing, RotationFinalized,
		RotationAborting, RotationAbortedLocal,
	}
	reached := map[RotationPhase]bool{RotationPlanning: true}
	queue := []RotationPhase{RotationPlanning}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, next := range clientTransitions[p] {
			if !reached[next] {
				reached[next] = true
				queue = append(queue, next)
			}
		}
	}
	for _, p := range all {
		if !p.Valid() {
			t.Errorf("%s is not a known phase", p)
		}
		if !reached[p] {
			t.Errorf("%s is unreachable from planning", p)
		}
		if !p.Terminal() && len(clientTransitions[p]) == 0 {
			t.Errorf("%s is a dead end but is not terminal", p)
		}
		if p.Terminal() && len(clientTransitions[p]) != 0 {
			t.Errorf("%s is terminal but has transitions", p)
		}
	}
	if RotationPhase("halfway").Valid() {
		t.Fatal("an unknown phase is valid")
	}
}

func TestCommittingResolvesToEitherOutcome(t *testing.T) {
	if !RotationCommitting.CanTransition(RotationCommittedLocal) {
		t.Fatal("committing cannot resolve to committed")
	}
	if !RotationCommitting.CanTransition(RotationAbortedLocal) {
		t.Fatal("committing cannot resolve to aborted")
	}
	if RotationCommitting.CanTransition(RotationFinalized) {
		t.Fatal("committing can skip straight to finalized")
	}
}

func TestManifestDigestCoversTheSignature(t *testing.T) {
	m := sampleManifest()
	signed := SignedTransitionManifest{Manifest: m, Signature: Bytes("signature-a")}
	a, err := signed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = Bytes("signature-b")
	b, err := signed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Fatal("the digest does not cover the signature")
	}
	unsigned := SignedTransitionManifest{Manifest: m}
	if _, err := unsigned.Digest(); err == nil {
		t.Fatal("an unsigned manifest produced a digest")
	}
}

func TestManifestItemOrderIsCanonical(t *testing.T) {
	m := sampleManifest()
	shuffled := append([]ManifestItem(nil), m.Items...)
	shuffled[0], shuffled[len(shuffled)-1] = shuffled[len(shuffled)-1], shuffled[0]
	SortItems(shuffled)
	a, err := Canonical(&m)
	if err != nil {
		t.Fatal(err)
	}
	m.Items = shuffled
	b, err := Canonical(&m)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("sorting did not produce the same canonical manifest")
	}
}

func TestTransitionManifestSigningInputIsCanonical(t *testing.T) {
	m := &TransitionManifest{}
	first, err := m.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("the same manifest produced two signing inputs")
	}
	if len(first) == 0 {
		t.Fatal("the signing input is empty")
	}
	var decoded map[string]any
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("the signing input is not JSON: %v", err)
	}
}
