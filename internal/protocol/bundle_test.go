// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func key(seed byte) Bytes { return bytes.Repeat(Bytes{seed}, VaultKeyBytes) }

func sampleCheckpoint() Checkpoint {
	heads := []Head{
		{RecordID: "22222222222222222222222222222222", Rev: 3, Digest: digest("head a"), Deleted: false},
		{RecordID: "11111111111111111111111111111111", Rev: 1, Digest: digest("head b"), Deleted: true},
	}
	SortHeads(heads)
	return Checkpoint{
		Domain:           CheckpointDomain,
		FormatVersion:    CheckpointFormatVer,
		VaultID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		KeyEpoch:         1,
		Seq:              441,
		MembershipDigest: digest("membership head"),
		Heads:            heads,
		CreatedAt:        "2026-09-12T00:00:00Z",
	}
}

func sampleBundle() Bundle {
	transcript := digest("confirmed transcript")
	recipient := ID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	return Bundle{
		Domain:            BundleDomain,
		FormatVersion:     BundleFormatVersion,
		Suite:             testSuite,
		VaultID:           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		GenesisDigest:     digest("genesis"),
		Purpose:           PurposeEnrollment,
		RecipientDeviceID: &recipient,
		Recipient:         "age1pq1joiner",
		KeyEpoch:          1,
		MetadataKey:       key(0x10),
		SecretKey:         key(0x20),
		TranscriptDigest:  transcript,
		Checkpoint:        sampleCheckpoint(),
		CreatedAt:         "2026-09-12T00:00:00Z",
	}
}

func TestCheckpointValidates(t *testing.T) {
	c := sampleCheckpoint()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	shuffled := sampleCheckpoint()
	shuffled.Heads[0], shuffled.Heads[1] = shuffled.Heads[1], shuffled.Heads[0]
	if err := shuffled.Validate(); err == nil {
		t.Fatal("unsorted heads validated")
	}
	SortHeads(shuffled.Heads)
	a, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b, err := shuffled.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the same accepted state produced two checkpoint digests")
	}
}

func TestCheckpointRejections(t *testing.T) {
	cases := map[string]func(*Checkpoint){
		"wrong domain":      func(c *Checkpoint) { c.Domain = BundleDomain },
		"bad version":       func(c *Checkpoint) { c.FormatVersion = 2 },
		"zero epoch":        func(c *Checkpoint) { c.KeyEpoch = 0 },
		"short membership":  func(c *Checkpoint) { c.MembershipDigest = Bytes("x") },
		"bad timestamp":     func(c *Checkpoint) { c.CreatedAt = "soon" },
		"duplicate head":    func(c *Checkpoint) { c.Heads[1].RecordID = c.Heads[0].RecordID },
		"zero rev":          func(c *Checkpoint) { c.Heads[0].Rev = 0 },
		"short head digest": func(c *Checkpoint) { c.Heads[0].Digest = Bytes("x") },
		"malformed head id": func(c *Checkpoint) { c.Heads[0].RecordID = "nope" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := sampleCheckpoint()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("the checkpoint validated")
			}
		})
	}
}

func TestEmptyCheckpointIsValid(t *testing.T) {
	c := sampleCheckpoint()
	c.Heads = nil
	c.Seq = 0
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBundleValidates(t *testing.T) {
	b := sampleBundle()
	if err := b.Validate(testSuite); err != nil {
		t.Fatal(err)
	}
}

func TestBundleRejections(t *testing.T) {
	cases := map[string]func(*Bundle){
		"wrong domain":       func(b *Bundle) { b.Domain = CheckpointDomain },
		"unknown suite":      func(b *Bundle) { b.Suite = "sshstate.suite.v2" },
		"unknown purpose":    func(b *Bundle) { b.Purpose = "sharing" },
		"no recipient":       func(b *Bundle) { b.Recipient = "" },
		"short metadata key": func(b *Bundle) { b.MetadataKey = Bytes("short") },
		"short secret key":   func(b *Bundle) { b.SecretKey = Bytes("short") },
		"short genesis":      func(b *Bundle) { b.GenesisDigest = Bytes("x") },
		"bad timestamp":      func(b *Bundle) { b.CreatedAt = "later" },
		"checkpoint vault":   func(b *Bundle) { b.Checkpoint.VaultID = "cccccccccccccccccccccccccccccccc" },
		"checkpoint epoch":   func(b *Bundle) { b.Checkpoint.KeyEpoch = 2 },
		"no transcript":      func(b *Bundle) { b.TranscriptDigest = nil },
		"no recipient id":    func(b *Bundle) { b.RecipientDeviceID = nil },
		"rotation history":   func(b *Bundle) { b.EpochHistory = []EpochKeys{{KeyEpoch: 1}} },
		"stray rotation id":  func(b *Bundle) { id := ID("dddddddddddddddddddddddddddddddd"); b.RotationID = &id },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := sampleBundle()
			mutate(&b)
			if err := b.Validate(testSuite); err == nil {
				t.Fatal("the bundle validated")
			}
		})
	}
}

func TestSnapshotBindingIsAllOrNothing(t *testing.T) {
	b := sampleBundle()
	b.SnapshotDigest = digest("snapshot")
	if err := b.Validate(testSuite); err == nil {
		t.Fatal("a digest with no length validated")
	}
	length := Counter(182344)
	b.SnapshotLength = &length
	if err := b.Validate(testSuite); err != nil {
		t.Fatal(err)
	}
	b.SnapshotDigest = nil
	if err := b.Validate(testSuite); err == nil {
		t.Fatal("a length with no digest validated")
	}
}

func TestRecoveryBundle(t *testing.T) {
	b := sampleBundle()
	b.Purpose = PurposeRecovery
	b.TranscriptDigest = nil
	b.RecipientDeviceID = nil
	b.Recipient = "age1pq1recovery"
	if err := b.Validate(testSuite); err != nil {
		t.Fatal(err)
	}
	b.TranscriptDigest = digest("transcript")
	if err := b.Validate(testSuite); err == nil {
		t.Fatal("a recovery bundle carried a pairing transcript")
	}
}

func TestRotationBundleCarriesEveryEarlierEpoch(t *testing.T) {
	rotation := ID("dddddddddddddddddddddddddddddddd")
	b := sampleBundle()
	b.Purpose = PurposeRotation
	b.TranscriptDigest = nil
	b.RotationID = &rotation
	b.KeyEpoch = 3
	b.Checkpoint.KeyEpoch = 3

	if err := b.Validate(testSuite); err == nil {
		t.Fatal("a rotation bundle with no epoch history validated")
	}
	b.EpochHistory = []EpochKeys{
		{KeyEpoch: 1, MetadataKey: key(1), SecretKey: key(2)},
		{KeyEpoch: 2, MetadataKey: key(3), SecretKey: key(4)},
	}
	if err := b.Validate(testSuite); err != nil {
		t.Fatal(err)
	}

	b.EpochHistory = []EpochKeys{{KeyEpoch: 2, MetadataKey: key(3), SecretKey: key(4)}}
	if err := b.Validate(testSuite); err == nil {
		t.Fatal("a rotation bundle missing epoch 1 validated")
	}
	b.EpochHistory = []EpochKeys{
		{KeyEpoch: 2, MetadataKey: key(3), SecretKey: key(4)},
		{KeyEpoch: 1, MetadataKey: key(1), SecretKey: key(2)},
	}
	if err := b.Validate(testSuite); err == nil {
		t.Fatal("out-of-order epoch history validated")
	}
	b.KeyEpoch = 1
	b.Checkpoint.KeyEpoch = 1
	b.EpochHistory = nil
	if err := b.Validate(testSuite); err == nil {
		t.Fatal("a rotation bundle at epoch 1 validated")
	}
}

func TestBundleSigningInputIsCanonical(t *testing.T) {
	b := sampleBundle()
	a, err := b.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonical(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, canon) {
		t.Fatal("the signing input is not the canonical bundle")
	}
	b.MetadataKey, b.SecretKey = b.SecretKey, b.MetadataKey
	swapped, err := b.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, swapped) {
		t.Fatal("swapping the vault keys did not change the signing input")
	}
}

func TestCheckpointDigestCoversEveryHead(t *testing.T) {
	c := sampleCheckpoint()
	base, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Checkpoint){
		"a head's rev":      func(c *Checkpoint) { c.Heads[0].Rev = 9 },
		"a head's digest":   func(c *Checkpoint) { c.Heads[0].Digest = digest("substituted") },
		"a head's deletion": func(c *Checkpoint) { c.Heads[0].Deleted = !c.Heads[0].Deleted },
		"the membership":    func(c *Checkpoint) { c.MembershipDigest = digest("other chain") },
		"the epoch":         func(c *Checkpoint) { c.KeyEpoch = 2 },
		"the seq":           func(c *Checkpoint) { c.Seq = 442 },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := sampleCheckpoint()
			mutate(&mutated)
			got, err := mutated.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("the checkpoint digest did not change")
			}
		})
	}
	if len(base) != sha256.Size {
		t.Fatalf("checkpoint digest is %d bytes", len(base))
	}
}
