// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package export

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const stamp = "2026-09-12T00:00:00Z"

type identity struct {
	id      protocol.ID
	signing *crypto.SigningKey
	enc     *crypto.EncryptionKey
}

func newIdentity(t *testing.T) identity {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := crypto.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	return identity{id: protocol.MustNewID(), signing: sk, enc: ek}
}

type vault struct {
	genesis  *protocol.Genesis
	first    identity
	recovery identity
	chain    *membership.Chain
	digest   []byte
}

func newVault(t *testing.T) *vault {
	t.Helper()
	first := newIdentity(t)
	recovery := newIdentity(t)
	g := &protocol.Genesis{
		Domain:               protocol.GenesisDomain,
		FormatVersion:        protocol.GenesisFormatVersion,
		Suite:                crypto.SuiteID,
		VaultID:              protocol.MustNewID(),
		CreatedAt:            stamp,
		FirstDeviceID:        first.id,
		FirstDeviceVerifyKey: first.signing.Verifier().Bytes(),
		FirstDeviceRecipient: first.enc.Recipient().String(),
		RecoveryVerifyKey:    recovery.signing.Verifier().Bytes(),
		RecoveryRecipient:    recovery.enc.Recipient().String(),
	}
	root, err := membership.Root(g, first.signing, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := membership.Validate(g, []protocol.SignedMembershipEvent{root})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return &vault{genesis: g, first: first, recovery: recovery, chain: chain, digest: digest}
}

func (v *vault) record(t *testing.T, kind protocol.RecordType, filler string) *protocol.Envelope {
	t.Helper()
	env := &protocol.Envelope{
		Context: protocol.Context{
			Domain:        protocol.RecordDomain,
			FormatVersion: protocol.RecordFormatVersion,
			VaultID:       v.genesis.VaultID,
			RecordID:      protocol.MustNewID(),
			RecordType:    kind,
			KeyEpoch:      1,
			Rev:           1,
			MutationID:    protocol.MustNewID(),
			UpdatedBy:     v.first.id,
		},
		Nonce:      bytes.Repeat([]byte{0x11}, 24),
		Ciphertext: []byte("ciphertext:" + filler),
	}
	msg, err := env.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := v.first.signing.Sign(protocol.RecordSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	return env
}

func (v *vault) checkpoint(records []*protocol.Envelope) protocol.Checkpoint {
	heads := make([]protocol.Head, 0, len(records))
	for _, env := range records {
		d, _ := env.Digest()
		heads = append(heads, protocol.Head{
			RecordID: env.Context.RecordID, Rev: env.Context.Rev, Digest: d,
		})
	}
	protocol.SortHeads(heads)
	return protocol.Checkpoint{
		Domain:           protocol.CheckpointDomain,
		FormatVersion:    protocol.CheckpointFormatVer,
		VaultID:          v.genesis.VaultID,
		KeyEpoch:         1,
		Seq:              protocol.Counter(len(records)),
		MembershipDigest: v.chain.HeadDigest(),
		Heads:            heads,
		CreatedAt:        stamp,
	}
}

func (v *vault) build(t *testing.T, records, conflicts []*protocol.Envelope) []byte {
	t.Helper()
	checkpoint := v.checkpoint(records)
	sealed, err := Build(Contents{
		Genesis:    v.genesis,
		Membership: v.chain.Events(),
		Records:    records,
		Conflicts:  conflicts,
		Bundle:     v.bundle(t, checkpoint, v.first),
	}, checkpoint, v.first.id, v.first.signing,
		mustRecipient(t, v.genesis.RecoveryRecipient), stamp)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func (v *vault) bundle(t *testing.T, checkpoint protocol.Checkpoint, by identity) *protocol.SignedBundle {
	t.Helper()
	b := protocol.Bundle{
		Domain:        protocol.BundleDomain,
		FormatVersion: protocol.BundleFormatVersion,
		Suite:         crypto.SuiteID,
		VaultID:       v.genesis.VaultID,
		GenesisDigest: v.digest,
		Purpose:       protocol.PurposeRecovery,
		Recipient:     v.genesis.RecoveryRecipient,
		KeyEpoch:      1,
		MetadataKey:   bytes.Repeat([]byte{0x10}, protocol.VaultKeyBytes),
		SecretKey:     bytes.Repeat([]byte{0x20}, protocol.VaultKeyBytes),
		Checkpoint:    checkpoint,
		CreatedAt:     stamp,
	}
	msg, err := b.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := by.signing.Sign(protocol.BundleSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.SignedBundle{Bundle: b, Signature: sig}
}

func mustRecipient(t *testing.T, s string) *crypto.Recipient {
	t.Helper()
	r, err := crypto.ParseRecipient(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestExportRoundTrip(t *testing.T) {
	v := newVault(t)
	records := []*protocol.Envelope{
		v.record(t, protocol.RecordHost, "prod"),
		v.record(t, protocol.RecordKey, "a key"),
	}
	conflicts := []*protocol.Envelope{v.record(t, protocol.RecordConflictMetadata, "preserved")}

	sealed := v.build(t, records, conflicts)
	archive, err := Open(sealed, v.recovery.enc, v.digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Contents.Records) != 2 || len(archive.Contents.Conflicts) != 1 {
		t.Fatalf("archive holds %d records and %d conflicts",
			len(archive.Contents.Records), len(archive.Contents.Conflicts))
	}
	if archive.Contents.Genesis.VaultID != v.genesis.VaultID {
		t.Fatal("the archive's genesis is not the vault's")
	}
	if archive.Manifest.Checkpoint.Seq != 2 {
		t.Fatalf("checkpoint seq is %s", archive.Manifest.Checkpoint.Seq)
	}
	for _, env := range archive.Contents.Records {
		if err := env.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmptyVaultExports(t *testing.T) {
	v := newVault(t)
	sealed := v.build(t, nil, nil)
	archive, err := Open(sealed, v.recovery.enc, v.digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Contents.Records) != 0 {
		t.Fatal("an empty vault exported records")
	}
	if len(archive.Manifest.Members) != 5 {
		t.Fatalf("the manifest names %d members", len(archive.Manifest.Members))
	}
}

func TestExportCarriesTheVaultKeys(t *testing.T) {
	v := newVault(t)
	sealed := v.build(t, []*protocol.Envelope{v.record(t, protocol.RecordHost, "prod")}, nil)
	archive, err := Open(sealed, v.recovery.enc, v.digest)
	if err != nil {
		t.Fatal(err)
	}
	if archive.Contents.Bundle == nil {
		t.Fatal("the archive carries no vault keys")
	}
	if len(archive.Contents.Bundle.Bundle.MetadataKey) != protocol.VaultKeyBytes {
		t.Fatal("the metadata key did not survive the round trip")
	}
	if archive.Contents.Bundle.Bundle.Purpose != protocol.PurposeRecovery {
		t.Fatalf("the bundle is for %s", archive.Contents.Bundle.Bundle.Purpose)
	}

	impostor := newIdentity(t)
	checkpoint := v.checkpoint(nil)
	forged, err := Build(Contents{
		Genesis:    v.genesis,
		Membership: v.chain.Events(),
		Bundle:     v.bundle(t, checkpoint, impostor),
	}, checkpoint, v.first.id, v.first.signing,
		mustRecipient(t, v.genesis.RecoveryRecipient), stamp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(forged, v.recovery.enc, v.digest); err == nil {
		t.Fatal("an archive whose keys were signed by another device was accepted")
	}
}

func TestOnlyTheKitCanOpenAnExport(t *testing.T) {
	v := newVault(t)
	sealed := v.build(t, []*protocol.Envelope{v.record(t, protocol.RecordHost, "prod")}, nil)

	stranger := newIdentity(t)
	if _, err := Open(sealed, stranger.enc, v.digest); err == nil {
		t.Fatal("an export opened without the recovery kit")
	}
	if _, err := Open(sealed, v.first.enc, v.digest); err == nil {
		t.Fatal("the exporting device could open its own export")
	}
}

func TestExportForAnotherVaultIsRefused(t *testing.T) {
	v := newVault(t)
	other := newVault(t)
	sealed := v.build(t, nil, nil)
	if _, err := Open(sealed, v.recovery.enc, other.digest); err == nil {
		t.Fatal("an archive for another vault was accepted")
	}
	if _, err := Open(sealed, v.recovery.enc, nil); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedArchiveIsDetected(t *testing.T) {
	v := newVault(t)
	records := []*protocol.Envelope{v.record(t, protocol.RecordHost, "prod")}
	sealed := v.build(t, records, nil)

	raw, err := crypto.OpenBounded(v.recovery.enc, sealed, MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	substituted := append([]byte(nil), raw...)
	substituted[len(substituted)-5] ^= 0x01
	if bytes.Equal(raw, substituted) {
		t.Fatal("the test did not substitute anything")
	}
	resealed, err := crypto.SealBounded(substituted, MaxArchiveBytes, mustRecipient(t, v.genesis.RecoveryRecipient))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(resealed, v.recovery.enc, v.digest)
	if err == nil {
		t.Fatal("a substituted record was accepted")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManifestFromAnUnknownDeviceIsRefused(t *testing.T) {
	v := newVault(t)
	impostor := newIdentity(t)
	checkpoint := v.checkpoint(nil)
	sealed, err := Build(Contents{
		Genesis:    v.genesis,
		Membership: v.chain.Events(),
		Bundle:     v.bundle(t, checkpoint, impostor),
	}, checkpoint, impostor.id, impostor.signing,
		mustRecipient(t, v.genesis.RecoveryRecipient), stamp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, v.recovery.enc, v.digest); err == nil {
		t.Fatal("an export signed by an unknown device was accepted")
	}
}

func TestRecordWithABadSignatureStopsTheRestore(t *testing.T) {
	v := newVault(t)
	bad := v.record(t, protocol.RecordHost, "prod")
	bad.Ciphertext = []byte("substituted after signing")
	sealed := v.build(t, []*protocol.Envelope{bad}, nil)
	if _, err := Open(sealed, v.recovery.enc, v.digest); err == nil {
		t.Fatal("a record with a broken signature was restored")
	}
}

func TestExportRefusesAnotherRecipient(t *testing.T) {
	v := newVault(t)
	stranger := newIdentity(t)
	checkpoint := v.checkpoint(nil)
	_, err := Build(Contents{
		Genesis:    v.genesis,
		Membership: v.chain.Events(),
		Bundle:     v.bundle(t, checkpoint, v.first),
	}, checkpoint, v.first.id, v.first.signing,
		stranger.enc.Recipient(), stamp)
	if err == nil {
		t.Fatal("an export was built for a recipient genesis does not pin")
	}
}

func TestTrailingDataIsRefused(t *testing.T) {
	v := newVault(t)
	sealed := v.build(t, nil, nil)
	raw, err := crypto.OpenBounded(v.recovery.enc, sealed, MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := crypto.SealBounded(append(raw, []byte("extra")...), MaxArchiveBytes,
		mustRecipient(t, v.genesis.RecoveryRecipient))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(resealed, v.recovery.enc, v.digest); err == nil {
		t.Fatal("an archive with trailing data was accepted")
	}
}

func TestNotAnExportIsRefused(t *testing.T) {
	v := newVault(t)
	sealed, err := crypto.SealBounded([]byte("hello\n"), MaxArchiveBytes,
		mustRecipient(t, v.genesis.RecoveryRecipient))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, v.recovery.enc, v.digest); err == nil {
		t.Fatal("an unrelated sealed file was read as an export")
	}
}
