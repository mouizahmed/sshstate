package vault

import (
	"errors"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type fixture struct {
	vaultID  protocol.ID
	deviceID protocol.ID
	keys     *Keys
	writer   *Writer
	reader   *Reader
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		vaultID:  protocol.MustNewID(),
		deviceID: protocol.MustNewID(),
		keys:     keys,
	}
	f.writer = &Writer{VaultID: f.vaultID, DeviceID: f.deviceID, Signing: sk, Keys: keys}
	f.reader = &Reader{
		VaultID: f.vaultID,
		Keys:    keys,
		Verifier: func(d protocol.ID) (*crypto.VerifyKey, error) {
			if d != f.deviceID {
				return nil, errors.New("not an authorized device")
			}
			return sk.Verifier(), nil
		},
	}
	return f
}

func hostPayload() *HostPayload {
	return &HostPayload{
		FormatVersion: PayloadFormatVersion,
		Alias:         "prod",
		HostName:      "10.0.0.5",
		User:          "ubuntu",
		Port:          DefaultPort,
		KeyIDs:        []protocol.ID{protocol.MustNewID()},
	}
}

func creation(t protocol.RecordType) Mutation {
	return Mutation{
		RecordID:   protocol.MustNewID(),
		RecordType: t,
		Rev:        1,
		MutationID: protocol.MustNewID(),
	}
}

func TestSealOpenHostRoundTrip(t *testing.T) {
	f := newFixture(t)
	want := hostPayload()
	env, err := f.writer.Seal(creation(protocol.RecordHost), want)
	if err != nil {
		t.Fatal(err)
	}
	var got HostPayload
	if err := f.reader.Open(env, &got); err != nil {
		t.Fatal(err)
	}
	if got.Alias != want.Alias || got.HostName != want.HostName || got.Port != want.Port {
		t.Fatalf("payload changed: %+v", got)
	}
	if len(got.KeyIDs) != 1 || got.KeyIDs[0] != want.KeyIDs[0] {
		t.Fatalf("key order or content changed: %v", got.KeyIDs)
	}
}

func TestSecretRecordsNeedTheSecretKey(t *testing.T) {
	f := newFixture(t)
	env, err := f.writer.Seal(creation(protocol.RecordKey), &KeyPayload{
		FormatVersion: PayloadFormatVersion,
		PrivateKey:    "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
		PublicKey:     "ssh-ed25519 AAAA...",
		Fingerprint:   "SHA256:abc",
		Algorithm:     "ssh-ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}

	metadataOnly := &Reader{
		VaultID:  f.vaultID,
		Keys:     &Keys{Epoch: f.keys.Epoch, Metadata: f.keys.Metadata, Secret: f.keys.Metadata},
		Verifier: f.reader.Verifier,
	}
	if err := metadataOnly.Open(env, &KeyPayload{}); err == nil {
		t.Fatal("the metadata key decrypted a private-key record")
	}
}

func TestContextTamperingBreaksDecryption(t *testing.T) {
	f := newFixture(t)
	env, err := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(e *protocol.Envelope){
		"deleted flag": func(e *protocol.Envelope) { e.Context.Deleted = true },
		"record id":    func(e *protocol.Envelope) { e.Context.RecordID = protocol.MustNewID() },
		"mutation id":  func(e *protocol.Envelope) { e.Context.MutationID = protocol.MustNewID() },
		"record type":  func(e *protocol.Envelope) { e.Context.RecordType = protocol.RecordKnownHost },
	}
	for name, mutate := range mutations {
		tampered := *env
		mutate(&tampered)
		err := f.reader.Open(&tampered, &HostPayload{})
		if err == nil {
			t.Errorf("%s: tampered record opened", name)
			continue
		}
		if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "authentication") {
			t.Errorf("%s: unexpected rejection: %v", name, err)
		}
	}
}

func TestForeignWriterRejected(t *testing.T) {
	f := newFixture(t)
	env, err := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	intruder, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	forged := *env
	forged.Context.UpdatedBy = protocol.MustNewID()
	input, err := forged.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := intruder.Sign(protocol.RecordSignatureDomain, input)
	if err != nil {
		t.Fatal(err)
	}
	forged.Signature = sig
	if err := f.reader.Open(&forged, &HostPayload{}); err == nil {
		t.Fatal("accepted a record from an unauthorized device")
	}
}

func TestSignatureTamperRejected(t *testing.T) {
	f := newFixture(t)
	env, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	env.Signature[0] ^= 0x01
	if err := f.reader.Open(env, &HostPayload{}); err == nil {
		t.Fatal("accepted a tampered signature")
	}
}

func TestTombstoneCarriesEmptyPayload(t *testing.T) {
	f := newFixture(t)
	create, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	parent, err := create.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tomb, err := f.writer.Seal(Mutation{
		RecordID:     create.Context.RecordID,
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: parent,
		MutationID:   protocol.MustNewID(),
		Deleted:      true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tomb.Ciphertext) == 0 {
		t.Fatal("tombstone has no ciphertext; an encrypted empty object is required")
	}
	if err := f.reader.Open(tomb, &HostPayload{}); err != nil {
		t.Fatalf("tombstone did not verify: %v", err)
	}
	if string(tomb.Nonce) == string(create.Nonce) {
		t.Fatal("tombstone reused the creation's nonce")
	}
}

func TestEpochAndVaultMismatchRejected(t *testing.T) {
	f := newFixture(t)
	env, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())

	otherVault := &Reader{VaultID: protocol.MustNewID(), Keys: f.keys, Verifier: f.reader.Verifier}
	if err := otherVault.Open(env, &HostPayload{}); err == nil {
		t.Fatal("opened a record belonging to another vault")
	}

	nextEpoch := &Reader{
		VaultID:  f.vaultID,
		Keys:     &Keys{Epoch: 2, Metadata: f.keys.Metadata, Secret: f.keys.Secret},
		Verifier: f.reader.Verifier,
	}
	if err := nextEpoch.Open(env, &HostPayload{}); err == nil {
		t.Fatal("opened a record from a superseded epoch without a migration")
	}
}

func TestLockedVaultCannotSealOrOpen(t *testing.T) {
	f := newFixture(t)
	env, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())

	f.keys.Wipe()
	if _, err := f.writer.Seal(creation(protocol.RecordHost), hostPayload()); err == nil {
		t.Fatal("sealed a record with wiped vault keys")
	}
	if err := f.reader.Open(env, &HostPayload{}); err == nil {
		t.Fatal("opened a record with wiped vault keys")
	}
}

func TestSealRejectsInvalidContext(t *testing.T) {
	f := newFixture(t)
	m := creation(protocol.RecordHost)
	m.Rev = 2
	if _, err := f.writer.Seal(m, hostPayload()); err == nil {
		t.Fatal("sealed an update with no parent digest")
	}
}

func TestKeysRedactInFormatting(t *testing.T) {
	f := newFixture(t)
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		got := sprintf(format, *f.keys)
		if !strings.Contains(got, "redacted") {
			t.Errorf("%s exposed vault keys: %s", format, got)
		}
	}
}
