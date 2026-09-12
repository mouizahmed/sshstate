// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "vault.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStoreCreatesRestrictivePermissions(t *testing.T) {
	old := syscallUmask(0)
	defer syscallUmask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "data", "vault.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != filePerm {
		t.Errorf("database mode is %o, want %o", got, filePerm)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != dirPerm {
		t.Errorf("directory mode is %o, want %o", got, dirPerm)
	}
}

func TestMetaRoundTripAndNotFound(t *testing.T) {
	s := newStore(t)
	if _, err := s.Meta("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.SetMeta(MetaVaultID, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta(MetaVaultID, "def"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Meta(MetaVaultID)
	if err != nil || got != "def" {
		t.Fatalf("got %q %v", got, err)
	}
}

func testGenesis(t *testing.T) *protocol.Genesis {
	t.Helper()
	sk, _ := crypto.GenerateSigningKey()
	ek, _ := crypto.GenerateEncryptionKey()
	rk, _ := crypto.GenerateSigningKey()
	rek, _ := crypto.GenerateEncryptionKey()
	return &protocol.Genesis{
		Domain:               protocol.GenesisDomain,
		FormatVersion:        protocol.GenesisFormatVersion,
		Suite:                crypto.SuiteID,
		VaultID:              protocol.MustNewID(),
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
		FirstDeviceID:        protocol.MustNewID(),
		FirstDeviceVerifyKey: sk.Verifier().Bytes(),
		FirstDeviceRecipient: ek.Recipient().String(),
		RecoveryVerifyKey:    rk.Verifier().Bytes(),
		RecoveryRecipient:    rek.Recipient().String(),
	}
}

func TestGenesisIsWriteOnce(t *testing.T) {
	s := newStore(t)
	if ok, err := s.Initialized(); err != nil || ok {
		t.Fatalf("fresh store reports initialized: %v %v", ok, err)
	}
	g := testGenesis(t)
	if err := s.PutGenesis(g); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Initialized(); !ok {
		t.Fatal("store does not report initialized after genesis")
	}
	if err := s.PutGenesis(testGenesis(t)); err == nil {
		t.Fatal("a second genesis replaced the first")
	}
	got, digest, err := s.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	if got.VaultID != g.VaultID {
		t.Fatalf("read back a different vault: %s", got.VaultID)
	}
	want, _ := g.Digest()
	if string(digest) != string(want) {
		t.Fatal("stored digest does not match the document")
	}
}

func TestWrapperStorage(t *testing.T) {
	s := newStore(t)
	vault, device := protocol.MustNewID(), protocol.MustNewID()
	w, err := crypto.Wrap([]byte("pw"), vault, device, crypto.PurposeVaultMetadataKey, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutWrapper(crypto.PurposeVaultMetadataKey, w); err != nil {
		t.Fatal(err)
	}
	got, err := s.Wrapper(crypto.PurposeVaultMetadataKey)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := got.Unwrap([]byte("pw"), vault, device, crypto.PurposeVaultMetadataKey)
	if err != nil || string(secret) != "k" {
		t.Fatalf("wrapper did not survive storage: %v", err)
	}
	if _, err := s.Wrapper("no-such-purpose"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	all, err := s.Wrappers()
	if err != nil || len(all) != 1 {
		t.Fatalf("Wrappers returned %d entries: %v", len(all), err)
	}
}

func TestRecordChainEnforcement(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)

	create, err := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRecord(create); err != nil {
		t.Fatal(err)
	}
	parent, _ := create.Digest()

	if err := s.PutRecord(create); err != nil {
		t.Fatalf("identical re-apply rejected: %v", err)
	}

	update, err := f.writer.Seal(Mutation{
		RecordID:     create.Context.RecordID,
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: parent,
		MutationID:   protocol.MustNewID(),
	}, hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRecord(update); err != nil {
		t.Fatal(err)
	}

	competing, err := f.writer.Seal(Mutation{
		RecordID:     create.Context.RecordID,
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: parent,
		MutationID:   protocol.MustNewID(),
	}, hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRecord(competing); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("competing write: want ErrParentMismatch, got %v", err)
	}

	if err := s.PutRecord(create); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("stale write: want ErrParentMismatch, got %v", err)
	}
}

func TestRecordRejectsFutureRevAndWrongParent(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)

	orphan, err := f.writer.Seal(Mutation{
		RecordID:     protocol.MustNewID(),
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: make([]byte, 32),
		MutationID:   protocol.MustNewID(),
	}, hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRecord(orphan); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("orphan rev 2: want ErrParentMismatch, got %v", err)
	}

	create, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err := s.PutRecord(create); err != nil {
		t.Fatal(err)
	}
	wrongParent, err := f.writer.Seal(Mutation{
		RecordID:     create.Context.RecordID,
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: make([]byte, 32),
		MutationID:   protocol.MustNewID(),
	}, hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRecord(wrongParent); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("wrong parent digest: want ErrParentMismatch, got %v", err)
	}
}

func TestLiveRecordsExcludeTombstones(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)

	kept, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	removed, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err := s.PutRecord(kept); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRecord(removed); err != nil {
		t.Fatal(err)
	}
	parent, _ := removed.Digest()
	tomb, _ := f.writer.Seal(Mutation{
		RecordID:     removed.Context.RecordID,
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: parent,
		MutationID:   protocol.MustNewID(),
		Deleted:      true,
	}, nil)
	if err := s.PutRecord(tomb); err != nil {
		t.Fatal(err)
	}

	live, err := s.LiveRecords(protocol.RecordHost)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].Context.RecordID != kept.Context.RecordID {
		t.Fatalf("live set is %d records, expected only the surviving host", len(live))
	}
	head, _, err := s.Head(removed.Context.RecordID)
	if err != nil || !head.Context.Deleted {
		t.Fatalf("tombstone head missing: %v", err)
	}
}

func TestOutboxLifecycle(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)
	env, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())

	if err := s.ApplyLocal(env); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Outbox()
	if err != nil || len(pending) != 1 {
		t.Fatalf("outbox has %d entries: %v", len(pending), err)
	}
	if err := s.EnqueueOutbox(env); err != nil {
		t.Fatal(err)
	}
	pending, _ = s.Outbox()
	if len(pending) != 1 {
		t.Fatalf("duplicate mutation created %d candidates", len(pending))
	}
	if got := pending[0].Context.MutationID; got != env.Context.MutationID {
		t.Fatalf("outbox changed the mutation id: %s", got)
	}
	if err := s.DequeueOutbox(env.Context.MutationID); err != nil {
		t.Fatal(err)
	}
	pending, _ = s.Outbox()
	if len(pending) != 0 {
		t.Fatalf("outbox still holds %d entries", len(pending))
	}
}

func TestStoredEnvelopeIsByteIdentical(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)
	env, _ := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err := s.PutRecord(env); err != nil {
		t.Fatal(err)
	}
	back, _, err := s.Head(env.Context.RecordID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.reader.Open(back, &HostPayload{}); err != nil {
		t.Fatalf("stored envelope no longer verifies: %v", err)
	}
	before, _ := env.Digest()
	after, _ := back.Digest()
	if string(before) != string(after) {
		t.Fatal("round trip through SQLite changed the record digest")
	}
}

func TestDeviceMembership(t *testing.T) {
	s := newStore(t)
	sk, _ := crypto.GenerateSigningKey()
	ek, _ := crypto.GenerateEncryptionKey()
	d := Device{
		ID:         protocol.MustNewID(),
		VerifyKey:  sk.Verifier().Bytes(),
		Recipient:  ek.Recipient().String(),
		Status:     DeviceActive,
		EnrolledAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.PutDevice(d); err != nil {
		t.Fatal(err)
	}
	got, err := s.Device(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Recipient != d.Recipient || string(got.VerifyKey) != string(d.VerifyKey) {
		t.Fatal("membership row changed in storage")
	}
	if _, err := s.Device(protocol.MustNewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	all, err := s.Devices()
	if err != nil || len(all) != 1 {
		t.Fatalf("Devices returned %d rows: %v", len(all), err)
	}
}

func TestSchemaVersionMismatchRefusesToOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta(MetaSchemaVer, "999"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := OpenStore(path); err == nil {
		t.Fatal("opened a database written by a newer client")
	}
}
