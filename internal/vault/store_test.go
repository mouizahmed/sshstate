package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestApplyLocalBatchIsAtomic(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)

	good, err := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	bad, err := f.writer.Seal(Mutation{
		RecordID:     protocol.MustNewID(),
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: make([]byte, 32),
		MutationID:   protocol.MustNewID(),
	}, hostPayload())
	if err != nil {
		t.Fatal(err)
	}

	if err := s.ApplyLocalBatch(good, bad); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("batch: want ErrParentMismatch, got %v", err)
	}
	live, err := s.LiveRecords(protocol.RecordHost)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Fatalf("a failed batch left %d records committed", len(live))
	}
	pending, err := s.Outbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("a failed batch left %d outbox candidates", len(pending))
	}

	if err := s.ApplyLocalBatch(good); err != nil {
		t.Fatal(err)
	}
	live, err = s.LiveRecords(protocol.RecordHost)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Fatalf("a good batch stored %d records, want 1", len(live))
	}
	if pending, err := s.Outbox(); err != nil {
		t.Fatal(err)
	} else if len(pending) != 1 {
		t.Fatalf("a good batch queued %d candidates, want 1", len(pending))
	}
}

func TestInstallAcceptsHeadsPastTheirFirstRevision(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)
	create, err := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := create.Digest()
	head, err := f.writer.Seal(Mutation{
		RecordID:     create.Context.RecordID,
		RecordType:   protocol.RecordHost,
		Rev:          2,
		ParentDigest: parent,
		MutationID:   protocol.MustNewID(),
	}, hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Install(Installation{Genesis: testGenesis(t), Heads: []*protocol.Envelope{head}, Cursor: "7"}, nil); err != nil {
		t.Fatalf("install a head at rev 2: %v", err)
	}
	got, _, err := s.Head(head.Context.RecordID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Context.Rev != 2 {
		t.Fatalf("installed rev %s, want 2", got.Context.Rev)
	}
	if cursor, err := s.Cursor(CursorRecords); err != nil || cursor != "7" {
		t.Fatalf("cursor %q, %v", cursor, err)
	}
}

func TestAFailedInstallLeavesNoVault(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)
	head, err := f.writer.Seal(creation(protocol.RecordHost), hostPayload())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Install(Installation{
		Genesis: testGenesis(t),
		Devices: []Device{{ID: protocol.MustNewID(), VerifyKey: []byte{1}, Recipient: "r", Status: DeviceActive, EnrolledAt: "now"}},
		Heads:   []*protocol.Envelope{head, head},
		Meta:    map[string]string{MetaVaultID: "x"},
	}, func() error {
		t.Fatal("announced a device whose local install failed")
		return nil
	})
	if err == nil {
		t.Fatal("an install with a record listed twice succeeded")
	}
	if ok, err := s.Initialized(); err != nil || ok {
		t.Fatalf("a failed install left a vault behind: %v %v", ok, err)
	}
	if devices, err := s.Devices(); err != nil || len(devices) != 0 {
		t.Fatalf("a failed install left devices behind: %v %v", devices, err)
	}
	if err := s.Install(Installation{Genesis: testGenesis(t), Heads: []*protocol.Envelope{head}}, nil); err != nil {
		t.Fatalf("retrying after a failed install: %v", err)
	}
}

func TestAnInstallWhoseAnnouncementFailsLeavesNoVault(t *testing.T) {
	s := newStore(t)
	err := s.Install(Installation{Genesis: testGenesis(t)}, func() error {
		return errors.New("relay refused")
	})
	if err == nil || !strings.Contains(err.Error(), "relay refused") {
		t.Fatalf("want the announcement's error, got %v", err)
	}
	if ok, err := s.Initialized(); err != nil || ok {
		t.Fatalf("an unannounced install was kept: %v %v", ok, err)
	}
}

func TestRestartingTheHistoryForgetsPositionsFromTheOldOne(t *testing.T) {
	s := newStore(t)
	for name, value := range map[string]string{
		CursorRecords:                  "41",
		CursorHistory:                  "old",
		CursorRevokedAtPrefix + "dead": "12",
	} {
		if err := s.SetCursor(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetMeta(MetaRecoveryPublished, "stale"); err != nil {
		t.Fatal(err)
	}
	if err := s.RestartHistory("new"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Cursor(CursorRecords); got != "0" {
		t.Fatalf("the record cursor is %q after a restart", got)
	}
	if got, _ := s.Cursor(CursorHistory); got != "new" {
		t.Fatalf("the stored history is %q after a restart", got)
	}
	if _, err := s.Cursor(CursorRevokedAtPrefix + "dead"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a revocation position from the old history survived: %v", err)
	}
	if _, err := s.Meta(MetaRecoveryPublished); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the recovery copy is still marked current: %v", err)
	}
}
