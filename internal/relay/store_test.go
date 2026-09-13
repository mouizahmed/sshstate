// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const stamp = "2026-09-12T00:00:00Z"

type device struct {
	id      protocol.ID
	signing *crypto.SigningKey
	enc     *crypto.EncryptionKey
}

func newDevice(t *testing.T) device {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := crypto.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	return device{id: protocol.MustNewID(), signing: sk, enc: ek}
}

func (d device) keys() membership.DeviceKeys {
	return membership.DeviceKeys{
		ID:        d.id,
		VerifyKey: d.signing.Verifier().Bytes(),
		Recipient: d.enc.Recipient().String(),
	}
}

type harness struct {
	t       *testing.T
	store   *Store
	genesis *protocol.Genesis
	first   device
	vaultID protocol.ID
	now     time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	first := newDevice(t)
	recovery := newDevice(t)
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
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	root, err := membership.Root(g, first.signing, now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.CreateVault(g, root); err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, store: store, genesis: g, first: first, vaultID: g.VaultID, now: now}
}

func (h *harness) tick() time.Time {
	h.now = h.now.Add(time.Minute)
	return h.now
}

func (h *harness) envelope(by device, recordID protocol.ID, rev protocol.Counter, parent []byte, deleted bool, filler string) *protocol.Envelope {
	h.t.Helper()
	env := &protocol.Envelope{
		Context: protocol.Context{
			Domain:        protocol.RecordDomain,
			FormatVersion: protocol.RecordFormatVersion,
			VaultID:       h.vaultID,
			RecordID:      recordID,
			RecordType:    protocol.RecordHost,
			KeyEpoch:      1,
			Rev:           rev,
			ParentDigest:  parent,
			MutationID:    protocol.MustNewID(),
			UpdatedBy:     by.id,
			Deleted:       deleted,
		},
		Nonce:      bytes.Repeat([]byte{0x11}, 24),
		Ciphertext: []byte("ciphertext:" + filler),
	}
	msg, err := env.SigningInput()
	if err != nil {
		h.t.Fatal(err)
	}
	sig, err := by.signing.Sign(protocol.RecordSignatureDomain, msg)
	if err != nil {
		h.t.Fatal(err)
	}
	env.Signature = sig
	return env
}

func (h *harness) put(env *protocol.Envelope) (*PutOutcome, error) {
	return h.store.PutRecord(h.vaultID, env, stamp)
}

func (h *harness) mustPut(env *protocol.Envelope) *PutOutcome {
	h.t.Helper()
	out, err := h.put(env)
	if err != nil {
		h.t.Fatal(err)
	}
	if !out.Accepted {
		h.t.Fatalf("submission was rejected: %s", out.Code)
	}
	return out
}

func mustCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", want)
	}
	if got := protocol.CodeOf(err); got != want {
		t.Fatalf("got %s (%v), want %s", got, err, want)
	}
}

func TestCreateVaultIsOnce(t *testing.T) {
	h := newHarness(t)
	got, err := h.store.Genesis(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if got.VaultID != h.vaultID {
		t.Fatalf("stored genesis names vault %s", got.VaultID)
	}
	if id, err := h.store.VaultID(); err != nil || id != h.vaultID {
		t.Fatalf("VaultID returned (%s, %v)", id, err)
	}
	if epoch, err := h.store.Epoch(h.vaultID); err != nil || epoch != 1 {
		t.Fatalf("epoch is (%s, %v), want 1", epoch, err)
	}

	second := newHarness(t)
	err = h.store.CreateVault(second.genesis, second.rootEvent(t))
	mustCode(t, err, protocol.CodeBootstrapConsumed)
}

func (h *harness) rootEvent(t *testing.T) protocol.SignedMembershipEvent {
	t.Helper()
	ev, err := membership.Root(h.genesis, h.first.signing, h.now)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestMembershipAppend(t *testing.T) {
	h := newHarness(t)
	chain, err := h.store.Chain(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	second := newDevice(t)
	transcript := bytes.Repeat([]byte{7}, 32)
	ev, err := chain.Enroll(membership.Signer{DeviceID: h.first.id, Key: h.first.signing}, second.keys(), transcript, h.tick())
	if err != nil {
		t.Fatal(err)
	}
	next, err := h.store.AppendMembership(h.vaultID, ev)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Authorized(second.id) {
		t.Fatal("the appended enrolment did not authorize the device")
	}
	if events, err := h.store.Membership(h.vaultID); err != nil || len(events) != 2 {
		t.Fatalf("stored chain has %d events (%v), want 2", len(events), err)
	}

	if _, err := h.store.AppendMembership(h.vaultID, ev); err == nil {
		t.Fatal("the same event appended twice")
	} else {
		mustCode(t, err, protocol.CodeChainMismatch)
	}
}

func TestRecordLifecycle(t *testing.T) {
	h := newHarness(t)
	id := protocol.MustNewID()

	create := h.envelope(h.first, id, 1, nil, false, "one")
	out := h.mustPut(create)
	if out.Seq != 1 {
		t.Fatalf("first accepted change is seq %s, want 1", out.Seq)
	}
	createDigest, err := create.Digest()
	if err != nil {
		t.Fatal(err)
	}

	update := h.envelope(h.first, id, 2, createDigest, false, "two")
	out = h.mustPut(update)
	if out.Seq != 2 {
		t.Fatalf("second accepted change is seq %s, want 2", out.Seq)
	}

	head, err := h.store.Head(h.vaultID, id)
	if err != nil {
		t.Fatal(err)
	}
	if head == nil || head.Context.Rev != 2 || head.Seq != 2 {
		t.Fatalf("head is %+v", head)
	}

	updateDigest, err := update.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.mustPut(h.envelope(h.first, id, 3, updateDigest, true, "gone"))
	head, err = h.store.Head(h.vaultID, id)
	if err != nil {
		t.Fatal(err)
	}
	if !head.Context.Deleted {
		t.Fatal("the tombstone did not become the head")
	}
}

func TestParentMatchingIsExact(t *testing.T) {
	h := newHarness(t)
	id := protocol.MustNewID()
	create := h.envelope(h.first, id, 1, nil, false, "one")
	h.mustPut(create)
	createDigest, err := create.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.mustPut(h.envelope(h.first, id, 2, createDigest, false, "two"))

	wrongParent := h.envelope(h.first, id, 3, bytes.Repeat([]byte{9}, 32), false, "three")
	out, err := h.put(wrongParent)
	if err != nil {
		t.Fatal(err)
	}
	if out.Accepted || out.Code != protocol.CodeParentMismatch {
		t.Fatalf("a wrong parent digest was accepted: %+v", out)
	}
	if out.Head == nil || out.Head.Context.Rev != 2 {
		t.Fatal("the rejection did not carry the current head")
	}

	stale := h.envelope(h.first, id, 2, createDigest, false, "stale")
	out, err = h.put(stale)
	if err != nil {
		t.Fatal(err)
	}
	if out.Accepted {
		t.Fatal("a stale revision was accepted")
	}

	future := h.envelope(h.first, id, 9, bytes.Repeat([]byte{9}, 32), false, "future")
	out, err = h.put(future)
	if err != nil {
		t.Fatal(err)
	}
	if out.Accepted {
		t.Fatal("a future revision was accepted")
	}

	orphan := h.envelope(h.first, protocol.MustNewID(), 2, createDigest, false, "orphan")
	out, err = h.put(orphan)
	if err != nil {
		t.Fatal(err)
	}
	if out.Accepted {
		t.Fatal("an update to a nonexistent record was accepted")
	}
}

func TestIdempotency(t *testing.T) {
	h := newHarness(t)
	id := protocol.MustNewID()
	create := h.envelope(h.first, id, 1, nil, false, "one")
	first := h.mustPut(create)

	again, err := h.put(create)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Replayed || !again.Accepted || again.Seq != first.Seq {
		t.Fatalf("the retry produced a different outcome: %+v", again)
	}
	if seq, err := h.store.CurrentSeq(h.vaultID); err != nil || seq != 1 {
		t.Fatalf("the retry appended a second change: seq %s (%v)", seq, err)
	}

	forged := h.envelope(h.first, id, 1, nil, false, "different")
	forged.Context.MutationID = create.Context.MutationID
	msg, err := forged.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := h.first.signing.Sign(protocol.RecordSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	forged.Signature = sig
	_, err = h.put(forged)
	mustCode(t, err, protocol.CodeIdempotencyMismat)
}

func TestRejectionsAreStable(t *testing.T) {
	h := newHarness(t)
	id := protocol.MustNewID()
	create := h.envelope(h.first, id, 1, nil, false, "one")
	h.mustPut(create)

	loser := h.envelope(h.first, id, 2, bytes.Repeat([]byte{9}, 32), false, "loser")
	first, err := h.put(loser)
	if err != nil {
		t.Fatal(err)
	}
	if first.Accepted {
		t.Fatal("the losing candidate was accepted")
	}

	createDigest, err := create.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.mustPut(h.envelope(h.first, id, 2, createDigest, false, "winner"))

	again, err := h.put(loser)
	if err != nil {
		t.Fatal(err)
	}
	if again.Accepted || again.Code != first.Code || !again.Replayed {
		t.Fatalf("the retried rejection changed: %+v", again)
	}
	if again.Head == nil || again.Head.Context.Rev != 2 {
		t.Fatal("the replayed rejection did not carry the current head")
	}
}

func TestWriterMustBeAuthorized(t *testing.T) {
	h := newHarness(t)
	stranger := newDevice(t)
	_, err := h.put(h.envelope(stranger, protocol.MustNewID(), 1, nil, false, "x"))
	mustCode(t, err, protocol.CodeDeviceUnknown)

	chain, err := h.store.Chain(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	enroll, err := chain.Enroll(membership.Signer{DeviceID: h.first.id, Key: h.first.signing}, stranger.keys(), bytes.Repeat([]byte{7}, 32), h.tick())
	if err != nil {
		t.Fatal(err)
	}
	chain, err = h.store.AppendMembership(h.vaultID, enroll)
	if err != nil {
		t.Fatal(err)
	}
	h.mustPut(h.envelope(stranger, protocol.MustNewID(), 1, nil, false, "allowed"))

	revoke, err := chain.Revoke(membership.Signer{DeviceID: h.first.id, Key: h.first.signing}, stranger.id, h.tick())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AppendMembership(h.vaultID, revoke); err != nil {
		t.Fatal(err)
	}
	_, err = h.put(h.envelope(stranger, protocol.MustNewID(), 1, nil, false, "after revocation"))
	mustCode(t, err, protocol.CodeDeviceRevoked)
}

func TestBadSignatureIsRejected(t *testing.T) {
	h := newHarness(t)
	env := h.envelope(h.first, protocol.MustNewID(), 1, nil, false, "one")
	env.Ciphertext = []byte("substituted after signing")
	_, err := h.put(env)
	mustCode(t, err, protocol.CodeSignatureInvalid)
}

func TestEpochMismatchIsRejected(t *testing.T) {
	h := newHarness(t)
	env := h.envelope(h.first, protocol.MustNewID(), 1, nil, false, "one")
	env.Context.KeyEpoch = 2
	msg, err := env.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := h.first.signing.Sign(protocol.RecordSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	_, err = h.put(env)
	mustCode(t, err, protocol.CodeEpochMismatch)
}

func TestPagination(t *testing.T) {
	h := newHarness(t)
	const total = 25
	for i := 0; i < total; i++ {
		h.mustPut(h.envelope(h.first, protocol.MustNewID(), 1, nil, false, string(rune('a'+i))))
	}

	page, err := h.store.Changes(h.vaultID, 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Changes) != 10 || !page.HasMore {
		t.Fatalf("first page has %d changes, has_more=%v", len(page.Changes), page.HasMore)
	}
	if page.SnapshotCursor != total {
		t.Fatalf("snapshot cursor is %s, want %d", page.SnapshotCursor, total)
	}
	if page.NextCursor != 10 {
		t.Fatalf("next cursor is %s, want 10", page.NextCursor)
	}

	h.mustPut(h.envelope(h.first, protocol.MustNewID(), 1, nil, false, "after the snapshot"))

	seen := len(page.Changes)
	cursor := page.NextCursor
	for page.HasMore {
		page, err = h.store.Changes(h.vaultID, cursor, page.SnapshotCursor, 10)
		if err != nil {
			t.Fatal(err)
		}
		seen += len(page.Changes)
		cursor = page.NextCursor
	}
	if seen != total {
		t.Fatalf("pagination returned %d changes, want %d — the snapshot bound leaked", seen, total)
	}

	page, err = h.store.Changes(h.vaultID, 0, 0, MaxPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	for i, env := range page.Changes {
		if env.Seq != protocol.Counter(i+1) {
			t.Fatalf("change %d has seq %s", i, env.Seq)
		}
	}
	if page.HasMore {
		t.Fatal("a page containing everything reported more")
	}
}

func TestPaginationRejectsInvalidBounds(t *testing.T) {
	h := newHarness(t)
	h.mustPut(h.envelope(h.first, protocol.MustNewID(), 1, nil, false, "one"))

	if _, err := h.store.Changes(h.vaultID, 5, 2, 10); err == nil {
		t.Fatal("since past through was accepted")
	} else {
		mustCode(t, err, protocol.CodeInvalidRequest)
	}
	if _, err := h.store.Changes(h.vaultID, 0, 99, 10); err == nil {
		t.Fatal("a through past the head was accepted")
	} else {
		mustCode(t, err, protocol.CodeInvalidRequest)
	}
}

func TestEmptyVaultPaginates(t *testing.T) {
	h := newHarness(t)
	page, err := h.store.Changes(h.vaultID, 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Changes) != 0 || page.HasMore || page.NextCursor != 0 || page.SnapshotCursor != 0 {
		t.Fatalf("an empty vault paginated as %+v", page)
	}
}

func TestSchemaVersionIsChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE meta SET value = '99' WHERE key = 'schema_version'`); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("a database from a newer server was opened")
	}
}

func TestStoreCreatesRestrictivePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, c := range []struct {
		path string
		want os.FileMode
	}{
		{dir, 0o700},
		{path, 0o600},
	} {
		info, err := os.Stat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != c.want {
			t.Errorf("%s has mode %o, want %o", c.path, got, c.want)
		}
	}
}
