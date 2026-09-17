package syncengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/httpsig"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relay"
	"github.com/mouizahmed/sshstate/internal/relayclient"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const stamp = "2026-09-12T00:00:00Z"

type keys struct {
	id      protocol.ID
	signing *crypto.SigningKey
	enc     *crypto.EncryptionKey
}

func newKeys(t *testing.T) keys {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := crypto.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	return keys{id: protocol.MustNewID(), signing: sk, enc: ek}
}

func (k keys) deviceKeys() membership.DeviceKeys {
	return membership.DeviceKeys{
		ID:        k.id,
		VerifyKey: k.signing.Verifier().Bytes(),
		Recipient: k.enc.Recipient().String(),
	}
}

type device struct {
	t      *testing.T
	keys   keys
	store  *vault.Store
	engine *Engine
}

type world struct {
	t       *testing.T
	genesis *protocol.Genesis
	relay   *relay.Store
	url     string
	first   keys
	now     time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	first := newKeys(t)
	recovery := newKeys(t)
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
	store, err := relay.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.CreateVault(g, root); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.NewServer(store, relay.Config{PublicHTTPS: false}).Handler())
	t.Cleanup(srv.Close)
	return &world{t: t, genesis: g, relay: store, url: srv.URL, first: first, now: now}
}

func (w *world) tick() time.Time {
	w.now = w.now.Add(time.Minute)
	return w.now
}

func (w *world) device(k keys) *device {
	w.t.Helper()
	store, err := vault.OpenStore(filepath.Join(w.t.TempDir(), "vault.db"))
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { store.Close() })
	if err := store.PutGenesis(w.genesis); err != nil {
		w.t.Fatal(err)
	}
	client, err := relayclient.New(relayclient.Options{
		BaseURL: w.url,
		Signer: &httpsig.Signer{
			VaultID:  w.genesis.VaultID,
			DeviceID: k.id,
			Key:      k.signing,
		},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	d := &device{t: w.t, keys: k, store: store}
	d.engine = &Engine{
		Store:    store,
		Client:   client,
		Genesis:  w.genesis,
		Preserve: d.preserve,
	}
	return d
}

func (w *world) enroll(from *device, k keys) {
	w.t.Helper()
	events, err := from.engine.Client.Membership(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	chain, err := membership.Validate(w.genesis, events)
	if err != nil {
		w.t.Fatal(err)
	}
	ev, err := chain.Enroll(membership.Signer{DeviceID: from.keys.id, Key: from.keys.signing},
		k.deviceKeys(), bytes.Repeat([]byte{7}, 32), w.tick())
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := from.engine.Client.AppendMembership(context.Background(), ev); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) revoke(from *device, target protocol.ID) {
	w.t.Helper()
	events, err := from.engine.Client.Membership(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	chain, err := membership.Validate(w.genesis, events)
	if err != nil {
		w.t.Fatal(err)
	}
	ev, err := chain.Revoke(membership.Signer{DeviceID: from.keys.id, Key: from.keys.signing}, target, w.tick())
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := from.engine.Client.AppendMembership(context.Background(), ev); err != nil {
		w.t.Fatal(err)
	}
}

func (d *device) sign(ctx protocol.Context, filler string) *protocol.Envelope {
	d.t.Helper()
	env := &protocol.Envelope{
		Context:    ctx,
		Nonce:      bytes.Repeat([]byte{0x11}, 24),
		Ciphertext: []byte("ciphertext:" + filler),
	}
	msg, err := env.SigningInput()
	if err != nil {
		d.t.Fatal(err)
	}
	sig, err := d.keys.signing.Sign(protocol.RecordSignatureDomain, msg)
	if err != nil {
		d.t.Fatal(err)
	}
	env.Signature = sig
	return env
}

func (d *device) write(vaultID, recordID protocol.ID, filler string, deleted bool) *protocol.Envelope {
	d.t.Helper()
	rev := protocol.Counter(1)
	var parent []byte
	if head, digest, err := d.store.Head(recordID); err == nil {
		rev = head.Context.Rev + 1
		parent = digest
	} else if !errors.Is(err, vault.ErrNotFound) {
		d.t.Fatal(err)
	}
	env := d.sign(protocol.Context{
		Domain:        protocol.RecordDomain,
		FormatVersion: protocol.RecordFormatVersion,
		VaultID:       vaultID,
		RecordID:      recordID,
		RecordType:    protocol.RecordHost,
		KeyEpoch:      1,
		Rev:           rev,
		ParentDigest:  parent,
		MutationID:    protocol.MustNewID(),
		UpdatedBy:     d.keys.id,
		Deleted:       deleted,
	}, filler)
	if err := d.store.ApplyLocalBatch(env); err != nil {
		d.t.Fatal(err)
	}
	return env
}

func (d *device) preserve(candidate, head *protocol.Envelope) (*protocol.Envelope, error) {
	conflictID, err := protocol.ConflictID(
		candidate.Context.VaultID, candidate.Context.RecordID, candidate.Context.MutationID)
	if err != nil {
		return nil, err
	}
	rev := protocol.Counter(1)
	var parent []byte
	if existing, digest, err := d.store.Head(conflictID); err == nil {
		rev = existing.Context.Rev + 1
		parent = digest
	} else if !errors.Is(err, vault.ErrNotFound) {
		return nil, err
	}
	return d.sign(protocol.Context{
		Domain:        protocol.RecordDomain,
		FormatVersion: protocol.RecordFormatVersion,
		VaultID:       candidate.Context.VaultID,
		RecordID:      conflictID,
		RecordType:    protocol.RecordConflictMetadata,
		KeyEpoch:      1,
		Rev:           rev,
		ParentDigest:  parent,
		MutationID:    protocol.MustNewID(),
		UpdatedBy:     d.keys.id,
	}, "preserved:"+string(candidate.Ciphertext)), nil
}

func (d *device) sync() *Report {
	d.t.Helper()
	report, err := d.engine.Sync(context.Background())
	if err != nil {
		d.t.Fatal(err)
	}
	return report
}

func (d *device) head(id protocol.ID) *protocol.Envelope {
	d.t.Helper()
	env, _, err := d.store.Head(id)
	if err != nil {
		d.t.Fatalf("no head for %s: %v", id, err)
	}
	return env
}

func TestTwoDevicesConverge(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)

	prod := protocol.MustNewID()
	a.write(w.genesis.VaultID, prod, "prod v1", false)
	if r := a.sync(); r.Pushed != 1 || !r.Complete {
		t.Fatalf("A's sync: %+v", r)
	}

	r := b.sync()
	if r.Applied != 1 || !r.Complete {
		t.Fatalf("B's sync: %+v", r)
	}
	if got := string(b.head(prod).Ciphertext); got != "ciphertext:prod v1" {
		t.Fatalf("B has %q", got)
	}

	staging := protocol.MustNewID()
	b.write(w.genesis.VaultID, staging, "staging v1", false)
	b.sync()
	a.sync()
	if got := string(a.head(staging).Ciphertext); got != "ciphertext:staging v1" {
		t.Fatalf("A has %q", got)
	}
}

func TestOfflineConflictIsPreserved(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)

	prod := protocol.MustNewID()
	a.write(w.genesis.VaultID, prod, "prod v1", false)
	a.sync()
	b.sync()

	a.write(w.genesis.VaultID, prod, "A's edit", false)
	loser := b.write(w.genesis.VaultID, prod, "B's edit", false)
	a.sync()

	r := b.sync()
	if r.Preserved != 1 {
		t.Fatalf("B preserved %d candidates: %+v", r.Preserved, r)
	}
	if got := string(b.head(prod).Ciphertext); got != "ciphertext:A's edit" {
		t.Fatalf("B's head is %q; acceptance order did not win", got)
	}
	conflictID, err := protocol.ConflictID(w.genesis.VaultID, prod, loser.Context.MutationID)
	if err != nil {
		t.Fatal(err)
	}
	conflict := b.head(conflictID)
	if !bytes.Contains(conflict.Ciphertext, []byte("B's edit")) {
		t.Fatalf("the preserved candidate is %q", conflict.Ciphertext)
	}
	if conflict.Context.RecordType != protocol.RecordConflictMetadata {
		t.Fatalf("the preserved candidate is a %s", conflict.Context.RecordType)
	}
	pending, err := b.store.Outbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Context.RecordID != conflictID {
		t.Fatalf("unexpected outbox after preservation: %+v", pending)
	}
	for _, env := range pending {
		if env.Context.MutationID == loser.Context.MutationID {
			t.Fatal("the rejected candidate is still queued for retry")
		}
	}

	b.sync()
	a.sync()
	if got := a.head(conflictID); got == nil {
		t.Fatal("A never saw the preserved candidate")
	}
}

func TestDeletionReachesALongOfflineDevice(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)

	prod := protocol.MustNewID()
	a.write(w.genesis.VaultID, prod, "prod v1", false)
	a.sync()
	b.sync()

	for i := 0; i < 5; i++ {
		a.write(w.genesis.VaultID, protocol.MustNewID(), "other", false)
	}
	a.write(w.genesis.VaultID, prod, "prod v2", false)
	a.write(w.genesis.VaultID, prod, "", true)
	a.sync()

	b.sync()
	head := b.head(prod)
	if !head.Context.Deleted {
		t.Fatal("the tombstone did not reach the offline device")
	}
	if head.Context.Rev != 3 {
		t.Fatalf("B is at rev %s; intermediate revisions were skipped", head.Context.Rev)
	}
	live, err := b.store.LiveRecords(protocol.RecordHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range live {
		if env.Context.RecordID == prod {
			t.Fatal("a tombstoned record is still live")
		}
	}
}

func TestInterruptedSyncResumes(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)

	for i := 0; i < 5; i++ {
		a.write(w.genesis.VaultID, protocol.MustNewID(), "record", false)
	}
	a.sync()

	b.engine.Client = mustClient(t, w, second)
	first, err := b.engine.Client.Records(context.Background(), 0, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	chain := mustChain(t, w, b)
	if err := b.engine.applyPage(chain, first, &Report{}); err != nil {
		t.Fatal(err)
	}
	cursor, err := b.engine.cursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("cursor is %s after one page of two", cursor)
	}

	r := b.sync()
	if r.Applied != 3 {
		t.Fatalf("the resumed sync applied %d changes, want the remaining 3", r.Applied)
	}
	if !r.Complete {
		t.Fatal("the resumed sync did not reach its snapshot bound")
	}
}

func TestForgedRecordsAreRejectedAndTheCursorHolds(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)

	a.write(w.genesis.VaultID, protocol.MustNewID(), "genuine", false)
	a.sync()
	b.sync()
	before, err := b.engine.cursor()
	if err != nil {
		t.Fatal(err)
	}

	chain := mustChain(t, w, b)
	forged := a.sign(protocol.Context{
		Domain:        protocol.RecordDomain,
		FormatVersion: protocol.RecordFormatVersion,
		VaultID:       w.genesis.VaultID,
		RecordID:      protocol.MustNewID(),
		RecordType:    protocol.RecordHost,
		KeyEpoch:      1,
		Rev:           1,
		MutationID:    protocol.MustNewID(),
		UpdatedBy:     a.keys.id,
	}, "genuine")
	forged.Ciphertext = []byte("substituted after signing")
	forged.Seq = before + 1

	page := &protocol.RecordsResponse{
		Changes:        []protocol.Envelope{*forged},
		NextCursor:     before + 1,
		SnapshotCursor: before + 1,
	}
	if err := b.engine.applyPage(chain, page, &Report{}); err == nil {
		t.Fatal("a tampered envelope was applied")
	}
	after, err := b.engine.cursor()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("the cursor advanced past a rejected page: %s to %s", before, after)
	}
}

func TestForkAtTheHeadRevisionIsRejected(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	prod := protocol.MustNewID()
	a.write(w.genesis.VaultID, prod, "the real one", false)
	a.sync()

	chain := mustChain(t, w, a)
	head := a.head(prod)
	fork := a.sign(head.Context, "a different history")
	fork.Context.MutationID = protocol.MustNewID()
	fork = a.sign(fork.Context, "a different history")
	fork.Seq = head.Seq

	page := &protocol.RecordsResponse{
		Changes:        []protocol.Envelope{*fork},
		NextCursor:     head.Seq,
		SnapshotCursor: head.Seq,
	}
	err := a.engine.applyPage(chain, page, &Report{})
	if err == nil {
		t.Fatal("a fork at the head revision was accepted")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("fork")) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(a.head(prod).Ciphertext); got != "ciphertext:the real one" {
		t.Fatalf("the head became %q", got)
	}
}

func TestRereadingOwnHistoryIsANoOp(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	prod := protocol.MustNewID()
	a.write(w.genesis.VaultID, prod, "v1", false)
	a.sync()
	a.write(w.genesis.VaultID, prod, "v2", false)
	a.write(w.genesis.VaultID, prod, "v3", false)
	a.sync()

	if err := a.store.SetCursor(vault.CursorRecords, "0"); err != nil {
		t.Fatal(err)
	}
	r := a.sync()
	if r.Applied != 0 {
		t.Fatalf("re-reading applied %d changes, want none", r.Applied)
	}
	if !r.Complete {
		t.Fatal("the re-read did not complete")
	}
	if a.head(prod).Context.Rev != 3 {
		t.Fatalf("the head moved to rev %s", a.head(prod).Context.Rev)
	}
}

func TestUnknownWriterIsRejected(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	stranger := w.device(newKeys(t))
	chain := mustChain(t, w, a)

	env := stranger.sign(protocol.Context{
		Domain:        protocol.RecordDomain,
		FormatVersion: protocol.RecordFormatVersion,
		VaultID:       w.genesis.VaultID,
		RecordID:      protocol.MustNewID(),
		RecordType:    protocol.RecordHost,
		KeyEpoch:      1,
		Rev:           1,
		MutationID:    protocol.MustNewID(),
		UpdatedBy:     stranger.keys.id,
	}, "from nowhere")
	env.Seq = 1
	if err := a.engine.verify(chain, env); err == nil {
		t.Fatal("a record from an unenrolled device verified")
	}
}

func TestRevokedWritesAfterTheObservationAreRejected(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)

	early := protocol.MustNewID()
	b.write(w.genesis.VaultID, early, "before revocation", false)
	b.sync()
	a.sync()

	w.revoke(a, second.id)
	a.sync()

	if got := string(a.head(early).Ciphertext); got != "ciphertext:before revocation" {
		t.Fatalf("an earlier write from a revoked device was dropped: %q", got)
	}

	chain := mustChain(t, w, a)
	at, err := a.engine.cursor()
	if err != nil {
		t.Fatal(err)
	}
	late := b.sign(protocol.Context{
		Domain:        protocol.RecordDomain,
		FormatVersion: protocol.RecordFormatVersion,
		VaultID:       w.genesis.VaultID,
		RecordID:      protocol.MustNewID(),
		RecordType:    protocol.RecordHost,
		KeyEpoch:      1,
		Rev:           1,
		MutationID:    protocol.MustNewID(),
		UpdatedBy:     b.keys.id,
	}, "after revocation")
	late.Seq = at + 1
	if err := a.engine.verify(chain, late); err == nil {
		t.Fatal("a revoked device's later write was accepted")
	}
}

func TestRevokedDeviceCannotPublish(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)
	b.sync()

	w.revoke(a, second.id)

	b.write(w.genesis.VaultID, protocol.MustNewID(), "after revocation", false)
	_, err := b.engine.Sync(context.Background())
	if err == nil {
		t.Fatal("a revoked device published successfully")
	}
	if code := protocol.CodeOf(err); code != protocol.CodeDeviceRevoked {
		t.Fatalf("the relay refused with %s, want device_revoked", code)
	}
}

func TestEngineRequiresAPreserver(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	a.engine.Preserve = nil
	if _, err := a.engine.Sync(context.Background()); err == nil {
		t.Fatal("an engine with no preserver synced")
	}
}

func mustClient(t *testing.T, w *world, k keys) *relayclient.Client {
	t.Helper()
	client, err := relayclient.New(relayclient.Options{
		BaseURL: w.url,
		Signer:  &httpsig.Signer{VaultID: w.genesis.VaultID, DeviceID: k.id, Key: k.signing},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func mustChain(t *testing.T, w *world, d *device) *membership.Chain {
	t.Helper()
	events, err := d.engine.Client.Membership(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	chain, err := membership.Validate(w.genesis, events)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

func TestDeleteEditRacePreservesTheEditWithoutResurrecting(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	b := w.device(second)

	prod := protocol.MustNewID()
	a.write(w.genesis.VaultID, prod, "prod v1", false)
	a.sync()
	b.sync()

	a.write(w.genesis.VaultID, prod, "", true)
	loser := b.write(w.genesis.VaultID, prod, "B's edit", false)
	a.sync()

	r := b.sync()
	if r.Preserved != 1 {
		t.Fatalf("B preserved %d candidates: %+v", r.Preserved, r)
	}

	head := b.head(prod)
	if !head.Context.Deleted {
		t.Fatal("the edit resurrected a deleted record")
	}
	live, err := b.store.LiveRecords(protocol.RecordHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range live {
		if env.Context.RecordID == prod {
			t.Fatal("a tombstoned record is live again")
		}
	}

	conflictID, err := protocol.ConflictID(w.genesis.VaultID, prod, loser.Context.MutationID)
	if err != nil {
		t.Fatal(err)
	}
	conflict := b.head(conflictID)
	if !bytes.Contains(conflict.Ciphertext, []byte("B's edit")) {
		t.Fatalf("the preserved candidate is %q", conflict.Ciphertext)
	}
}

func TestAShorterMembershipChainIsNotAdopted(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	second := newKeys(t)
	w.enroll(a, second)
	a.sync()

	before, err := a.store.MembershipEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 {
		t.Fatalf("expected the root and the enrolment, got %d", len(before))
	}

	lying := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(protocol.MembershipResponse{Events: before[:1]})
	}))
	defer lying.Close()

	chain, err := membership.Validate(w.genesis, before[:1])
	if err != nil {
		t.Fatalf("the truncated chain does not even validate, so this test proves nothing: %v", err)
	}
	if chain.Len() != 1 {
		t.Fatal("unexpected truncated chain")
	}

	a.engine.Client = clientFor(t, lying.URL, w.first)
	if _, err := a.engine.Sync(context.Background()); err != nil {
		t.Logf("sync against the truncating relay failed: %v", err)
	}
	after, err := a.store.MembershipEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) < len(before) {
		t.Fatalf("the stored chain shrank from %d to %d events", len(before), len(after))
	}
	if _, err := a.store.Device(second.id); err != nil {
		t.Fatalf("the enrolled device vanished from local membership: %v", err)
	}
}

func TestRecordRollbackIsRefused(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	prod := protocol.MustNewID()
	first := a.write(w.genesis.VaultID, prod, "v1", false)
	a.sync()
	a.write(w.genesis.VaultID, prod, "v2", false)
	a.sync()

	chain := mustChain(t, w, a)
	old := *first
	old.Seq = 99
	page := &protocol.RecordsResponse{
		Changes:        []protocol.Envelope{old},
		NextCursor:     99,
		SnapshotCursor: 99,
	}
	if err := a.engine.applyPage(chain, page, &Report{}); err != nil {
		t.Fatalf("re-serving an old revision should be ignored, not fail: %v", err)
	}
	if got := a.head(prod).Context.Rev; got != 2 {
		t.Fatalf("the head moved back to rev %s", got)
	}
	if got := string(a.head(prod).Ciphertext); got != "ciphertext:v2" {
		t.Fatalf("the head content rolled back to %q", got)
	}
}

func clientFor(t *testing.T, url string, k keys) *relayclient.Client {
	t.Helper()
	client, err := relayclient.New(relayclient.Options{
		BaseURL: url,
		Signer:  &httpsig.Signer{VaultID: protocol.MustNewID(), DeviceID: k.id, Key: k.signing},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestARelayRolledBackBehindThisDeviceIsNamed(t *testing.T) {
	w := newWorld(t)
	a := w.device(w.first)
	record := protocol.MustNewID()
	a.write(w.genesis.VaultID, record, "one", false)
	a.sync()
	a.write(w.genesis.VaultID, record, "two", false)
	if err := a.store.SetCursor(vault.CursorRecords, "40"); err != nil {
		t.Fatal(err)
	}
	_, err := a.engine.Sync(context.Background())
	var behind *RelayBehindError
	if !errors.As(err, &behind) {
		t.Fatalf("want RelayBehindError, got %v", err)
	}
	if behind.Local != 40 || behind.Relay != 1 {
		t.Fatalf("got %+v, want local 40 and relay 1", behind)
	}
	if !strings.Contains(err.Error(), "restored from an older backup") {
		t.Fatalf("unhelpful message: %v", err)
	}
	pending, err := a.store.Outbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("a local edit was pushed to a relay that had fallen behind: %d still queued", len(pending))
	}
	if got := string(a.head(record).Ciphertext); got != "ciphertext:two" {
		t.Fatalf("the local head was replaced by the relay's older copy: %q", got)
	}
}
