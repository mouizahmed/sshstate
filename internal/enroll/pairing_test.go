// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"bytes"
	"context"
	"encoding/json"
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
)

const stamp0 = "2026-09-12T00:00:00Z"

func newIdentity(t *testing.T) Identity {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := crypto.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	return Identity{DeviceID: protocol.MustNewID(), Signing: sk, Encryption: ek}
}

type world struct {
	t       *testing.T
	genesis *protocol.Genesis
	store   *relay.Store
	url     string
	first   Identity
	now     time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	first := newIdentity(t)
	recovery := newIdentity(t)
	g := &protocol.Genesis{
		Domain:               protocol.GenesisDomain,
		FormatVersion:        protocol.GenesisFormatVersion,
		Suite:                crypto.SuiteID,
		VaultID:              protocol.MustNewID(),
		CreatedAt:            stamp0,
		FirstDeviceID:        first.DeviceID,
		FirstDeviceVerifyKey: first.Signing.Verifier().Bytes(),
		FirstDeviceRecipient: first.Encryption.Recipient().String(),
		RecoveryVerifyKey:    recovery.Signing.Verifier().Bytes(),
		RecoveryRecipient:    recovery.Encryption.Recipient().String(),
	}
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	root, err := membership.Root(g, first.Signing, now)
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
	w := &world{t: t, genesis: g, store: store, url: srv.URL, first: first, now: now}
	store.Now = func() time.Time { return w.now }
	return w
}

func (w *world) signed(id Identity) *relayclient.Client {
	w.t.Helper()
	c, err := relayclient.New(relayclient.Options{
		BaseURL: w.url,
		Signer: &httpsig.Signer{
			VaultID:  w.genesis.VaultID,
			DeviceID: id.DeviceID,
			Key:      id.Signing,
			Now:      func() time.Time { return w.now },
		},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return c
}

func (w *world) unsigned() *relayclient.Client {
	w.t.Helper()
	c, err := relayclient.New(relayclient.Options{BaseURL: w.url})
	if err != nil {
		w.t.Fatal(err)
	}
	return c
}

func (w *world) clock() func() time.Time { return func() time.Time { return w.now } }

func (w *world) keyBundle(t *testing.T, joiner Identity, transcriptDigest []byte, snapshotDigest []byte, snapshotLength protocol.Counter) *protocol.Bundle {
	t.Helper()
	genesisDigest, err := w.genesis.Digest()
	if err != nil {
		t.Fatal(err)
	}
	recipientID := joiner.DeviceID
	b := &protocol.Bundle{
		Domain:            protocol.BundleDomain,
		FormatVersion:     protocol.BundleFormatVersion,
		Suite:             crypto.SuiteID,
		VaultID:           w.genesis.VaultID,
		GenesisDigest:     genesisDigest,
		Purpose:           protocol.PurposeEnrollment,
		RecipientDeviceID: &recipientID,
		Recipient:         joiner.Encryption.Recipient().String(),
		KeyEpoch:          1,
		MetadataKey:       bytes.Repeat([]byte{0x10}, protocol.VaultKeyBytes),
		SecretKey:         bytes.Repeat([]byte{0x20}, protocol.VaultKeyBytes),
		TranscriptDigest:  transcriptDigest,
		Checkpoint: protocol.Checkpoint{
			Domain:           protocol.CheckpointDomain,
			FormatVersion:    protocol.CheckpointFormatVer,
			VaultID:          w.genesis.VaultID,
			KeyEpoch:         1,
			Seq:              0,
			MembershipDigest: bytes.Repeat([]byte{0x30}, 32),
			CreatedAt:        stamp0,
		},
		CreatedAt: stamp0,
	}
	if snapshotDigest != nil {
		length := snapshotLength
		b.SnapshotDigest = snapshotDigest
		b.SnapshotLength = &length
	}
	return b
}

func pair(t *testing.T, w *world, joiner Identity, snapshot []byte) (*Delivery, *Joiner) {
	t.Helper()
	ctx := context.Background()

	j, err := Begin(ctx, w.signed(joiner), w.genesis, joiner, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(ctx, w.signed(w.first), w.genesis, j.SessionID(), w.first, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Transcript(ctx); err != nil {
		t.Fatal(err)
	}

	jf, err := j.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	af, err := a.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if jf != af {
		t.Fatalf("the two devices displayed different fingerprints:\n  %s\n  %s", jf, af)
	}

	if err := j.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	ready, err := a.AwaitJoiner(ctx)
	if err != nil || !ready {
		t.Fatalf("the approver did not see the joiner's confirmation (%v, %v)", ready, err)
	}

	digest, err := a.Transcript().Digest()
	if err != nil {
		t.Fatal(err)
	}
	events, err := w.signed(w.first).Membership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := membership.Validate(w.genesis, events)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := chain.Enroll(membership.Signer{DeviceID: w.first.DeviceID, Key: w.first.Signing},
		a.JoinerKeys(), digest, w.now)
	if err != nil {
		t.Fatal(err)
	}

	var sealedSnapshot, snapshotDigest []byte
	var snapshotLength protocol.Counter
	if snapshot != nil {
		sealedSnapshot, snapshotDigest, snapshotLength, err = SealSnapshot(snapshot, mustRecipient(t, a.JoinerKeys().Recipient))
		if err != nil {
			t.Fatal(err)
		}
	}
	bundle := w.keyBundle(t, joiner, digest, snapshotDigest, snapshotLength)
	sealed, err := SealBundle(bundle, w.first.Signing, mustRecipient(t, bundle.Recipient))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(ctx, ev, sealed, sealedSnapshot); err != nil {
		t.Fatal(err)
	}

	delivery, err := j.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Acknowledge(ctx); err != nil {
		t.Fatal(err)
	}
	return delivery, j
}

func mustRecipient(t *testing.T, s string) *crypto.Recipient {
	t.Helper()
	r, err := crypto.ParseRecipient(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPairingDeliversTheVaultKeys(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)

	records := []*protocol.Envelope{}
	snapshot, err := BuildSnapshot(records)
	if err != nil {
		t.Fatal(err)
	}
	delivery, j := pair(t, w, joiner, snapshot)

	if delivery.Bundle.KeyEpoch != 1 {
		t.Fatalf("bundle epoch is %s", delivery.Bundle.KeyEpoch)
	}
	if !bytes.Equal(delivery.Bundle.MetadataKey, bytes.Repeat([]byte{0x10}, protocol.VaultKeyBytes)) {
		t.Fatal("the metadata key did not survive the round trip")
	}
	if delivery.Event.Event.DeviceID != joiner.DeviceID {
		t.Fatal("the enrolment names another device")
	}

	if _, err := j.Receive(context.Background()); err == nil {
		t.Fatal("a completed session was read back as live")
	} else if protocol.CodeOf(err) != protocol.CodePairingConsumed {
		t.Fatalf("unexpected error: %v", err)
	}

	chainEvents, err := w.signed(joiner).Membership(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	chain, err := membership.Validate(w.genesis, chainEvents)
	if err != nil {
		t.Fatal(err)
	}
	if !chain.Authorized(joiner.DeviceID) {
		t.Fatal("the enrolled device is not authorized")
	}
}

func TestPairingCarriesASnapshot(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)

	env := &protocol.Envelope{
		Context: protocol.Context{
			Domain:        protocol.RecordDomain,
			FormatVersion: protocol.RecordFormatVersion,
			VaultID:       w.genesis.VaultID,
			RecordID:      protocol.MustNewID(),
			RecordType:    protocol.RecordHost,
			KeyEpoch:      1,
			Rev:           1,
			MutationID:    protocol.MustNewID(),
			UpdatedBy:     w.first.DeviceID,
		},
		Nonce:      bytes.Repeat([]byte{0x11}, 24),
		Ciphertext: []byte("ciphertext"),
		Signature:  bytes.Repeat([]byte{0x40}, 3309),
	}
	snapshot, err := BuildSnapshot([]*protocol.Envelope{env})
	if err != nil {
		t.Fatal(err)
	}
	delivery, _ := pair(t, w, joiner, snapshot)
	if len(delivery.Snapshot) != 1 {
		t.Fatalf("the snapshot carried %d records", len(delivery.Snapshot))
	}
	if delivery.Snapshot[0].Context.RecordID != env.Context.RecordID {
		t.Fatal("the snapshot record changed in transit")
	}
}

func TestNoKeysBeforeBothConfirmations(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)
	ctx := context.Background()

	j, err := Begin(ctx, w.signed(joiner), w.genesis, joiner, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(ctx, w.signed(w.first), w.genesis, j.SessionID(), w.first, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Confirm(ctx); err != nil {
		t.Fatal(err)
	}

	ready, err := a.AwaitJoiner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ready {
		t.Fatal("the approver believed an unconfirmed joiner had confirmed")
	}
	digest, err := a.Transcript().Digest()
	if err != nil {
		t.Fatal(err)
	}
	bundle := w.keyBundle(t, joiner, digest, nil, 0)
	sealed, err := SealBundle(bundle, w.first.Signing, mustRecipient(t, bundle.Recipient))
	if err != nil {
		t.Fatal(err)
	}
	events, err := w.signed(w.first).Membership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := membership.Validate(w.genesis, events)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := chain.Enroll(membership.Signer{DeviceID: w.first.DeviceID, Key: w.first.Signing},
		a.JoinerKeys(), digest, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(ctx, ev, sealed, nil); err == nil {
		t.Fatal("keys were delivered before the joiner confirmed")
	}

	_, err = w.signed(w.first).CompletePairing(ctx, j.SessionID(), protocol.CompletePairingRequest{
		MembershipEvent: &ev, Bundle: sealed,
	})
	if code := protocol.CodeOf(err); code != protocol.CodePairingIncomplete {
		t.Fatalf("the relay answered %s, want pairing_incomplete", code)
	}

	after, err := w.signed(w.first).Membership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	finalChain, err := membership.Validate(w.genesis, after)
	if err != nil {
		t.Fatal(err)
	}
	if _, seen := finalChain.Device(joiner.DeviceID); seen {
		t.Fatal("the device was enrolled before its user confirmed the fingerprint")
	}
	session, err := w.unsigned().Pairing(ctx, j.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Bundle) != 0 {
		t.Fatal("a bundle reached the session before both confirmations")
	}
}

func TestBundleFromTheWrongSignerIsRejected(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)
	impostor := newIdentity(t)

	bundle := w.keyBundle(t, joiner, bytes.Repeat([]byte{7}, 32), nil, 0)
	sealed, err := SealBundle(bundle, impostor.Signing, mustRecipient(t, bundle.Recipient))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(sealed, joiner.Encryption, w.first.Signing.Verifier()); err == nil {
		t.Fatal("a bundle signed by an impostor was accepted")
	}
	sealed, err = SealBundle(bundle, w.first.Signing, mustRecipient(t, bundle.Recipient))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(sealed, joiner.Encryption, w.first.Signing.Verifier()); err != nil {
		t.Fatal(err)
	}
}

func TestBundleIsOnlyReadableByItsRecipient(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)
	eavesdropper := newIdentity(t)

	bundle := w.keyBundle(t, joiner, bytes.Repeat([]byte{7}, 32), nil, 0)
	sealed, err := SealBundle(bundle, w.first.Signing, mustRecipient(t, bundle.Recipient))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(sealed, eavesdropper.Encryption, w.first.Signing.Verifier()); err == nil {
		t.Fatal("a bundle was readable by a device it was not addressed to")
	}
}

func TestSnapshotSubstitutionIsDetected(t *testing.T) {
	joiner := newIdentity(t)
	recipient := mustRecipient(t, joiner.Encryption.Recipient().String())

	genuine, err := BuildSnapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, length, err := SealSnapshot(genuine, recipient)
	if err != nil {
		t.Fatal(err)
	}
	substituted, err := crypto.SealBounded([]byte("not the snapshot\n"), MaxSnapshotBytes, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSnapshot(substituted, joiner.Encryption, digest, length); err == nil {
		t.Fatal("a substituted snapshot was accepted")
	}
}

func TestKeySubstitutionChangesTheFingerprint(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)
	attacker := newIdentity(t)
	ctx := context.Background()

	j, err := Begin(ctx, w.signed(joiner), w.genesis, joiner, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(ctx, w.signed(w.first), w.genesis, j.SessionID(), w.first, w.clock())
	if err != nil {
		t.Fatal(err)
	}

	substituted := *a.session.Offer
	substituted.JoinerVerifyKey = attacker.Signing.Verifier().Bytes()
	substituted.JoinerRecipient = attacker.Encryption.Recipient().String()
	deceived, err := protocol.BuildTranscript(j.SessionID(), substituted, a.approval, crypto.SuiteID)
	if err != nil {
		t.Fatal(err)
	}

	honest, err := a.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := deceived.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if honest == forged {
		t.Fatal("substituting the joiner's key left the fingerprint unchanged")
	}
	differing := 0
	for i := 0; i < protocol.FingerprintGroupCount; i++ {
		if honest[i*4:(i+1)*4] != forged[i*4:(i+1)*4] {
			differing++
		}
	}
	if differing < protocol.FingerprintGroupCount/2 {
		t.Fatalf("only %d of %d groups differ", differing, protocol.FingerprintGroupCount)
	}
}

func TestJoinerRefusesAConfirmationOverAnotherTranscript(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)
	attacker := newIdentity(t)
	ctx := context.Background()

	j, err := Begin(ctx, w.signed(joiner), w.genesis, joiner, w.clock())
	if err != nil {
		t.Fatal(err)
	}

	lying := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		session, err := w.unsigned().Pairing(ctx, j.SessionID())
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		session.Offer.JoinerVerifyKey = attacker.Signing.Verifier().Bytes()
		session.Offer.JoinerRecipient = attacker.Encryption.Recipient().String()
		msg, err := session.Offer.SigningInput()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		sig, err := attacker.Signing.Sign(protocol.PairingOfferDomain, msg)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		session.OfferSignature = sig
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(session)
	}))
	defer lying.Close()

	hostile, err := relayclient.New(relayclient.Options{BaseURL: lying.URL})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(ctx, hostile, w.genesis, j.SessionID(), w.first, w.clock())
	if err != nil {
		t.Fatalf("the substituted offer was self-consistent and should have parsed: %v", err)
	}
	if err := publishApproverHalf(t, w, a); err != nil {
		t.Fatal(err)
	}

	if _, err := j.Transcript(ctx); err == nil {
		t.Fatal("the joiner accepted a confirmation over a transcript it did not build")
	}
}

func publishApproverHalf(t *testing.T, w *world, a *Approver) error {
	t.Helper()
	conf, err := signConfirmation(a.Transcript(), w.first, w.now)
	if err != nil {
		return err
	}
	approval := a.approval
	_, err = w.signed(w.first).ConfirmPairing(context.Background(), a.sessionID,
		protocol.ConfirmPairingRequest{
			Approver:     &approval,
			Confirmation: conf.Confirmation,
			Signature:    conf.Signature,
		})
	return err
}

func TestPairingExpires(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)
	ctx := context.Background()

	j, err := Begin(ctx, w.signed(joiner), w.genesis, joiner, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(ctx, w.signed(w.first), w.genesis, j.SessionID(), w.first, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	w.now = w.now.Add(protocol.PairingLifetime + time.Second)
	w.store.Now = func() time.Time { return w.now }

	if err := a.Confirm(ctx); err == nil {
		t.Fatal("an expired session accepted a confirmation")
	} else if protocol.CodeOf(err) != protocol.CodePairingExpired {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := j.Transcript(ctx); err == nil {
		t.Fatal("an expired session produced a transcript")
	}
}

func TestFingerprintIsShownInFull(t *testing.T) {
	w := newWorld(t)
	joiner := newIdentity(t)
	ctx := context.Background()

	j, err := Begin(ctx, w.signed(joiner), w.genesis, joiner, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(ctx, w.signed(w.first), w.genesis, j.SessionID(), w.first, w.clock())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Transcript(ctx); err != nil {
		t.Fatal(err)
	}
	fp, err := j.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != protocol.FingerprintChars {
		t.Fatalf("the fingerprint is %d characters", len(fp))
	}
	digest, err := a.Transcript().Digest()
	if err != nil {
		t.Fatal(err)
	}
	block, err := protocol.FormatFingerprint(digest)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := protocol.FingerprintGroups(digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if !strings.Contains(block, g) {
			t.Fatalf("group %s is missing from the display:\n%s", g, block)
		}
	}
}
