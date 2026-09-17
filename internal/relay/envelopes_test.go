package relay

import (
	"bytes"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

func (h *harness) envelopeFor(recipient protocol.ID, purpose protocol.BundlePurpose, epoch protocol.Counter, body string) KeyEnvelope {
	return KeyEnvelope{
		ID:                protocol.MustNewID(),
		RecipientDeviceID: recipient,
		Purpose:           purpose,
		KeyEpoch:          epoch,
		Ciphertext:        []byte("age-sealed:" + body),
		CreatedAt:         stamp,
	}
}

func TestKeyEnvelopesAreScopedToTheirRecipient(t *testing.T) {
	h := newHarness(t)
	second := newDevice(t)
	chain, err := h.store.Chain(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	enroll, err := chain.Enroll(membership.Signer{DeviceID: h.first.id, Key: h.first.signing}, second.keys(), bytes.Repeat([]byte{7}, 32), h.tick())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AppendMembership(h.vaultID, enroll); err != nil {
		t.Fatal(err)
	}

	mine := h.envelopeFor(h.first.id, protocol.PurposeRotation, 1, "for first")
	theirs := h.envelopeFor(second.id, protocol.PurposeEnrollment, 1, "for second")
	for _, env := range []KeyEnvelope{mine, theirs} {
		if err := h.store.PutKeyEnvelope(h.vaultID, env); err != nil {
			t.Fatal(err)
		}
	}

	got, err := h.store.KeyEnvelopesFor(h.vaultID, h.first.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != mine.ID {
		t.Fatalf("a device saw %d envelopes, and not only its own: %+v", len(got), got)
	}
	if string(got[0].Ciphertext) != string(mine.Ciphertext) || got[0].Purpose != protocol.PurposeRotation {
		t.Fatalf("the stored envelope came back changed: %+v", got[0])
	}
}

func TestRevokedDevicesReceiveNoKeyMaterial(t *testing.T) {
	h := newHarness(t)
	second := newDevice(t)
	chain, err := h.store.Chain(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	enroll, err := chain.Enroll(membership.Signer{DeviceID: h.first.id, Key: h.first.signing}, second.keys(), bytes.Repeat([]byte{7}, 32), h.tick())
	if err != nil {
		t.Fatal(err)
	}
	chain, err = h.store.AppendMembership(h.vaultID, enroll)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutKeyEnvelope(h.vaultID, h.envelopeFor(second.id, protocol.PurposeEnrollment, 1, "before")); err != nil {
		t.Fatal(err)
	}

	revoke, err := chain.Revoke(membership.Signer{DeviceID: h.first.id, Key: h.first.signing}, second.id, h.tick())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AppendMembership(h.vaultID, revoke); err != nil {
		t.Fatal(err)
	}

	err = h.store.PutKeyEnvelope(h.vaultID, h.envelopeFor(second.id, protocol.PurposeRotation, 2, "after"))
	mustCode(t, err, protocol.CodeDeviceRevoked)

	err = h.store.PutKeyEnvelope(h.vaultID, h.envelopeFor(protocol.MustNewID(), protocol.PurposeRotation, 2, "stranger"))
	mustCode(t, err, protocol.CodeDeviceUnknown)
}

func TestRecoveryEnvelopeTracksTheLatestEpoch(t *testing.T) {
	h := newHarness(t)
	if _, err := h.store.RecoveryEnvelope(h.vaultID); err == nil {
		t.Fatal("a vault with no recovery envelope returned one")
	} else {
		mustCode(t, err, protocol.CodeNotFound)
	}

	first := h.envelopeFor("", protocol.PurposeRecovery, 1, "epoch one")
	if err := h.store.PutKeyEnvelope(h.vaultID, first); err != nil {
		t.Fatal(err)
	}
	second := h.envelopeFor("", protocol.PurposeRecovery, 2, "epoch two")
	if err := h.store.PutKeyEnvelope(h.vaultID, second); err != nil {
		t.Fatal(err)
	}

	got, err := h.store.RecoveryEnvelope(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != second.ID || got.KeyEpoch != 2 {
		t.Fatalf("recovery returned epoch %s (%s), want the latest", got.KeyEpoch, got.ID)
	}
	mine, err := h.store.KeyEnvelopesFor(h.vaultID, h.first.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 0 {
		t.Fatalf("recovery envelopes leaked into a device's list: %+v", mine)
	}
}

func TestTheNewestRecoveryUploadIsTheOneServed(t *testing.T) {
	h := newHarness(t)
	older := h.envelopeFor("", protocol.PurposeRecovery, 1, "older")
	older.ID = "ffffffffffffffffffffffffffffffff"
	newer := h.envelopeFor("", protocol.PurposeRecovery, 1, "newer")
	newer.ID = "00000000000000000000000000000000"
	for _, env := range []KeyEnvelope{older, newer} {
		if err := h.store.PutKeyEnvelope(h.vaultID, env); err != nil {
			t.Fatal(err)
		}
	}
	got, err := h.store.RecoveryEnvelope(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Ciphertext) != string(newer.Ciphertext) {
		t.Fatalf("served %q, want the newest upload", got.Ciphertext)
	}

	stale := h.envelopeFor("", protocol.PurposeRecovery, 1, "stale epoch")
	later := h.envelopeFor("", protocol.PurposeRecovery, 2, "later epoch")
	if err := h.store.PutKeyEnvelope(h.vaultID, later); err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutKeyEnvelope(h.vaultID, stale); err != nil {
		t.Fatal(err)
	}
	got, err = h.store.RecoveryEnvelope(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyEpoch != 2 {
		t.Fatalf("an upload for an older epoch displaced epoch %s", got.KeyEpoch)
	}
}

func TestKeyEnvelopeRejectsMalformedInput(t *testing.T) {
	h := newHarness(t)
	base := h.envelopeFor(h.first.id, protocol.PurposeRotation, 1, "body")
	for name, mutate := range map[string]func(*KeyEnvelope){
		"bad id":        func(e *KeyEnvelope) { e.ID = "nope" },
		"bad recipient": func(e *KeyEnvelope) { e.RecipientDeviceID = "nope" },
		"bad purpose":   func(e *KeyEnvelope) { e.Purpose = "sharing" },
		"no ciphertext": func(e *KeyEnvelope) { e.Ciphertext = nil },
		"zero epoch":    func(e *KeyEnvelope) { e.KeyEpoch = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			env := base
			mutate(&env)
			if err := h.store.PutKeyEnvelope(h.vaultID, env); err == nil {
				t.Fatal("the envelope was stored")
			}
		})
	}
}

func TestRecoveryChallengeIsConsumedOnce(t *testing.T) {
	h := newHarness(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	h.store.Now = func() time.Time { return now }

	nonce, expires, err := h.store.NewRecoveryChallenge(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if expires.Sub(now) != RecoveryChallengeTTL {
		t.Fatalf("challenge lasts %s, want %s", expires.Sub(now), RecoveryChallengeTTL)
	}
	if err := h.store.ConsumeRecoveryChallenge(h.vaultID, nonce); err != nil {
		t.Fatal(err)
	}
	mustCode(t, h.store.ConsumeRecoveryChallenge(h.vaultID, nonce), protocol.CodeNotAuthorized)
	mustCode(t, h.store.ConsumeRecoveryChallenge(h.vaultID, "invented"), protocol.CodeNotAuthorized)
}

func TestRecoveryChallengeExpires(t *testing.T) {
	h := newHarness(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	h.store.Now = func() time.Time { return now }

	nonce, _, err := h.store.NewRecoveryChallenge(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(RecoveryChallengeTTL + time.Second)
	mustCode(t, h.store.ConsumeRecoveryChallenge(h.vaultID, nonce), protocol.CodeNotAuthorized)
}

func TestRecoveryChallengesAreDistinct(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		nonce, _, err := h.store.NewRecoveryChallenge(h.vaultID)
		if err != nil {
			t.Fatal(err)
		}
		if seen[nonce] {
			t.Fatal("a recovery challenge repeated")
		}
		seen[nonce] = true
	}
}
