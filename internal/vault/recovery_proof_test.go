// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"errors"
	"testing"
	"time"
)

func unconfirmedVault(t *testing.T) (*Manager, *Kit) {
	t.Helper()
	s := newStore(t)
	m, kit, err := Init(s, InitOptions{Password: []byte(testPassword), DeviceLabel: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return m, kit
}

func signChallenge(t *testing.T, kit *Kit, nonce []byte) []byte {
	t.Helper()
	signing, _, err := kit.Keys()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signing.Sign(RecoveryConfirmDomain, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestRecoveryProofConfirmsTheVault(t *testing.T) {
	m, kit := unconfirmedVault(t)
	if _, err := m.AddKey(testKey(t, "k")); !errors.Is(err, ErrRecoveryUnconfirmed) {
		t.Fatalf("wrote before confirmation: %v", err)
	}
	nonce, err := m.RecoveryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryProof(nonce, signChallenge(t, kit, nonce)); err != nil {
		t.Fatal(err)
	}
	if !m.RecoveryConfirmed() {
		t.Fatal("a valid proof did not confirm the vault")
	}
	if _, err := m.AddKey(testKey(t, "k")); err != nil {
		t.Fatalf("the confirmed vault still refuses writes: %v", err)
	}
}

func TestRecoveryProofRejectsAnotherVaultsKit(t *testing.T) {
	m, _ := unconfirmedVault(t)
	_, otherKit := unconfirmedVault(t)
	nonce, err := m.RecoveryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryProof(nonce, signChallenge(t, otherKit, nonce)); err == nil {
		t.Fatal("another vault's kit was accepted")
	}
	if m.RecoveryConfirmed() {
		t.Fatal("a rejected proof confirmed the vault anyway")
	}
}

func TestRecoveryChallengeIsSingleUse(t *testing.T) {
	m, kit := unconfirmedVault(t)
	first, err := m.RecoveryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	signature := signChallenge(t, kit, first)

	second, err := m.RecoveryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryProof(first, signature); err == nil {
		t.Fatal("a superseded challenge was accepted")
	}
	if err := m.ConfirmRecoveryProof(second, signChallenge(t, kit, second)); err == nil {
		t.Fatal("the challenge survived a failed attempt")
	}

	third, err := m.RecoveryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryProof(third, signChallenge(t, kit, third)); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryChallengeExpires(t *testing.T) {
	m, kit := unconfirmedVault(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	nonce, err := m.RecoveryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(recoveryChallengeTTL + time.Second)
	if err := m.ConfirmRecoveryProof(nonce, signChallenge(t, kit, nonce)); err == nil {
		t.Fatal("an expired challenge was accepted")
	}
}

func TestRecoveryProofIsDomainSeparated(t *testing.T) {
	m, kit := unconfirmedVault(t)
	nonce, err := m.RecoveryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	signing, _, err := kit.Keys()
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain, err := signing.Sign("sshstate.record.v1", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryProof(nonce, wrongDomain); err == nil {
		t.Fatal("a signature from another domain confirmed the vault")
	}
}

func TestRecoveryProofWithoutAChallenge(t *testing.T) {
	m, _ := unconfirmedVault(t)
	if err := m.ConfirmRecoveryProof([]byte("no challenge"), []byte("no signature")); err == nil {
		t.Fatal("a proof was accepted with no challenge outstanding")
	}
}
