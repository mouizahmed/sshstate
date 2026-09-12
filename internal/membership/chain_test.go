// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package membership

import (
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type device struct {
	id      protocol.ID
	signing *crypto.SigningKey
	enc     *crypto.EncryptionKey
}

func (d device) signer() Signer { return Signer{DeviceID: d.id, Key: d.signing} }

func (d device) keys() DeviceKeys {
	return DeviceKeys{
		ID:        d.id,
		VerifyKey: d.signing.Verifier().Bytes(),
		Recipient: d.enc.Recipient().String(),
	}
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

type vault struct {
	genesis  *protocol.Genesis
	first    device
	recovery *crypto.SigningKey
	recvEnc  *crypto.EncryptionKey
	now      time.Time
}

func newVault(t *testing.T) *vault {
	t.Helper()
	first := newDevice(t)
	recovery := newDevice(t)
	g := &protocol.Genesis{
		Domain:               protocol.GenesisDomain,
		FormatVersion:        protocol.GenesisFormatVersion,
		Suite:                crypto.SuiteID,
		VaultID:              protocol.MustNewID(),
		CreatedAt:            "2026-09-12T00:00:00Z",
		FirstDeviceID:        first.id,
		FirstDeviceVerifyKey: first.signing.Verifier().Bytes(),
		FirstDeviceRecipient: first.enc.Recipient().String(),
		RecoveryVerifyKey:    recovery.signing.Verifier().Bytes(),
		RecoveryRecipient:    recovery.enc.Recipient().String(),
	}
	if err := g.Validate(crypto.SuiteID); err != nil {
		t.Fatal(err)
	}
	return &vault{
		genesis:  g,
		first:    first,
		recovery: recovery.signing,
		recvEnc:  recovery.enc,
		now:      time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC),
	}
}

func (v *vault) tick() time.Time {
	v.now = v.now.Add(time.Minute)
	return v.now
}

func (v *vault) rooted(t *testing.T) *Chain {
	t.Helper()
	root, err := Root(v.genesis, v.first.signing, v.tick())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Validate(v.genesis, []protocol.SignedMembershipEvent{root})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func transcript() []byte {
	d := make([]byte, 32)
	for i := range d {
		d[i] = byte(i + 1)
	}
	return d
}

func TestRootEnrollRevoke(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	if !c.Authorized(v.first.id) {
		t.Fatal("the first device is not authorized by its own root event")
	}

	second := newDevice(t)
	ev, err := c.Enroll(v.first.signer(), second.keys(), transcript(), v.tick())
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Append(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Authorized(second.id) || c.AuthorizedCount() != 2 {
		t.Fatalf("enrolment did not authorize the second device: %d authorized", c.AuthorizedCount())
	}

	rev, err := c.Revoke(second.signer(), v.first.id, v.tick())
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Append(rev)
	if err != nil {
		t.Fatal(err)
	}
	if c.Authorized(v.first.id) {
		t.Fatal("the revoked device is still authorized")
	}
	d, ok := c.Device(v.first.id)
	if !ok || d.VerifyKey == nil || !d.Revoked {
		t.Fatalf("revoked device lost its key or its status: %+v", d)
	}
	if got := c.Devices(); len(got) != 2 || got[0].ID != v.first.id || got[1].ID != second.id {
		t.Fatalf("Devices() is not in enrolment order: %+v", got)
	}
}

func TestAppendLeavesTheReceiverUnchanged(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	second := newDevice(t)
	ev, err := c.Enroll(v.first.signer(), second.keys(), transcript(), v.tick())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(ev); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 || c.Authorized(second.id) {
		t.Fatal("Append mutated the chain it was called on")
	}
}

func TestRootMustRestateGenesis(t *testing.T) {
	v := newVault(t)
	impostor := newDevice(t)

	cases := map[string]func(*protocol.MembershipEvent){
		"different device": func(e *protocol.MembershipEvent) {
			e.DeviceID = impostor.id
			e.AuthorizedBy = impostor.id
			e.DeviceVerifyKey = impostor.signing.Verifier().Bytes()
		},
		"different verify key": func(e *protocol.MembershipEvent) {
			e.DeviceVerifyKey = impostor.signing.Verifier().Bytes()
		},
		"different recipient": func(e *protocol.MembershipEvent) {
			r := impostor.enc.Recipient().String()
			e.DeviceRecipient = &r
		},
		"revocation as root": func(e *protocol.MembershipEvent) {
			e.Action = protocol.ActionRevoke
			e.DeviceVerifyKey = nil
			e.DeviceRecipient = nil
			e.TranscriptDigest = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root, err := Root(v.genesis, v.first.signing, v.now)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&root.Event)
			key := v.first.signing
			if root.Event.AuthorizedBy == impostor.id {
				key = impostor.signing
			}
			msg, err := root.Event.SigningInput()
			if err != nil {
				t.Fatal(err)
			}
			sig, err := key.Sign(protocol.MembershipSignatureDomain, msg)
			if err != nil {
				t.Fatal(err)
			}
			root.Signature = sig
			if _, err := Validate(v.genesis, []protocol.SignedMembershipEvent{root}); err == nil {
				t.Fatal("a root that disagrees with genesis was accepted")
			}
		})
	}
}

func TestChainOrderIsEnforced(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	second := newDevice(t)
	ev, err := c.Enroll(v.first.signer(), second.keys(), transcript(), v.tick())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("gap in chain_seq", func(t *testing.T) {
		bad := resign(t, ev, v.first.signing, func(e *protocol.MembershipEvent) { e.ChainSeq = 3 })
		if _, err := c.Append(bad); err == nil {
			t.Fatal("a chain_seq gap was accepted")
		}
	})
	t.Run("wrong parent digest", func(t *testing.T) {
		bad := resign(t, ev, v.first.signing, func(e *protocol.MembershipEvent) {
			e.ParentDigest = transcript()
		})
		if _, err := c.Append(bad); err == nil {
			t.Fatal("an event naming the wrong parent was accepted")
		}
	})
	t.Run("altered after signing", func(t *testing.T) {
		bad := ev
		bad.Event.DeviceID = protocol.MustNewID()
		if _, err := c.Append(bad); err == nil {
			t.Fatal("an altered event verified anyway")
		}
	})
}

func TestRevokedDeviceCannotAuthorize(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	second, third := newDevice(t), newDevice(t)

	c = appendOrFail(t, c, mustEnroll(t, c, v.first.signer(), second.keys(), v.tick()))
	c = appendOrFail(t, c, mustRevoke(t, c, v.first.signer(), second.id, v.tick()))

	ev, err := c.Enroll(second.signer(), third.keys(), transcript(), v.tick())
	if err == nil {
		if _, err = c.Append(ev); err == nil {
			t.Fatal("a revoked device enrolled another device")
		}
	}
	forged := forgeEnroll(t, c, second, third, v.tick())
	if _, err := c.Append(forged); err == nil {
		t.Fatal("a forged event from a revoked device was accepted")
	}
}

func TestDeviceIDsAreNeverReused(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	second := newDevice(t)
	c = appendOrFail(t, c, mustEnroll(t, c, v.first.signer(), second.keys(), v.tick()))
	c = appendOrFail(t, c, mustRevoke(t, c, v.first.signer(), second.id, v.tick()))

	replacement := newDevice(t)
	replacement.id = second.id
	ev, err := c.Enroll(v.first.signer(), replacement.keys(), transcript(), v.tick())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Append(ev)
	if err == nil {
		t.Fatal("a revoked device id was re-enrolled")
	}
	if !strings.Contains(err.Error(), "before") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTheLastDeviceCannotBeRevoked(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	if _, err := c.Revoke(v.first.signer(), v.first.id, v.tick()); err == nil {
		t.Fatal("the builder allowed revoking the only device")
	}
	forged := forgeRevoke(t, c, v.first, v.first.id, v.tick())
	if _, err := c.Append(forged); err == nil {
		t.Fatal("the validator accepted revoking the last authorized device")
	}
}

func TestRecoveryAuthority(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	replacement := newDevice(t)

	ev, err := c.RecoveryEnroll(v.recovery, replacement.keys(), v.tick())
	if err != nil {
		t.Fatal(err)
	}
	next, err := c.Append(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Authorized(replacement.id) {
		t.Fatal("the recovery kit did not authorize a replacement device")
	}

	bad := resign(t, ev, v.first.signing, func(e *protocol.MembershipEvent) {})
	if _, err := c.Append(bad); err == nil {
		t.Fatal("a device forged a recovery-authorized enrolment")
	}
}

func TestEnrolmentRequiresATranscript(t *testing.T) {
	v := newVault(t)
	c := v.rooted(t)
	second := newDevice(t)
	if _, err := c.Enroll(v.first.signer(), second.keys(), nil, v.tick()); err == nil {
		t.Fatal("the builder enrolled a device with no transcript digest")
	}
	ev := mustEnroll(t, c, v.first.signer(), second.keys(), v.tick())
	bad := resign(t, ev, v.first.signing, func(e *protocol.MembershipEvent) { e.TranscriptDigest = nil })
	if _, err := c.Append(bad); err == nil {
		t.Fatal("the validator accepted an enrolment with no transcript digest")
	}
}

func TestEmptyChainIsRejected(t *testing.T) {
	v := newVault(t)
	if _, err := Validate(v.genesis, nil); err == nil {
		t.Fatal("an empty membership chain was accepted")
	}
}

func resign(t *testing.T, in protocol.SignedMembershipEvent, key *crypto.SigningKey, mutate func(*protocol.MembershipEvent)) protocol.SignedMembershipEvent {
	t.Helper()
	out := in
	mutate(&out.Event)
	msg, err := out.Event.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(protocol.MembershipSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	out.Signature = sig
	return out
}

func forgeEnroll(t *testing.T, c *Chain, by, subject device, now time.Time) protocol.SignedMembershipEvent {
	t.Helper()
	recipient := subject.enc.Recipient().String()
	ev := protocol.MembershipEvent{
		Domain:           protocol.MembershipDomain,
		FormatVersion:    protocol.MembershipFormatVersion,
		Suite:            crypto.SuiteID,
		VaultID:          c.Genesis().VaultID,
		EventID:          protocol.MustNewID(),
		ChainSeq:         protocol.Counter(c.Len() + 1),
		ParentDigest:     c.HeadDigest(),
		Action:           protocol.ActionEnroll,
		DeviceID:         subject.id,
		DeviceVerifyKey:  subject.signing.Verifier().Bytes(),
		DeviceRecipient:  &recipient,
		TranscriptDigest: transcript(),
		Authority:        protocol.AuthorityDevice,
		AuthorizedBy:     by.id,
		CreatedAt:        stamp(now),
	}
	return signForTest(t, ev, by.signing)
}

func forgeRevoke(t *testing.T, c *Chain, by device, target protocol.ID, now time.Time) protocol.SignedMembershipEvent {
	t.Helper()
	ev := protocol.MembershipEvent{
		Domain:        protocol.MembershipDomain,
		FormatVersion: protocol.MembershipFormatVersion,
		Suite:         crypto.SuiteID,
		VaultID:       c.Genesis().VaultID,
		EventID:       protocol.MustNewID(),
		ChainSeq:      protocol.Counter(c.Len() + 1),
		ParentDigest:  c.HeadDigest(),
		Action:        protocol.ActionRevoke,
		DeviceID:      target,
		Authority:     protocol.AuthorityDevice,
		AuthorizedBy:  by.id,
		CreatedAt:     stamp(now),
	}
	return signForTest(t, ev, by.signing)
}

func signForTest(t *testing.T, ev protocol.MembershipEvent, key *crypto.SigningKey) protocol.SignedMembershipEvent {
	t.Helper()
	msg, err := ev.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(protocol.MembershipSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.SignedMembershipEvent{Event: ev, Signature: sig}
}

func mustEnroll(t *testing.T, c *Chain, by Signer, keys DeviceKeys, now time.Time) protocol.SignedMembershipEvent {
	t.Helper()
	ev, err := c.Enroll(by, keys, transcript(), now)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func mustRevoke(t *testing.T, c *Chain, by Signer, target protocol.ID, now time.Time) protocol.SignedMembershipEvent {
	t.Helper()
	ev, err := c.Revoke(by, target, now)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func appendOrFail(t *testing.T, c *Chain, ev protocol.SignedMembershipEvent) *Chain {
	t.Helper()
	next, err := c.Append(ev)
	if err != nil {
		t.Fatal(err)
	}
	return next
}
