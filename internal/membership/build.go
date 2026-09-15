// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package membership

import (
	"errors"
	"fmt"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type Signer struct {
	DeviceID protocol.ID
	Key      *crypto.SigningKey
}

type DeviceKeys struct {
	ID        protocol.ID
	VerifyKey []byte
	Recipient string
}

func Root(g *protocol.Genesis, key *crypto.SigningKey, now time.Time) (protocol.SignedMembershipEvent, error) {
	recipient := g.FirstDeviceRecipient
	ev := protocol.MembershipEvent{
		Domain:           protocol.MembershipDomain,
		FormatVersion:    protocol.MembershipFormatVersion,
		Suite:            crypto.SuiteID,
		VaultID:          g.VaultID,
		ChainSeq:         1,
		Action:           protocol.ActionEnroll,
		DeviceID:         g.FirstDeviceID,
		DeviceVerifyKey:  g.FirstDeviceVerifyKey,
		DeviceRecipient:  &recipient,
		TranscriptDigest: selfEnrolmentTranscript(),
		Authority:        protocol.AuthorityDevice,
		AuthorizedBy:     g.FirstDeviceID,
		CreatedAt:        stamp(now),
	}
	return sign(ev, key)
}

func selfEnrolmentTranscript() protocol.Bytes { return make(protocol.Bytes, 32) }

func (c *Chain) Enroll(by Signer, device DeviceKeys, transcriptDigest []byte, now time.Time) (protocol.SignedMembershipEvent, error) {
	if len(transcriptDigest) == 0 {
		return protocol.SignedMembershipEvent{}, errors.New("enrolment needs the confirmed pairing transcript digest")
	}
	if !c.Authorized(by.DeviceID) {
		return protocol.SignedMembershipEvent{}, fmt.Errorf("device %s is not authorized to enrol", by.DeviceID)
	}
	recipient := device.Recipient
	ev := protocol.MembershipEvent{
		Domain:           protocol.MembershipDomain,
		FormatVersion:    protocol.MembershipFormatVersion,
		Suite:            crypto.SuiteID,
		VaultID:          c.genesis.VaultID,
		ChainSeq:         protocol.Counter(len(c.events) + 1),
		ParentDigest:     c.HeadDigest(),
		Action:           protocol.ActionEnroll,
		DeviceID:         device.ID,
		DeviceVerifyKey:  device.VerifyKey,
		DeviceRecipient:  &recipient,
		TranscriptDigest: transcriptDigest,
		Authority:        protocol.AuthorityDevice,
		AuthorizedBy:     by.DeviceID,
		CreatedAt:        stamp(now),
	}
	return sign(ev, by.Key)
}

func (c *Chain) RecoveryEnroll(recovery *crypto.SigningKey, device DeviceKeys, now time.Time) (protocol.SignedMembershipEvent, error) {
	recipient := device.Recipient
	ev := protocol.MembershipEvent{
		Domain:          protocol.MembershipDomain,
		FormatVersion:   protocol.MembershipFormatVersion,
		Suite:           crypto.SuiteID,
		VaultID:         c.genesis.VaultID,
		ChainSeq:        protocol.Counter(len(c.events) + 1),
		ParentDigest:    c.HeadDigest(),
		Action:          protocol.ActionEnroll,
		DeviceID:        device.ID,
		DeviceVerifyKey: device.VerifyKey,
		DeviceRecipient: &recipient,
		Authority:       protocol.AuthorityRecovery,
		AuthorizedBy:    c.genesis.VaultID,
		CreatedAt:       stamp(now),
	}
	return sign(ev, recovery)
}

func (c *Chain) Revoke(by Signer, target protocol.ID, now time.Time) (protocol.SignedMembershipEvent, error) {
	if !c.Authorized(by.DeviceID) {
		return protocol.SignedMembershipEvent{}, fmt.Errorf("device %s is not authorized to revoke", by.DeviceID)
	}
	if !c.Authorized(target) {
		return protocol.SignedMembershipEvent{}, fmt.Errorf("device %s is not currently authorized", target)
	}
	if c.AuthorizedCount() == 1 {
		return protocol.SignedMembershipEvent{}, errors.New("this is the last authorized device; revoking it would leave the recovery kit as the only write path")
	}
	ev := protocol.MembershipEvent{
		Domain:        protocol.MembershipDomain,
		FormatVersion: protocol.MembershipFormatVersion,
		Suite:         crypto.SuiteID,
		VaultID:       c.genesis.VaultID,
		ChainSeq:      protocol.Counter(len(c.events) + 1),
		ParentDigest:  c.HeadDigest(),
		Action:        protocol.ActionRevoke,
		DeviceID:      target,
		Authority:     protocol.AuthorityDevice,
		AuthorizedBy:  by.DeviceID,
		CreatedAt:     stamp(now),
	}
	return sign(ev, by.Key)
}

func sign(ev protocol.MembershipEvent, key *crypto.SigningKey) (protocol.SignedMembershipEvent, error) {
	id, err := protocol.NewID()
	if err != nil {
		return protocol.SignedMembershipEvent{}, err
	}
	ev.EventID = id
	msg, err := ev.SigningInput()
	if err != nil {
		return protocol.SignedMembershipEvent{}, err
	}
	sig, err := key.Sign(protocol.MembershipSignatureDomain, msg)
	if err != nil {
		return protocol.SignedMembershipEvent{}, err
	}
	return protocol.SignedMembershipEvent{Event: ev, Signature: sig}, nil
}

func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }
