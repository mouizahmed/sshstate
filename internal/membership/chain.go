// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package membership

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type Device struct {
	ID         protocol.ID
	VerifyKey  *crypto.VerifyKey
	Recipient  string
	EnrolledAt string
	EnrolledBy protocol.ID
	Revoked    bool
	RevokedAt  string
	EnrollSeq  protocol.Counter
	RevokeSeq  protocol.Counter
}

type Chain struct {
	genesis *protocol.Genesis
	events  []protocol.SignedMembershipEvent
	devices map[protocol.ID]*Device
	order   []protocol.ID
	head    []byte
}

func Validate(g *protocol.Genesis, events []protocol.SignedMembershipEvent) (*Chain, error) {
	if err := g.Validate(crypto.SuiteID); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, errors.New("membership chain is empty")
	}
	c := &Chain{genesis: g, devices: make(map[protocol.ID]*Device)}
	for i := range events {
		if err := c.apply(events[i]); err != nil {
			return nil, fmt.Errorf("membership event %d: %w", i+1, err)
		}
	}
	return c, nil
}

func (c *Chain) Append(ev protocol.SignedMembershipEvent) (*Chain, error) {
	next := c.clone()
	if err := next.apply(ev); err != nil {
		return nil, err
	}
	return next, nil
}

func (c *Chain) clone() *Chain {
	out := &Chain{
		genesis: c.genesis,
		events:  append([]protocol.SignedMembershipEvent(nil), c.events...),
		devices: make(map[protocol.ID]*Device, len(c.devices)),
		order:   append([]protocol.ID(nil), c.order...),
		head:    append([]byte(nil), c.head...),
	}
	for id, d := range c.devices {
		copied := *d
		out.devices[id] = &copied
	}
	return out
}

func (c *Chain) apply(s protocol.SignedMembershipEvent) error {
	ev := s.Event
	if err := ev.Validate(crypto.SuiteID); err != nil {
		return err
	}
	if ev.VaultID != c.genesis.VaultID {
		return fmt.Errorf("event names vault %s, genesis is %s", ev.VaultID, c.genesis.VaultID)
	}
	if want := protocol.Counter(len(c.events) + 1); ev.ChainSeq != want {
		return fmt.Errorf("chain_seq is %s, expected %s", ev.ChainSeq, want)
	}
	if len(c.events) == 0 {
		if err := c.checkRoot(ev); err != nil {
			return err
		}
	} else if !bytes.Equal(ev.ParentDigest, c.head) {
		return errors.New("parent_digest does not name the current chain head")
	}

	signer, err := c.signerKey(ev)
	if err != nil {
		return err
	}
	msg, err := ev.SigningInput()
	if err != nil {
		return err
	}
	if err := crypto.Verify(signer, protocol.MembershipSignatureDomain, msg, s.Signature); err != nil {
		return fmt.Errorf("membership signature: %w", err)
	}

	if err := c.applyAction(ev); err != nil {
		return err
	}
	digest, err := s.Digest()
	if err != nil {
		return err
	}
	c.events = append(c.events, s)
	c.head = digest
	return nil
}

func (c *Chain) checkRoot(ev protocol.MembershipEvent) error {
	if ev.Action != protocol.ActionEnroll {
		return errors.New("the root event must enrol the first device")
	}
	if ev.Authority != protocol.AuthorityDevice {
		return errors.New("the root event is signed by the first device, not the recovery key")
	}
	if ev.DeviceID != c.genesis.FirstDeviceID || ev.AuthorizedBy != c.genesis.FirstDeviceID {
		return errors.New("the root event does not enrol the genesis first device")
	}
	if !bytes.Equal(ev.DeviceVerifyKey, c.genesis.FirstDeviceVerifyKey) {
		return errors.New("the root event's verify key is not the one genesis pins")
	}
	if ev.DeviceRecipient == nil || *ev.DeviceRecipient != c.genesis.FirstDeviceRecipient {
		return errors.New("the root event's recipient is not the one genesis pins")
	}
	return nil
}

func (c *Chain) signerKey(ev protocol.MembershipEvent) (*crypto.VerifyKey, error) {
	if ev.Authority == protocol.AuthorityRecovery {
		return crypto.VerifyKeyFromBytes(c.genesis.RecoveryVerifyKey)
	}
	if len(c.events) == 0 {
		return crypto.VerifyKeyFromBytes(ev.DeviceVerifyKey)
	}
	d, ok := c.devices[ev.AuthorizedBy]
	if !ok {
		return nil, fmt.Errorf("device %s is not in the membership chain", ev.AuthorizedBy)
	}
	if d.Revoked {
		return nil, fmt.Errorf("device %s was revoked and cannot authorize", ev.AuthorizedBy)
	}
	return d.VerifyKey, nil
}

func (c *Chain) applyAction(ev protocol.MembershipEvent) error {
	switch ev.Action {
	case protocol.ActionEnroll:
		if _, seen := c.devices[ev.DeviceID]; seen {
			return fmt.Errorf("device %s has appeared in this chain before", ev.DeviceID)
		}
		key, err := crypto.VerifyKeyFromBytes(ev.DeviceVerifyKey)
		if err != nil {
			return fmt.Errorf("enrolled device_verify_key: %w", err)
		}
		if _, err := crypto.ParseRecipient(*ev.DeviceRecipient); err != nil {
			return fmt.Errorf("enrolled device_recipient: %w", err)
		}
		c.devices[ev.DeviceID] = &Device{
			ID:         ev.DeviceID,
			VerifyKey:  key,
			Recipient:  *ev.DeviceRecipient,
			EnrolledAt: ev.CreatedAt,
			EnrolledBy: ev.AuthorizedBy,
			EnrollSeq:  ev.ChainSeq,
		}
		c.order = append(c.order, ev.DeviceID)
		return nil
	case protocol.ActionRevoke:
		d, ok := c.devices[ev.DeviceID]
		if !ok {
			return fmt.Errorf("device %s is not in the membership chain", ev.DeviceID)
		}
		if d.Revoked {
			return fmt.Errorf("device %s is already revoked", ev.DeviceID)
		}
		if c.AuthorizedCount() == 1 {
			return errors.New("refusing to revoke the last authorized device: the vault would have no write path but the recovery kit")
		}
		d.Revoked = true
		d.RevokedAt = ev.CreatedAt
		d.RevokeSeq = ev.ChainSeq
		return nil
	}
	return fmt.Errorf("unknown membership action %q", ev.Action)
}

func (c *Chain) AuthorizedCount() int {
	n := 0
	for _, d := range c.devices {
		if !d.Revoked {
			n++
		}
	}
	return n
}

func (c *Chain) Authorized(id protocol.ID) bool {
	d, ok := c.devices[id]
	return ok && !d.Revoked
}

func (c *Chain) Device(id protocol.ID) (Device, bool) {
	d, ok := c.devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

func (c *Chain) Devices() []Device {
	out := make([]Device, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, *c.devices[id])
	}
	return out
}

func (c *Chain) HeadDigest() []byte { return append([]byte(nil), c.head...) }

func (c *Chain) Len() int { return len(c.events) }

func (c *Chain) Events() []protocol.SignedMembershipEvent {
	return append([]protocol.SignedMembershipEvent(nil), c.events...)
}

func (c *Chain) Genesis() *protocol.Genesis { return c.genesis }
