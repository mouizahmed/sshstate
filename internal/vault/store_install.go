// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"fmt"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type Installation struct {
	Genesis    *protocol.Genesis
	Wrappers   map[string]*crypto.Wrapper
	Membership []protocol.SignedMembershipEvent
	Devices    []Device
	Heads      []*protocol.Envelope
	Cursor     string
	Meta       map[string]string
}

func (s *Store) Install(inst Installation) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := putGenesis(tx, inst.Genesis); err != nil {
		return err
	}
	for purpose, w := range inst.Wrappers {
		if err := putWrapper(tx, purpose, w); err != nil {
			return err
		}
	}
	if err := putMembershipEvents(tx, inst.Membership); err != nil {
		return err
	}
	for _, d := range inst.Devices {
		if err := putDevice(tx, d); err != nil {
			return err
		}
	}
	seen := make(map[protocol.ID]bool, len(inst.Heads))
	for _, env := range inst.Heads {
		if seen[env.Context.RecordID] {
			return fmt.Errorf("install records: record %s appears twice", env.Context.RecordID)
		}
		seen[env.Context.RecordID] = true
		if err := replaceHeadTx(tx, env); err != nil {
			return fmt.Errorf("install records: %w", err)
		}
	}
	if err := setCursor(tx, CursorRecords, inst.Cursor); err != nil {
		return err
	}
	for k, v := range inst.Meta {
		if err := setMeta(tx, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}
