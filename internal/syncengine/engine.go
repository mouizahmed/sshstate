// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package syncengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relayclient"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const PageLimit = 200

type Preserver func(candidate, head *protocol.Envelope) (*protocol.Envelope, error)

type Engine struct {
	Store    *vault.Store
	Client   *relayclient.Client
	Genesis  *protocol.Genesis
	Preserve Preserver
}

type Report struct {
	MembershipEvents int
	Pushed           int
	Preserved        int
	Applied          int
	Cursor           protocol.Counter
	Complete         bool
}

func (e *Engine) Sync(ctx context.Context) (*Report, error) {
	if e.Store == nil || e.Client == nil || e.Genesis == nil {
		return nil, errors.New("sync: engine is not configured")
	}
	if e.Preserve == nil {
		return nil, errors.New("sync: no way to preserve a rejected candidate")
	}
	report := &Report{}

	chain, err := e.syncMembership(ctx)
	if err != nil {
		return nil, err
	}
	report.MembershipEvents = chain.Len()

	if err := e.push(ctx, report); err != nil {
		return nil, err
	}
	if err := e.pull(ctx, chain, report); err != nil {
		return nil, err
	}
	return report, nil
}

func (e *Engine) syncMembership(ctx context.Context) (*membership.Chain, error) {
	events, err := e.Client.Membership(ctx)
	if err != nil {
		return nil, err
	}
	chain, err := membership.Validate(e.Genesis, events)
	if err != nil {
		return nil, fmt.Errorf("membership chain from the relay: %w", err)
	}
	for _, d := range chain.Devices() {
		status := vault.DeviceActive
		if d.Revoked {
			status = vault.DeviceRevoked
		}
		if err := e.Store.PutDevice(vault.Device{
			ID:         d.ID,
			VerifyKey:  d.VerifyKey.Bytes(),
			Recipient:  d.Recipient,
			Status:     status,
			EnrolledAt: d.EnrolledAt,
		}); err != nil {
			return nil, err
		}
		if d.Revoked {
			if err := e.noteRevocation(d.ID); err != nil {
				return nil, err
			}
		}
	}
	return chain, nil
}

func (e *Engine) noteRevocation(id protocol.ID) error {
	key := vault.CursorRevokedAtPrefix + id.String()
	if _, err := e.Store.Cursor(key); err == nil {
		return nil
	} else if !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	at, err := e.cursor()
	if err != nil {
		return err
	}
	return e.Store.SetCursor(key, at.String())
}

func (e *Engine) push(ctx context.Context, report *Report) error {
	candidates, err := e.Store.Outbox()
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		res, err := e.Client.PutRecord(ctx, candidate)
		if err != nil {
			return fmt.Errorf("publish record %s: %w", candidate.Context.RecordID, err)
		}
		if res.Accepted {
			if err := e.Store.AcceptOutbox(candidate, res.Seq); err != nil {
				return err
			}
			report.Pushed++
			continue
		}
		conflict, err := e.Preserve(candidate, res.Head)
		if err != nil {
			return fmt.Errorf("preserve rejected candidate %s: %w", candidate.Context.MutationID, err)
		}
		if err := e.Store.ResolveConflict(candidate.Context.MutationID, conflict, res.Head); err != nil {
			return err
		}
		report.Preserved++
	}
	return nil
}

func (e *Engine) pull(ctx context.Context, chain *membership.Chain, report *Report) error {
	since, err := e.cursor()
	if err != nil {
		return err
	}
	var through protocol.Counter
	for {
		page, err := e.Client.Records(ctx, since, through, PageLimit)
		if err != nil {
			return err
		}
		through = page.SnapshotCursor
		if err := e.applyPage(chain, page, report); err != nil {
			return err
		}
		since = page.NextCursor
		if !page.HasMore {
			break
		}
	}
	report.Cursor = since
	report.Complete = since >= through
	return nil
}

func (e *Engine) applyPage(chain *membership.Chain, page *protocol.RecordsResponse, report *Report) error {
	envs := make([]*protocol.Envelope, 0, len(page.Changes))
	for i := range page.Changes {
		env := page.Changes[i]
		if err := e.verify(chain, &env); err != nil {
			return fmt.Errorf("record %s at seq %s: %w", env.Context.RecordID, env.Seq, err)
		}
		apply, err := e.ahead(&env)
		if err != nil {
			return fmt.Errorf("record %s at seq %s: %w", env.Context.RecordID, env.Seq, err)
		}
		if !apply {
			continue
		}
		envs = append(envs, &env)
	}
	if err := e.Store.ApplyRemoteBatch(page.NextCursor.String(), envs); err != nil {
		return err
	}
	report.Applied += len(envs)
	return nil
}

func (e *Engine) ahead(env *protocol.Envelope) (bool, error) {
	head, storedDigest, err := e.Store.Head(env.Context.RecordID)
	if errors.Is(err, vault.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if env.Context.Rev > head.Context.Rev {
		return true, nil
	}
	if env.Context.Rev == head.Context.Rev {
		digest, err := env.Digest()
		if err != nil {
			return false, err
		}
		if !bytes.Equal(digest, storedDigest) {
			return false, fmt.Errorf(
				"the relay served a different envelope at revision %s: this is a fork, not an update",
				env.Context.Rev)
		}
	}
	return false, nil
}

func (e *Engine) verify(chain *membership.Chain, env *protocol.Envelope) error {
	if err := env.Validate(); err != nil {
		return err
	}
	if env.Context.VaultID != e.Genesis.VaultID {
		return errors.New("the record belongs to another vault")
	}
	if env.Seq == 0 {
		return errors.New("the relay returned a change with no seq")
	}
	d, ok := chain.Device(env.Context.UpdatedBy)
	if !ok {
		return fmt.Errorf("writer %s is not in the membership chain", env.Context.UpdatedBy)
	}
	if d.Revoked {
		if err := e.checkRevokedWriter(d.ID, env.Seq); err != nil {
			return err
		}
	}
	msg, err := env.SigningInput()
	if err != nil {
		return err
	}
	if err := crypto.Verify(d.VerifyKey, protocol.RecordSignatureDomain, msg, env.Signature); err != nil {
		return fmt.Errorf("signature from %s does not verify", env.Context.UpdatedBy)
	}
	return nil
}

func (e *Engine) checkRevokedWriter(id protocol.ID, seq protocol.Counter) error {
	raw, err := e.Store.Cursor(vault.CursorRevokedAtPrefix + id.String())
	if errors.Is(err, vault.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	at, err := protocol.ParseCounter(raw)
	if err != nil {
		return fmt.Errorf("stored revocation position for %s: %w", id, err)
	}
	if seq > at {
		return fmt.Errorf("device %s was revoked at seq %s and this write is at seq %s", id, at, seq)
	}
	return nil
}

func (e *Engine) cursor() (protocol.Counter, error) {
	raw, err := e.Store.Cursor(vault.CursorRecords)
	if errors.Is(err, vault.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	c, err := protocol.ParseCounter(raw)
	if err != nil {
		return 0, fmt.Errorf("stored record cursor: %w", err)
	}
	return c, nil
}
