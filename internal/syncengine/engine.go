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
	MembershipEvents  int
	MembershipLearned int
	Pushed            int
	Preserved         int
	Applied           int
	Cursor            protocol.Counter
	Complete          bool
}

func (e *Engine) Sync(ctx context.Context) (*Report, error) {
	if e.Store == nil || e.Client == nil || e.Genesis == nil {
		return nil, errors.New("sync: engine is not configured")
	}
	if e.Preserve == nil {
		return nil, errors.New("sync: no way to preserve a rejected candidate")
	}
	report := &Report{}

	known := localChainLength(e.Store)
	chain, newlyRevoked, err := e.syncMembership(ctx)
	if err != nil {
		if protocol.CodeOf(err) == protocol.CodeDeviceRevoked {
			_ = e.Store.SetMeta(vault.MetaRevokedNotice, "true")
		}
		return nil, err
	}
	report.MembershipEvents = chain.Len()

	if err := e.checkRelayNotBehind(ctx); err != nil {
		return nil, err
	}
	report.MembershipLearned = max(chain.Len()-known, 0)

	if err := e.push(ctx, report); err != nil {
		return nil, err
	}
	through, err := e.pull(ctx, chain, report)
	if err != nil {
		return nil, err
	}
	if report.Complete {
		for _, id := range newlyRevoked {
			if err := e.noteRevocation(id, through); err != nil {
				return nil, err
			}
		}
	}
	return report, nil
}

func (e *Engine) syncMembership(ctx context.Context) (*membership.Chain, []protocol.ID, error) {
	events, err := e.Client.Membership(ctx)
	if err != nil {
		return nil, nil, err
	}
	chain, err := membership.Validate(e.Genesis, events)
	if err != nil {
		return nil, nil, fmt.Errorf("membership chain from the relay: %w", err)
	}
	if chain.Len() >= localChainLength(e.Store) {
		if err := e.Store.PutMembershipEvents(chain.Events()); err != nil {
			return nil, nil, err
		}
	}
	var newlyRevoked []protocol.ID
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
			return nil, nil, err
		}
		if !d.Revoked {
			continue
		}
		noted, err := e.revocationNoted(d.ID)
		if err != nil {
			return nil, nil, err
		}
		if !noted {
			newlyRevoked = append(newlyRevoked, d.ID)
		}
	}
	return chain, newlyRevoked, nil
}

func (e *Engine) revocationNoted(id protocol.ID) (bool, error) {
	_, err := e.Store.Cursor(vault.CursorRevokedAtPrefix + id.String())
	if errors.Is(err, vault.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (e *Engine) noteRevocation(id protocol.ID, at protocol.Counter) error {
	key := vault.CursorRevokedAtPrefix + id.String()
	if _, err := e.Store.Cursor(key); err == nil {
		return nil
	} else if !errors.Is(err, vault.ErrNotFound) {
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
		if isConflictRecord(candidate) && res.Head != nil {
			if err := e.Store.Supersede(nil, res.Head); err != nil {
				return err
			}
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

func (e *Engine) pull(ctx context.Context, chain *membership.Chain, report *Report) (protocol.Counter, error) {
	since, err := e.cursor()
	if err != nil {
		return 0, err
	}
	var through protocol.Counter
	for {
		page, err := e.Client.Records(ctx, since, through, PageLimit)
		if err != nil {
			return 0, err
		}
		through = page.SnapshotCursor
		if err := e.applyPage(chain, page, report); err != nil {
			return 0, err
		}
		since = page.NextCursor
		if !page.HasMore {
			break
		}
	}
	report.Cursor = since
	report.Complete = since >= through
	return through, nil
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

type RelayBehindError struct {
	URL   string
	Relay protocol.Counter
	Local protocol.Counter
}

func (e *RelayBehindError) Error() string {
	return fmt.Sprintf("the relay's history ends at change %s, but this machine has already seen change %s, "+
		"so the relay was probably restored from an older backup\n"+
		"this machine's vault is intact, and sync is stopped so nothing is overwritten\n"+
		"to put this machine's changes back on the relay, run: sshstate connect %s --rejoin",
		e.Relay, e.Local, e.URL)
}

type HistoryChangedError struct {
	URL string
}

func (e *HistoryChangedError) Error() string {
	return fmt.Sprintf("the relay at %s was started again from another machine or restored from a backup, "+
		"so its change numbers no longer match this machine's\n"+
		"this machine's vault is intact, and sync is stopped so nothing is missed\n"+
		"to continue, run: sshstate connect %s --rejoin", e.URL, e.URL)
}

func (e *Engine) checkRelayNotBehind(ctx context.Context) error {
	since, err := e.cursor()
	if err != nil {
		return err
	}
	latest, err := e.Client.Records(ctx, 0, 0, 1)
	if err != nil {
		return err
	}
	stored, err := e.history()
	if err != nil {
		return err
	}
	if latest.History != "" {
		switch {
		case stored == "" && since != 0 && latest.HistoryOrigin != protocol.HistoryCreated:
			return &HistoryChangedError{URL: e.Client.URL()}
		case stored != "" && stored != latest.History:
			return &HistoryChangedError{URL: e.Client.URL()}
		}
	}
	if since > latest.SnapshotCursor {
		return &RelayBehindError{URL: e.Client.URL(), Relay: latest.SnapshotCursor, Local: since}
	}
	if stored == "" && latest.History != "" {
		return e.Store.SetCursor(vault.CursorHistory, latest.History)
	}
	return nil
}

func (e *Engine) history() (string, error) {
	raw, err := e.Store.Cursor(vault.CursorHistory)
	if errors.Is(err, vault.ErrNotFound) {
		return "", nil
	}
	return raw, err
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

func localChainLength(store *vault.Store) int {
	events, err := store.MembershipEvents()
	if err != nil {
		return 0
	}
	return len(events)
}

func isConflictRecord(env *protocol.Envelope) bool {
	t := env.Context.RecordType
	return t == protocol.RecordConflictMetadata || t == protocol.RecordConflictSecret
}
