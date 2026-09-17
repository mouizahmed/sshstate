package syncengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const importBatchBytes = 3 << 20

type RejoinReport struct {
	Needed             bool
	MembershipUploaded int
	Imported           int
	Diverged           int
}

func (e *Engine) NeedsRejoin(ctx context.Context) (bool, error) {
	err := e.checkRelayNotBehind(ctx)
	var behind *RelayBehindError
	var changed *HistoryChangedError
	switch {
	case err == nil:
		return false, nil
	case errors.As(err, &behind), errors.As(err, &changed):
		return true, nil
	}
	return false, err
}

func (e *Engine) Rejoin(ctx context.Context) (*RejoinReport, error) {
	if e.Store == nil || e.Client == nil || e.Genesis == nil || e.Preserve == nil {
		return nil, errors.New("rejoin: engine is not configured")
	}
	report := &RejoinReport{Needed: true}
	chain, uploaded, err := e.mergeMembership(ctx)
	if err != nil {
		return nil, err
	}
	report.MembershipUploaded = uploaded

	stored, err := e.history()
	if err != nil {
		return nil, err
	}
	latest, err := e.Client.Records(ctx, 0, 0, 1)
	if err != nil {
		return nil, err
	}
	history := latest.History

	heads, err := e.Store.Heads()
	if err != nil {
		return nil, err
	}
	byID := make(map[protocol.ID]*protocol.Envelope, len(heads))
	var batch []protocol.ImportRecord
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		res, err := e.Client.ImportRecords(ctx, &protocol.ImportRequest{History: stored, Records: batch})
		if err != nil {
			return fmt.Errorf("bring this machine's records back onto the relay: %w", err)
		}
		history = res.History
		if err := e.settle(chain, byID, res.Outcomes, report); err != nil {
			return err
		}
		batch, size = nil, 0
		return nil
	}
	for _, head := range heads {
		byID[head.Context.RecordID] = head
		ancestors, err := e.Store.Ancestors(head.Context.RecordID)
		if err != nil {
			return nil, err
		}
		item := protocol.ImportRecord{Envelope: *head}
		item.Envelope.Seq = 0
		for _, a := range ancestors {
			item.Ancestors = append(item.Ancestors, a)
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if size+len(encoded) > importBatchBytes {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		batch = append(batch, item)
		size += len(encoded)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if err := e.Store.RestartHistory(history); err != nil {
		return nil, err
	}
	return report, nil
}

func (e *Engine) settle(chain *membership.Chain, local map[protocol.ID]*protocol.Envelope, outcomes []protocol.ImportOutcome, report *RejoinReport) error {
	for _, out := range outcomes {
		mine, ok := local[out.RecordID]
		if !ok {
			return fmt.Errorf("the relay answered for record %s, which this machine did not send", out.RecordID)
		}
		switch out.Outcome {
		case protocol.ImportImported, protocol.ImportCurrent:
			if out.Outcome == protocol.ImportImported {
				report.Imported++
			}
			if err := e.Store.AcceptImported(mine, out.Seq); err != nil {
				return err
			}
		case protocol.ImportBehind:
			if err := e.Store.DropPending(mine.Context.RecordID, mine.Context.Rev); err != nil {
				return err
			}
		case protocol.ImportDiverged:
			if err := e.keepAside(chain, mine, out.Head); err != nil {
				return fmt.Errorf("record %s: %w", out.RecordID, err)
			}
			report.Diverged++
		default:
			return fmt.Errorf("the relay answered %q for record %s", out.Outcome, out.RecordID)
		}
	}
	return nil
}

func (e *Engine) keepAside(chain *membership.Chain, mine, head *protocol.Envelope) error {
	if head == nil || head.Context.RecordID != mine.Context.RecordID {
		return errors.New("the relay reported a different version without sending it")
	}
	if err := verifyWriter(chain, e.Genesis.VaultID, head); err != nil {
		return fmt.Errorf("the relay's version: %w", err)
	}
	if isConflictRecord(mine) {
		return e.Store.Supersede(nil, head)
	}
	conflict, err := e.Preserve(mine, head)
	if err != nil {
		return err
	}
	return e.Store.Supersede(conflict, head)
}

func verifyWriter(chain *membership.Chain, vaultID protocol.ID, env *protocol.Envelope) error {
	if err := env.Validate(); err != nil {
		return err
	}
	if env.Context.VaultID != vaultID {
		return errors.New("the record belongs to another vault")
	}
	d, ok := chain.Device(env.Context.UpdatedBy)
	if !ok {
		return fmt.Errorf("writer %s is not in the membership chain", env.Context.UpdatedBy)
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

func (e *Engine) mergeMembership(ctx context.Context) (*membership.Chain, int, error) {
	remote, err := e.Client.Membership(ctx)
	if err != nil {
		return nil, 0, err
	}
	if _, err := membership.Validate(e.Genesis, remote); err != nil {
		return nil, 0, fmt.Errorf("membership chain from the relay: %w", err)
	}
	local, err := e.Store.MembershipEvents()
	if err != nil {
		return nil, 0, err
	}
	for i := 0; i < len(remote) && i < len(local); i++ {
		same, err := sameEvent(remote[i], local[i])
		if err != nil {
			return nil, 0, err
		}
		if !same {
			return nil, 0, fmt.Errorf("the relay's device list and this machine's disagree at event %d, "+
				"so they are not the same history; nothing was changed", i+1)
		}
	}
	uploaded := 0
	for _, ev := range local[min(len(remote), len(local)):] {
		if _, err := e.Client.AppendMembership(ctx, ev); err != nil {
			return nil, 0, fmt.Errorf("put this machine's device list back on the relay: %w", err)
		}
		uploaded++
	}
	chain, _, err := e.syncMembership(ctx)
	if err != nil {
		return nil, 0, err
	}
	return chain, uploaded, nil
}

func sameEvent(a, b protocol.SignedMembershipEvent) (bool, error) {
	ca, err := protocol.Canonical(&a)
	if err != nil {
		return false, err
	}
	cb, err := protocol.Canonical(&b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ca, cb), nil
}
