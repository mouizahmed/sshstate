package protocol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const (
	MembershipDomain          = "sshstate.membership.v1"
	MembershipSignatureDomain = "sshstate.membership-sig.v1"
	MembershipFormatVersion   = 1
)

type MembershipAction string

const (
	ActionEnroll MembershipAction = "enroll"
	ActionRevoke MembershipAction = "revoke"
)

type Authority string

const (
	AuthorityDevice   Authority = "device"
	AuthorityRecovery Authority = "recovery"
)

type MembershipEvent struct {
	Domain           string           `json:"domain"`
	FormatVersion    int              `json:"format_version"`
	Suite            string           `json:"suite"`
	VaultID          ID               `json:"vault_id"`
	EventID          ID               `json:"event_id"`
	ChainSeq         Counter          `json:"chain_seq"`
	ParentDigest     Bytes            `json:"parent_digest"`
	Action           MembershipAction `json:"action"`
	DeviceID         ID               `json:"device_id"`
	DeviceVerifyKey  Bytes            `json:"device_verify_key"`
	DeviceRecipient  *string          `json:"device_recipient"`
	TranscriptDigest Bytes            `json:"transcript_digest"`
	Authority        Authority        `json:"authority"`
	AuthorizedBy     ID               `json:"authorized_by"`
	CreatedAt        string           `json:"created_at"`
}

type SignedMembershipEvent struct {
	Event     MembershipEvent `json:"event"`
	Signature Bytes           `json:"signature"`
}

func (e *MembershipEvent) SigningInput() ([]byte, error) { return Canonical(e) }

func (e *MembershipEvent) Validate(expectSuite string) error {
	if e.Domain != MembershipDomain {
		return fmt.Errorf("membership domain %q is not %q", e.Domain, MembershipDomain)
	}
	if e.FormatVersion != MembershipFormatVersion {
		return fmt.Errorf("unsupported membership format version %d", e.FormatVersion)
	}
	if e.Suite != expectSuite {
		return fmt.Errorf("membership event uses suite %q, this build implements %q", e.Suite, expectSuite)
	}
	if err := e.VaultID.check("vault_id"); err != nil {
		return err
	}
	if err := e.EventID.check("event_id"); err != nil {
		return err
	}
	if err := e.DeviceID.check("device_id"); err != nil {
		return err
	}
	if err := e.AuthorizedBy.check("authorized_by"); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, e.CreatedAt); err != nil {
		return fmt.Errorf("membership created_at is not RFC 3339: %w", err)
	}
	if e.ChainSeq < 1 {
		return errors.New("chain_seq starts at 1")
	}
	if e.ChainSeq == 1 && e.ParentDigest != nil {
		return errors.New("chain_seq 1 is the root and must not carry a parent_digest")
	}
	if e.ChainSeq > 1 && len(e.ParentDigest) != sha256.Size {
		return fmt.Errorf("chain_seq %s needs a %d-byte parent_digest, got %d", e.ChainSeq, sha256.Size, len(e.ParentDigest))
	}
	switch e.Authority {
	case AuthorityDevice:
	case AuthorityRecovery:
		if e.AuthorizedBy != e.VaultID {
			return errors.New("a recovery-authorized event must name the vault as authorized_by")
		}
	default:
		return fmt.Errorf("unknown membership authority %q", e.Authority)
	}
	switch e.Action {
	case ActionEnroll:
		if len(e.DeviceVerifyKey) == 0 || e.DeviceRecipient == nil || *e.DeviceRecipient == "" {
			return errors.New("an enrolment must carry the device's public keys")
		}
		if e.Authority == AuthorityDevice && len(e.TranscriptDigest) != sha256.Size {
			return fmt.Errorf("a device-authorized enrolment needs a %d-byte transcript_digest", sha256.Size)
		}
		if e.Authority == AuthorityRecovery && e.TranscriptDigest != nil {
			return errors.New("a recovery-authorized enrolment has no pairing transcript")
		}
	case ActionRevoke:
		if e.DeviceVerifyKey != nil || e.DeviceRecipient != nil || e.TranscriptDigest != nil {
			return errors.New("a revocation must not restate keys or a transcript")
		}
	default:
		return fmt.Errorf("unknown membership action %q", e.Action)
	}
	return nil
}

func (s *SignedMembershipEvent) Digest() ([]byte, error) {
	if len(s.Signature) == 0 {
		return nil, errors.New("digest: membership event is unsigned")
	}
	canon, err := Canonical(s)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}
