package protocol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const (
	PairingDomain        = "sshstate.pairing.v1"
	PairingOfferDomain   = "sshstate.pairing-offer.v1"
	PairingConfirmDomain = "sshstate.pairing-confirm.v1"
	PairingFormatVersion = 1

	PairingLifetime = 10 * time.Minute

	ChallengeBytes = 32
)

type PairingOffer struct {
	Domain          string `json:"domain"`
	FormatVersion   int    `json:"format_version"`
	Suite           string `json:"suite"`
	VaultID         ID     `json:"vault_id"`
	JoinerDeviceID  ID     `json:"joiner_device_id"`
	JoinerVerifyKey Bytes  `json:"joiner_verify_key"`
	JoinerRecipient string `json:"joiner_recipient"`
	JoinerChallenge Bytes  `json:"joiner_challenge"`
	CreatedAt       string `json:"created_at"`
}

type SignedPairingOffer struct {
	Offer     PairingOffer `json:"offer"`
	Signature Bytes        `json:"signature"`
}

func (o *PairingOffer) SigningInput() ([]byte, error) { return Canonical(o) }

func (o *PairingOffer) Validate(expectSuite string) error {
	if o.Domain != PairingOfferDomain {
		return fmt.Errorf("pairing offer domain %q is not %q", o.Domain, PairingOfferDomain)
	}
	if o.FormatVersion != PairingFormatVersion {
		return fmt.Errorf("unsupported pairing format version %d", o.FormatVersion)
	}
	if o.Suite != expectSuite {
		return fmt.Errorf("pairing offer uses suite %q, this build implements %q", o.Suite, expectSuite)
	}
	if err := o.VaultID.check("vault_id"); err != nil {
		return err
	}
	if err := o.JoinerDeviceID.check("joiner_device_id"); err != nil {
		return err
	}
	if len(o.JoinerVerifyKey) == 0 || o.JoinerRecipient == "" {
		return errors.New("pairing offer is missing the joiner's public keys")
	}
	if len(o.JoinerChallenge) != ChallengeBytes {
		return fmt.Errorf("joiner_challenge must be %d bytes, got %d", ChallengeBytes, len(o.JoinerChallenge))
	}
	if _, err := time.Parse(time.RFC3339, o.CreatedAt); err != nil {
		return fmt.Errorf("pairing offer created_at is not RFC 3339: %w", err)
	}
	return nil
}

type PairingApproval struct {
	ApproverDeviceID  ID     `json:"approver_device_id"`
	ApproverVerifyKey Bytes  `json:"approver_verify_key"`
	ApproverRecipient string `json:"approver_recipient"`
	ApproverChallenge Bytes  `json:"approver_challenge"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at"`
}

func (a *PairingApproval) Validate() error {
	if err := a.ApproverDeviceID.check("approver_device_id"); err != nil {
		return err
	}
	if len(a.ApproverVerifyKey) == 0 || a.ApproverRecipient == "" {
		return errors.New("pairing approval is missing the approver's public keys")
	}
	if len(a.ApproverChallenge) != ChallengeBytes {
		return fmt.Errorf("approver_challenge must be %d bytes, got %d", ChallengeBytes, len(a.ApproverChallenge))
	}
	created, err := time.Parse(time.RFC3339, a.CreatedAt)
	if err != nil {
		return fmt.Errorf("pairing approval created_at is not RFC 3339: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil {
		return fmt.Errorf("pairing approval expires_at is not RFC 3339: %w", err)
	}
	if !expires.Equal(created.Add(PairingLifetime)) {
		return fmt.Errorf("pairing session must last exactly %s", PairingLifetime)
	}
	return nil
}

type PairingTranscript struct {
	Domain            string `json:"domain"`
	FormatVersion     int    `json:"format_version"`
	Suite             string `json:"suite"`
	VaultID           ID     `json:"vault_id"`
	SessionID         ID     `json:"session_id"`
	ApproverDeviceID  ID     `json:"approver_device_id"`
	ApproverVerifyKey Bytes  `json:"approver_verify_key"`
	ApproverRecipient string `json:"approver_recipient"`
	JoinerDeviceID    ID     `json:"joiner_device_id"`
	JoinerVerifyKey   Bytes  `json:"joiner_verify_key"`
	JoinerRecipient   string `json:"joiner_recipient"`
	ApproverChallenge Bytes  `json:"approver_challenge"`
	JoinerChallenge   Bytes  `json:"joiner_challenge"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at"`
}

func BuildTranscript(sessionID ID, offer PairingOffer, approval PairingApproval, expectSuite string) (*PairingTranscript, error) {
	if err := sessionID.check("session_id"); err != nil {
		return nil, err
	}
	if err := offer.Validate(expectSuite); err != nil {
		return nil, err
	}
	if err := approval.Validate(); err != nil {
		return nil, err
	}
	if offer.JoinerDeviceID == approval.ApproverDeviceID {
		return nil, errors.New("a device cannot pair with itself")
	}
	return &PairingTranscript{
		Domain:            PairingDomain,
		FormatVersion:     PairingFormatVersion,
		Suite:             expectSuite,
		VaultID:           offer.VaultID,
		SessionID:         sessionID,
		ApproverDeviceID:  approval.ApproverDeviceID,
		ApproverVerifyKey: approval.ApproverVerifyKey,
		ApproverRecipient: approval.ApproverRecipient,
		JoinerDeviceID:    offer.JoinerDeviceID,
		JoinerVerifyKey:   offer.JoinerVerifyKey,
		JoinerRecipient:   offer.JoinerRecipient,
		ApproverChallenge: approval.ApproverChallenge,
		JoinerChallenge:   offer.JoinerChallenge,
		CreatedAt:         approval.CreatedAt,
		ExpiresAt:         approval.ExpiresAt,
	}, nil
}

func (t *PairingTranscript) Digest() ([]byte, error) {
	canon, err := Canonical(t)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}

func (t *PairingTranscript) Fingerprint() (string, error) {
	d, err := t.Digest()
	if err != nil {
		return "", err
	}
	return Fingerprint(d)
}

func (t *PairingTranscript) Expired(now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return true
	}
	return !now.Before(expires)
}

type PairingConfirmation struct {
	Domain           string `json:"domain"`
	FormatVersion    int    `json:"format_version"`
	VaultID          ID     `json:"vault_id"`
	SessionID        ID     `json:"session_id"`
	DeviceID         ID     `json:"device_id"`
	TranscriptDigest Bytes  `json:"transcript_digest"`
	CreatedAt        string `json:"created_at"`
}

type SignedPairingConfirmation struct {
	Confirmation PairingConfirmation `json:"confirmation"`
	Signature    Bytes               `json:"signature"`
}

func (c *PairingConfirmation) SigningInput() ([]byte, error) { return Canonical(c) }

func (c *PairingConfirmation) Validate() error {
	if c.Domain != PairingConfirmDomain {
		return fmt.Errorf("pairing confirmation domain %q is not %q", c.Domain, PairingConfirmDomain)
	}
	if c.FormatVersion != PairingFormatVersion {
		return fmt.Errorf("unsupported pairing format version %d", c.FormatVersion)
	}
	if err := c.VaultID.check("vault_id"); err != nil {
		return err
	}
	if err := c.SessionID.check("session_id"); err != nil {
		return err
	}
	if err := c.DeviceID.check("device_id"); err != nil {
		return err
	}
	if len(c.TranscriptDigest) != sha256.Size {
		return fmt.Errorf("transcript_digest must be %d bytes, got %d", sha256.Size, len(c.TranscriptDigest))
	}
	if _, err := time.Parse(time.RFC3339, c.CreatedAt); err != nil {
		return fmt.Errorf("pairing confirmation created_at is not RFC 3339: %w", err)
	}
	return nil
}
