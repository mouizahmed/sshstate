package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const APIVersion = "v1"

type ErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Detail  map[string]any `json:"detail,omitempty"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
	Head  *Envelope `json:"head,omitempty"`
}

type BootstrapRequest struct {
	Genesis        Genesis                 `json:"genesis"`
	MembershipRoot SignedMembershipEvent   `json:"membership_root"`
	Membership     []SignedMembershipEvent `json:"membership,omitempty"`
	Seeded         bool                    `json:"seeded,omitempty"`
}

type BootstrapResponse struct {
	VaultID ID `json:"vault_id"`
}

type CreatePairingRequest struct {
	VaultID   ID           `json:"vault_id"`
	Offer     PairingOffer `json:"offer"`
	Signature Bytes        `json:"signature"`
}

type CreatePairingResponse struct {
	SessionID ID     `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
}

type PairingResponse struct {
	SessionID            ID                         `json:"session_id"`
	State                string                     `json:"state"`
	Offer                *PairingOffer              `json:"offer"`
	OfferSignature       Bytes                      `json:"offer_signature"`
	Approver             *PairingApproval           `json:"approver"`
	ApproverConfirmation *SignedPairingConfirmation `json:"approver_confirmation"`
	JoinerConfirmation   *SignedPairingConfirmation `json:"joiner_confirmation"`
	Bundle               Bytes                      `json:"bundle"`
	Snapshot             Bytes                      `json:"snapshot"`
	MembershipEvent      *SignedMembershipEvent     `json:"membership_event"`
	Genesis              *Genesis                   `json:"genesis"`
	ExpiresAt            string                     `json:"expires_at"`
}

type ConfirmPairingRequest struct {
	Approver     *PairingApproval    `json:"approver"`
	Confirmation PairingConfirmation `json:"confirmation"`
	Signature    Bytes               `json:"signature"`
}

type CompletePairingRequest struct {
	MembershipEvent *SignedMembershipEvent `json:"membership_event"`
	Bundle          Bytes                  `json:"bundle"`
	Snapshot        Bytes                  `json:"snapshot"`
	Genesis         *Genesis               `json:"genesis,omitempty"`
	Acknowledged    bool                   `json:"acknowledged"`
}

type MembershipResponse struct {
	Events []SignedMembershipEvent `json:"events"`
}

type AppendMembershipRequest struct {
	Event SignedMembershipEvent `json:"event"`
}

type AppendMembershipResponse struct {
	ChainSeq   Counter `json:"chain_seq"`
	HeadDigest Bytes   `json:"head_digest"`
}

type EnvelopeBody struct {
	ID                ID            `json:"id"`
	RecipientDeviceID *ID           `json:"recipient_device_id"`
	Purpose           BundlePurpose `json:"purpose"`
	KeyEpoch          Counter       `json:"key_epoch"`
	Ciphertext        Bytes         `json:"ciphertext"`
}

type EnvelopesResponse struct {
	Envelopes []EnvelopeBody `json:"envelopes"`
}

type RecoveryChallengeRequest struct {
	VaultID ID `json:"vault_id"`
}

type RecoveryChallengeResponse struct {
	Nonce            string   `json:"nonce"`
	ExpiresAt        string   `json:"expires_at"`
	Genesis          *Genesis `json:"genesis"`
	RecoveryEnvelope Bytes    `json:"recovery_envelope"`
}

type RecoveryAdmission struct {
	Domain          string `json:"domain"`
	FormatVersion   int    `json:"format_version"`
	VaultID         ID     `json:"vault_id"`
	GenesisDigest   Bytes  `json:"genesis_digest"`
	Nonce           string `json:"nonce"`
	DeviceID        ID     `json:"device_id"`
	DeviceVerifyKey Bytes  `json:"device_verify_key"`
	DeviceRecipient string `json:"device_recipient"`
	CreatedAt       string `json:"created_at"`
}

func (a *RecoveryAdmission) SigningInput() ([]byte, error) { return Canonical(a) }

const (
	RecoveryAdmitDomain        = "sshstate.recovery-admit.v1"
	RecoveryAdmitFormatVersion = 1
)

type RecoveryCompleteRequest struct {
	Admission       RecoveryAdmission     `json:"admission"`
	Signature       Bytes                 `json:"signature"`
	MembershipEvent SignedMembershipEvent `json:"membership_event"`
}

type RecoveryCompleteResponse struct {
	DeviceID            ID    `json:"device_id"`
	MembershipHeadDiges Bytes `json:"membership_head_digest"`
}

type RecordsResponse struct {
	Changes        []Envelope `json:"changes"`
	NextCursor     Counter    `json:"next_cursor"`
	SnapshotCursor Counter    `json:"snapshot_cursor"`
	HasMore        bool       `json:"has_more"`
	History        string     `json:"history,omitempty"`
	HistoryOrigin  string     `json:"history_origin,omitempty"`
}

const (
	HistoryCreated   = "created"
	HistorySeeded    = "seeded"
	HistoryRestarted = "restarted"
)

const MaxImportBytes = 4 << 20

type ImportRecord struct {
	Envelope  Envelope `json:"envelope"`
	Ancestors []Bytes  `json:"ancestors,omitempty"`
}

type ImportRequest struct {
	History string         `json:"history"`
	Records []ImportRecord `json:"records"`
}

const (
	ImportImported = "imported"
	ImportCurrent  = "current"
	ImportBehind   = "behind"
	ImportDiverged = "diverged"
)

type ImportOutcome struct {
	RecordID ID        `json:"record_id"`
	Outcome  string    `json:"outcome"`
	Seq      Counter   `json:"seq,omitempty"`
	Head     *Envelope `json:"head,omitempty"`
}

type ImportResponse struct {
	History  string          `json:"history"`
	Outcomes []ImportOutcome `json:"outcomes"`
}

type PutRecordResponse struct {
	Accepted bool    `json:"accepted"`
	Seq      Counter `json:"seq"`
	Digest   Bytes   `json:"digest"`
}

const BootstrapSecretBytes = 32

func EncodeBootstrapSecret(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(secret)
}

func DecodeBootstrapSecret(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	text = strings.TrimRight(text, "=")
	text = strings.NewReplacer("+", "-", "/", "_").Replace(text)
	if text == "" {
		return nil, errors.New("the bootstrap secret is empty")
	}
	secret, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("the bootstrap secret is not base64: %w", err)
	}
	if len(secret) != BootstrapSecretBytes {
		return nil, fmt.Errorf("the bootstrap secret must be %d bytes, got %d",
			BootstrapSecretBytes, len(secret))
	}
	return secret, nil
}
