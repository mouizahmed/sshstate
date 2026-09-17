package vault

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type Mutation struct {
	RecordID     protocol.ID
	RecordType   protocol.RecordType
	Rev          protocol.Counter
	ParentDigest []byte
	MutationID   protocol.ID
	Deleted      bool
}

type Writer struct {
	VaultID  protocol.ID
	DeviceID protocol.ID
	Signing  *crypto.SigningKey
	Keys     *Keys
}

func (w *Writer) Seal(m Mutation, payload any) (*protocol.Envelope, error) {
	if w == nil || w.Signing == nil || w.Keys == nil {
		return nil, errors.New("seal: vault is locked")
	}
	ctx := protocol.Context{
		Domain:        protocol.RecordDomain,
		FormatVersion: protocol.RecordFormatVersion,
		VaultID:       w.VaultID,
		RecordID:      m.RecordID,
		RecordType:    m.RecordType,
		KeyEpoch:      w.Keys.Epoch,
		Rev:           m.Rev,
		ParentDigest:  m.ParentDigest,
		MutationID:    m.MutationID,
		UpdatedBy:     w.DeviceID,
		Deleted:       m.Deleted,
	}
	if err := ctx.Validate(); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}

	var plaintext []byte
	var err error
	if m.Deleted {
		plaintext = []byte("{}")
	} else {
		if payload == nil {
			return nil, errors.New("seal: a live record needs a payload")
		}
		plaintext, err = protocol.Canonical(payload)
		if err != nil {
			return nil, fmt.Errorf("seal: payload: %w", err)
		}
	}

	key, err := w.Keys.For(m.RecordType)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	aad, err := ctx.AAD()
	if err != nil {
		return nil, fmt.Errorf("seal: aad: %w", err)
	}
	nonce, ciphertext, err := crypto.SealAEAD(key, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}

	env := &protocol.Envelope{Context: ctx, Nonce: nonce, Ciphertext: ciphertext}
	input, err := env.SigningInput()
	if err != nil {
		return nil, fmt.Errorf("seal: signing input: %w", err)
	}
	sig, err := w.Signing.Sign(protocol.RecordSignatureDomain, input)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	env.Signature = sig
	return env, nil
}

type VerifierFor func(device protocol.ID) (*crypto.VerifyKey, error)

type Reader struct {
	VaultID  protocol.ID
	Keys     *Keys
	Verifier VerifierFor
}

func (r *Reader) Open(env *protocol.Envelope, out any) error {
	if r == nil || r.Keys == nil {
		return errors.New("open: vault is locked")
	}
	if env == nil {
		return errors.New("open: nil envelope")
	}
	if err := env.Validate(); err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if env.Context.VaultID != r.VaultID {
		return fmt.Errorf("open: record belongs to vault %s, not %s", env.Context.VaultID, r.VaultID)
	}
	if env.Context.KeyEpoch != r.Keys.Epoch {
		return fmt.Errorf("open: record is at epoch %s, vault keys are at %s", env.Context.KeyEpoch, r.Keys.Epoch)
	}
	if r.Verifier == nil {
		return errors.New("open: no writer verifier configured")
	}
	vk, err := r.Verifier(env.Context.UpdatedBy)
	if err != nil {
		return fmt.Errorf("open: writer %s: %w", env.Context.UpdatedBy, err)
	}
	input, err := env.SigningInput()
	if err != nil {
		return fmt.Errorf("open: signing input: %w", err)
	}
	if err := crypto.Verify(vk, protocol.RecordSignatureDomain, input, env.Signature); err != nil {
		return fmt.Errorf("open: signature: %w", err)
	}

	key, err := r.Keys.For(env.Context.RecordType)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	aad, err := env.Context.AAD()
	if err != nil {
		return fmt.Errorf("open: aad: %w", err)
	}
	plaintext, err := crypto.OpenAEAD(key, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if env.Context.Deleted {
		if !bytes.Equal(plaintext, []byte("{}")) {
			return errors.New("open: tombstone carries a payload")
		}
		return nil
	}
	if out == nil {
		return nil
	}
	if err := protocol.StrictUnmarshal(plaintext, out); err != nil {
		return fmt.Errorf("open: payload: %w", err)
	}
	return nil
}
