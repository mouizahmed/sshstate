package protocol

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	RecordDomain          = "sshstate.record.v1"
	RecordSignatureDomain = "sshstate.record-sig.v1"
)

const RecordFormatVersion = 1

type RecordType string

const (
	RecordHost             RecordType = "host"
	RecordKey              RecordType = "key"
	RecordKnownHost        RecordType = "known_host"
	RecordConflictMetadata RecordType = "conflict_metadata"
	RecordConflictSecret   RecordType = "conflict_secret"
)

func (t RecordType) Valid() bool {
	switch t {
	case RecordHost, RecordKey, RecordKnownHost, RecordConflictMetadata, RecordConflictSecret:
		return true
	}
	return false
}

func (t RecordType) SecretScoped() bool {
	return t == RecordKey || t == RecordConflictSecret
}

type Context struct {
	Domain        string     `json:"domain"`
	FormatVersion int        `json:"format_version"`
	VaultID       ID         `json:"vault_id"`
	RecordID      ID         `json:"record_id"`
	RecordType    RecordType `json:"record_type"`
	KeyEpoch      Counter    `json:"key_epoch"`
	Rev           Counter    `json:"rev"`
	ParentDigest  Bytes      `json:"parent_digest"`
	MutationID    ID         `json:"mutation_id"`
	UpdatedBy     ID         `json:"updated_by"`
	Deleted       bool       `json:"deleted"`
}

func (c *Context) Validate() error {
	if c.Domain != RecordDomain {
		return fmt.Errorf("record domain %q is not %q", c.Domain, RecordDomain)
	}
	if c.FormatVersion != RecordFormatVersion {
		return fmt.Errorf("unsupported record format version %d", c.FormatVersion)
	}
	if err := c.VaultID.check("vault_id"); err != nil {
		return err
	}
	if err := c.RecordID.check("record_id"); err != nil {
		return err
	}
	if err := c.MutationID.check("mutation_id"); err != nil {
		return err
	}
	if err := c.UpdatedBy.check("updated_by"); err != nil {
		return err
	}
	if !c.RecordType.Valid() {
		return fmt.Errorf("unknown record type %q", c.RecordType)
	}
	if c.KeyEpoch < 1 {
		return errors.New("key_epoch starts at 1")
	}
	if c.Rev < 1 {
		return errors.New("rev starts at 1")
	}
	if c.Rev == 1 && c.ParentDigest != nil {
		return errors.New("rev 1 is a creation and must not carry a parent_digest")
	}
	if c.Rev > 1 && len(c.ParentDigest) != sha256.Size {
		return fmt.Errorf("rev %s needs a %d-byte parent_digest, got %d", c.Rev, sha256.Size, len(c.ParentDigest))
	}
	return nil
}

func (c *Context) AAD() ([]byte, error) { return Canonical(c) }

type Envelope struct {
	Context    Context `json:"context"`
	Nonce      Bytes   `json:"nonce"`
	Ciphertext Bytes   `json:"ciphertext"`
	Signature  Bytes   `json:"signature"`
	Seq        Counter `json:"seq,omitempty"`
}

type signedView struct {
	Context    Context `json:"context"`
	Nonce      Bytes   `json:"nonce"`
	Ciphertext Bytes   `json:"ciphertext"`
}

type digestView struct {
	Context    Context `json:"context"`
	Nonce      Bytes   `json:"nonce"`
	Ciphertext Bytes   `json:"ciphertext"`
	Signature  Bytes   `json:"signature"`
}

func (e *Envelope) SigningInput() ([]byte, error) {
	return Canonical(signedView{Context: e.Context, Nonce: e.Nonce, Ciphertext: e.Ciphertext})
}

func (e *Envelope) Digest() ([]byte, error) {
	if len(e.Signature) == 0 {
		return nil, errors.New("digest: envelope is unsigned")
	}
	canon, err := Canonical(digestView{
		Context:    e.Context,
		Nonce:      e.Nonce,
		Ciphertext: e.Ciphertext,
		Signature:  e.Signature,
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}

func (e *Envelope) Validate() error {
	if err := e.Context.Validate(); err != nil {
		return err
	}
	if len(e.Nonce) == 0 {
		return errors.New("envelope has no nonce")
	}
	if len(e.Ciphertext) == 0 {
		return errors.New("envelope has no ciphertext")
	}
	if len(e.Signature) == 0 {
		return errors.New("envelope has no signature")
	}
	return nil
}
