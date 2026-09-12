// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func testContext(t *testing.T) Context {
	t.Helper()
	return Context{
		Domain:        RecordDomain,
		FormatVersion: RecordFormatVersion,
		VaultID:       MustNewID(),
		RecordID:      MustNewID(),
		RecordType:    RecordHost,
		KeyEpoch:      1,
		Rev:           1,
		MutationID:    MustNewID(),
		UpdatedBy:     MustNewID(),
	}
}

func testEnvelope(t *testing.T) Envelope {
	t.Helper()
	return Envelope{
		Context:    testContext(t),
		Nonce:      bytes.Repeat([]byte{1}, 24),
		Ciphertext: []byte("ciphertext"),
		Signature:  []byte("signature"),
	}
}

func TestContextValidation(t *testing.T) {
	base := testContext(t)
	if err := base.Validate(); err != nil {
		t.Fatalf("valid context rejected: %v", err)
	}

	bad := map[string]func(c *Context){
		"wrong domain":          func(c *Context) { c.Domain = "sshstate.record.v2" },
		"unknown format":        func(c *Context) { c.FormatVersion = 2 },
		"unknown type":          func(c *Context) { c.RecordType = "secret_sauce" },
		"epoch zero":            func(c *Context) { c.KeyEpoch = 0 },
		"rev zero":              func(c *Context) { c.Rev = 0 },
		"invalid vault id":      func(c *Context) { c.VaultID = "nope" },
		"invalid mutation id":   func(c *Context) { c.MutationID = "" },
		"parent on creation":    func(c *Context) { c.ParentDigest = make([]byte, sha256.Size) },
		"update without parent": func(c *Context) { c.Rev = 2 },
		"short parent digest":   func(c *Context) { c.Rev = 2; c.ParentDigest = []byte{1, 2, 3} },
	}
	for name, mutate := range bad {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted invalid context", name)
		}
	}
}

func TestDigestExcludesSeq(t *testing.T) {
	e := testEnvelope(t)
	before, err := e.Digest()
	if err != nil {
		t.Fatal(err)
	}
	e.Seq = 9001
	after, err := e.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("seq changed the record digest")
	}
	in1, err := e.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(in1, []byte("seq")) {
		t.Fatal("signing input mentions seq")
	}
}

func TestDigestCoversSignature(t *testing.T) {
	e := testEnvelope(t)
	before, _ := e.Digest()
	e.Signature = []byte("different")
	after, _ := e.Digest()
	if bytes.Equal(before, after) {
		t.Fatal("digest ignored the signature")
	}
}

func TestDigestChangesWithEveryContextField(t *testing.T) {
	base := testEnvelope(t)
	baseline, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(e *Envelope){
		"record type": func(e *Envelope) { e.Context.RecordType = RecordKey },
		"deleted":     func(e *Envelope) { e.Context.Deleted = true },
		"epoch":       func(e *Envelope) { e.Context.KeyEpoch = 2 },
		"rev":         func(e *Envelope) { e.Context.Rev = 2; e.Context.ParentDigest = baseline },
		"updated by":  func(e *Envelope) { e.Context.UpdatedBy = MustNewID() },
		"nonce":       func(e *Envelope) { e.Nonce = bytes.Repeat([]byte{2}, 24) },
		"ciphertext":  func(e *Envelope) { e.Ciphertext = []byte("other") },
	}
	for name, mutate := range mutations {
		e := base
		mutate(&e)
		got, err := e.Digest()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, baseline) {
			t.Errorf("%s: digest unchanged", name)
		}
	}
}

func TestUnsignedEnvelopeHasNoDigest(t *testing.T) {
	e := testEnvelope(t)
	e.Signature = nil
	if _, err := e.Digest(); err == nil {
		t.Fatal("produced a digest for an unsigned envelope")
	}
}

func TestSecretScopedTypes(t *testing.T) {
	secret := []RecordType{RecordKey, RecordConflictSecret}
	metadata := []RecordType{RecordHost, RecordKnownHost, RecordConflictMetadata}
	for _, tt := range secret {
		if !tt.SecretScoped() {
			t.Errorf("%s must use the vault secret key", tt)
		}
	}
	for _, tt := range metadata {
		if tt.SecretScoped() {
			t.Errorf("%s must use the vault metadata key", tt)
		}
	}
}
