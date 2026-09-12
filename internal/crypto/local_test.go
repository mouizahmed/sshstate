// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

func TestAEADRoundTripAndAADBinding(t *testing.T) {
	key, err := NewSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(`{"domain":"test"}`)
	nonce, ct, err := SealAEAD(key, []byte("payload"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("nonce is %d bytes, want %d", len(nonce), NonceSize)
	}
	got, err := OpenAEAD(key, nonce, ct, aad)
	if err != nil || string(got) != "payload" {
		t.Fatalf("round trip failed: %q %v", got, err)
	}
	if _, err := OpenAEAD(key, nonce, ct, []byte(`{"domain":"other"}`)); err == nil {
		t.Fatal("a different AAD decrypted the payload")
	}
	other, _ := NewSymmetricKey()
	if _, err := OpenAEAD(other, nonce, ct, aad); err == nil {
		t.Fatal("a different key decrypted the payload")
	}
}

func TestAEADRequiresAAD(t *testing.T) {
	key, _ := NewSymmetricKey()
	if _, _, err := SealAEAD(key, []byte("x"), nil); err == nil {
		t.Fatal("sealed without AAD; every caller in this system has a context to bind")
	}
}

func TestAEADTamperDetection(t *testing.T) {
	key, _ := NewSymmetricKey()
	aad := []byte(`{"a":1}`)
	nonce, ct, _ := SealAEAD(key, []byte("payload"), aad)
	for i := range ct {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x01
		if _, err := OpenAEAD(key, nonce, bad, aad); err == nil {
			t.Fatalf("accepted ciphertext with byte %d flipped", i)
		}
	}
	badNonce := bytes.Clone(nonce)
	badNonce[0] ^= 0x01
	if _, err := OpenAEAD(key, badNonce, ct, aad); err == nil {
		t.Fatal("accepted a modified nonce")
	}
}

func TestNoncesAreFresh(t *testing.T) {
	key, _ := NewSymmetricKey()
	aad := []byte(`{"a":1}`)
	seen := make(map[string]bool, 512)
	for i := 0; i < 512; i++ {
		nonce, _, err := SealAEAD(key, []byte("same plaintext"), aad)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(nonce)] {
			t.Fatal("nonce repeated under the same key")
		}
		seen[string(nonce)] = true
	}
}

func TestSymmetricKeyRedactsAndWipes(t *testing.T) {
	key, _ := NewSymmetricKey()
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(format, *key); !strings.Contains(got, "redacted") {
			t.Errorf("%s did not redact the key: %s", format, got)
		}
	}
	key.Wipe()
	if *key != (SymmetricKey{}) {
		t.Fatal("Wipe left key material behind")
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	vault, device := protocol.MustNewID(), protocol.MustNewID()
	secret := []byte("vault metadata key material 32by")
	w, err := Wrap([]byte("correct horse"), vault, device, PurposeVaultMetadataKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.Unwrap([]byte("correct horse"), vault, device, PurposeVaultMetadataKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("unwrapped secret differs")
	}
}

func TestWrapperContextIsBound(t *testing.T) {
	vault, device := protocol.MustNewID(), protocol.MustNewID()
	secret := []byte("secret")
	w, err := Wrap([]byte("pw"), vault, device, PurposeVaultMetadataKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		pw            string
		vault, device protocol.ID
		purpose       string
	}{
		"wrong password": {"other", vault, device, PurposeVaultMetadataKey},
		"other vault":    {"pw", protocol.MustNewID(), device, PurposeVaultMetadataKey},
		"other device":   {"pw", vault, protocol.MustNewID(), PurposeVaultMetadataKey},
		"other purpose":  {"pw", vault, device, PurposeVaultSecretKey},
	}
	for name, c := range cases {
		if _, err := w.Unwrap([]byte(c.pw), c.vault, c.device, c.purpose); err == nil {
			t.Errorf("%s: unwrapped anyway", name)
		}
	}
}

func TestWrapperHeaderIsSelfDescribing(t *testing.T) {
	vault, device := protocol.MustNewID(), protocol.MustNewID()
	w, err := Wrap([]byte("pw"), vault, device, PurposeVaultSecretKey, []byte("s"))
	if err != nil {
		t.Fatal(err)
	}
	if w.KDF.Algorithm != KDFAlgorithm || w.KDF.MemoryKiB != KDFMemoryKiB ||
		w.KDF.Iterations != KDFIterations || w.KDF.Lanes != KDFLanes {
		t.Fatalf("wrapper did not record the write profile: %+v", w.KDF)
	}
	if len(w.KDF.Salt) != KDFSaltSize {
		t.Fatalf("salt is %d bytes, want %d", len(w.KDF.Salt), KDFSaltSize)
	}
	second, _ := Wrap([]byte("pw"), vault, device, PurposeVaultSecretKey, []byte("s"))
	if bytes.Equal(w.KDF.Salt, second.KDF.Salt) {
		t.Fatal("two wrappers shared a salt")
	}
}

func TestKDFParamsBoundUntrustedHeaders(t *testing.T) {
	good, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("default profile rejected: %v", err)
	}
	bad := map[string]func(p *KDFParams){
		"absurd memory":    func(p *KDFParams) { p.MemoryKiB = 1 << 24 },
		"zero memory":      func(p *KDFParams) { p.MemoryKiB = 0 },
		"absurd iteration": func(p *KDFParams) { p.Iterations = 1000 },
		"zero iterations":  func(p *KDFParams) { p.Iterations = 0 },
		"absurd lanes":     func(p *KDFParams) { p.Lanes = 255 },
		"zero lanes":       func(p *KDFParams) { p.Lanes = 0 },
		"other algorithm":  func(p *KDFParams) { p.Algorithm = "scrypt" },
		"other version":    func(p *KDFParams) { p.Version = 16 },
		"short salt":       func(p *KDFParams) { p.Salt = []byte{1} },
	}
	for name, mutate := range bad {
		p := good
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted a hostile KDF header", name)
		}
		if _, err := p.DeriveKEK([]byte("pw")); err == nil {
			t.Errorf("%s: derived a KEK from a hostile header", name)
		}
	}
}

func TestRewrapChangesPasswordNotSecret(t *testing.T) {
	vault, device := protocol.MustNewID(), protocol.MustNewID()
	secret := []byte("device signing seed")
	first, err := Wrap([]byte("old"), vault, device, PurposeDeviceSigningKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := first.Unwrap([]byte("old"), vault, device, PurposeDeviceSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Rewrap([]byte("new"), vault, device, PurposeDeviceSigningKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Unwrap([]byte("old"), vault, device, PurposeDeviceSigningKey); err == nil {
		t.Fatal("old password still opens the rewrapped secret")
	}
	got, err := second.Unwrap([]byte("new"), vault, device, PurposeDeviceSigningKey)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("rewrap changed the secret: %v", err)
	}
	if bytes.Equal(first.KDF.Salt, second.KDF.Salt) {
		t.Fatal("rewrap reused the salt")
	}
}

func TestEmptyPasswordRejected(t *testing.T) {
	vault, device := protocol.MustNewID(), protocol.MustNewID()
	if _, err := Wrap(nil, vault, device, PurposeVaultSecretKey, []byte("s")); err == nil {
		t.Fatal("wrapped under an empty password")
	}
}
