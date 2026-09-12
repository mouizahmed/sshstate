// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const SymmetricKeySize = chacha20poly1305.KeySize

const NonceSize = chacha20poly1305.NonceSizeX

type SymmetricKey [SymmetricKeySize]byte

func NewSymmetricKey() (*SymmetricKey, error) {
	var k SymmetricKey
	if _, err := rand.Read(k[:]); err != nil {
		return nil, fmt.Errorf("generate symmetric key: %w", err)
	}
	return &k, nil
}

func SymmetricKeyFromBytes(b []byte) (*SymmetricKey, error) {
	if len(b) != SymmetricKeySize {
		return nil, fmt.Errorf("symmetric key must be %d bytes, got %d", SymmetricKeySize, len(b))
	}
	var k SymmetricKey
	copy(k[:], b)
	return &k, nil
}

func (k SymmetricKey) String() string { return "[redacted symmetric key]" }

func (k SymmetricKey) GoString() string { return k.String() }

func (k *SymmetricKey) Wipe() {
	if k == nil {
		return
	}
	clear(k[:])
}

func SealAEAD(key *SymmetricKey, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	if key == nil {
		return nil, nil, errors.New("seal: nil key")
	}
	if len(aad) == 0 {
		return nil, nil, errors.New("seal: aad is required")
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("seal: %w", err)
	}
	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("seal: nonce: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func OpenAEAD(key *SymmetricKey, nonce, ciphertext, aad []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("open: nil key")
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("open: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	if len(aad) == 0 {
		return nil, errors.New("open: aad is required")
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("open: authentication failed")
	}
	return pt, nil
}
