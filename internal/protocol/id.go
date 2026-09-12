// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const IDBytes = 16

type ID string

func NewID() (ID, error) {
	var b [IDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("new id: %w", err)
	}
	return ID(hex.EncodeToString(b[:])), nil
}

func MustNewID() ID {
	id, err := NewID()
	if err != nil {
		panic(err)
	}
	return id
}

func (id ID) Valid() bool {
	if len(id) != IDBytes*2 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (id ID) check(field string) error {
	if !id.Valid() {
		return fmt.Errorf("%s is not a 128-bit lowercase hex id", field)
	}
	return nil
}

func (id ID) String() string { return string(id) }
