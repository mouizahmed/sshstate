// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package sshkeys

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/ssh"
)

func fingerprintHex(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return hex.EncodeToString(sum[:])
}
