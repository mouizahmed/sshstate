// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const ConflictIDDomain = "sshstate.conflict-id.v1"

type conflictIDInput struct {
	Domain           string `json:"domain"`
	VaultID          ID     `json:"vault_id"`
	SourceRecordID   ID     `json:"source_record_id"`
	SourceMutationID ID     `json:"source_mutation_id"`
}

func ConflictID(vaultID, sourceRecordID, sourceMutationID ID) (ID, error) {
	for name, id := range map[string]ID{
		"vault_id":           vaultID,
		"source_record_id":   sourceRecordID,
		"source_mutation_id": sourceMutationID,
	} {
		if err := id.check(name); err != nil {
			return "", fmt.Errorf("conflict id: %w", err)
		}
	}
	canon, err := Canonical(conflictIDInput{
		Domain:           ConflictIDDomain,
		VaultID:          vaultID,
		SourceRecordID:   sourceRecordID,
		SourceMutationID: sourceMutationID,
	})
	if err != nil {
		return "", fmt.Errorf("conflict id: %w", err)
	}
	sum := sha256.Sum256(canon)
	return ID(hex.EncodeToString(sum[:IDBytes])), nil
}
