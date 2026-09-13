// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import "testing"

func TestConflictIDsAreDeterministicAndDistinct(t *testing.T) {
	const (
		vaultA    ID = "11111111111111111111111111111111"
		vaultB    ID = "22222222222222222222222222222222"
		record    ID = "33333333333333333333333333333333"
		mutationA ID = "44444444444444444444444444444444"
		mutationB ID = "55555555555555555555555555555555"
	)
	inputs := [][3]ID{
		{vaultA, record, mutationA},
		{vaultA, record, mutationB},
		{vaultB, record, mutationA},
	}
	seen := map[ID]bool{}
	for _, in := range inputs {
		id, err := ConflictID(in[0], in[1], in[2])
		if err != nil {
			t.Fatal(err)
		}
		again, err := ConflictID(in[0], in[1], in[2])
		if err != nil {
			t.Fatal(err)
		}
		if id != again {
			t.Fatalf("conflict id is not deterministic: %s then %s", id, again)
		}
		if !id.Valid() {
			t.Fatalf("derived conflict id %q is not a valid identifier", id)
		}
		if seen[id] {
			t.Fatalf("different inputs produced the same conflict id %s", id)
		}
		seen[id] = true
	}
}

func TestConflictIDRejectsMalformedInputs(t *testing.T) {
	const good ID = "11111111111111111111111111111111"
	for name, in := range map[string][3]ID{
		"vault":    {"not-an-id", good, good},
		"record":   {good, "", good},
		"mutation": {good, good, "ABCDEF11111111111111111111111111"},
	} {
		if _, err := ConflictID(in[0], in[1], in[2]); err == nil {
			t.Errorf("a malformed %s id produced a conflict id", name)
		}
	}
}
