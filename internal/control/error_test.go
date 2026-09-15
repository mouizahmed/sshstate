// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"testing"
)

func TestAPIErrorMatchesOnCodeNotMessage(t *testing.T) {
	locked := &APIError{Code: CodeLocked, Message: "vault is locked"}
	if !errors.Is(locked, ErrLocked) {
		t.Fatal("a locked error did not match ErrLocked")
	}
	if errors.Is(locked, ErrRecoveryUnconfirmed) {
		t.Fatal("a locked error matched an unrelated code")
	}

	differentMessage := &APIError{Code: CodeLocked, Message: "something else entirely"}
	if !errors.Is(differentMessage, ErrLocked) {
		t.Fatal("matching depends on the message, not the code")
	}

	wrapped := fmt.Errorf("unlock: %w", locked)
	if !errors.Is(wrapped, ErrLocked) {
		t.Fatal("a wrapped API error did not match")
	}
	if errors.Is(errors.New("plain"), ErrLocked) {
		t.Fatal("a plain error matched an API error")
	}
}
