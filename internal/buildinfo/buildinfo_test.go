// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package buildinfo

import (
	"strings"
	"testing"
)

func TestStringPrefersTheStampedVersion(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })

	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("a stamped version rendered as %q", got)
	}

	Version = ""
	if got := String(); got == "" {
		t.Fatal("an unstamped build has no version string at all")
	}
}

func TestNoticeCarriesTheLicenceTerms(t *testing.T) {
	n := Notice()
	for _, want := range []string{License, Copyright, SourceURL, "NO WARRANTY"} {
		if !strings.Contains(n, want) {
			t.Errorf("the notice omits %q:\n%s", want, n)
		}
	}
	if !strings.Contains(n, "AGPL") && !strings.Contains(n, "Affero") {
		t.Fatalf("the notice does not name the licence:\n%s", n)
	}
}
