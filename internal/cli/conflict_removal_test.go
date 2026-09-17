// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"regexp"
	"strings"
	"testing"
)

func conflictIDs(t *testing.T, s *scripted) []string {
	t.Helper()
	s.out.Reset()
	s.mustRun(t, "conflicts")
	var ids []string
	for _, m := range regexp.MustCompile(`(?m)^\s+([0-9a-f]{32})$`).FindAllStringSubmatch(s.out.String(), -1) {
		ids = append(ids, m[1])
	}
	return ids
}

func TestARemovalThatLosesToAnEditIsKeptAside(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	b := pairInto(t, r.url, a, vaultIDOf(t, a), "b's own password")

	a.mustRun(t, "remove", "prod", "--yes")
	b.mustRun(t, "edit", "prod", "--port", "2299")
	b.mustRun(t, "sync")
	a.mustRun(t, "sync")

	a.out.Reset()
	a.mustRun(t, "hosts")
	if got := a.out.String(); !strings.Contains(got, "ubuntu@10.0.0.5:2299") {
		t.Fatalf("the other device's edit did not win the record:\n%s", got)
	}
	a.out.Reset()
	a.mustRun(t, "conflicts")
	listing := a.out.String()
	if !strings.Contains(listing, "prod") || !strings.Contains(listing, "resolve removes it") {
		t.Fatalf("the losing removal is not listed clearly:\n%s", listing)
	}
	ids := conflictIDs(t, a)
	if len(ids) != 1 {
		t.Fatalf("want one conflict, got %v", ids)
	}
	a.mustRun(t, "resolve", ids[0])
	a.mustRun(t, "sync")
	b.mustRun(t, "sync")
	b.out.Reset()
	b.mustRun(t, "hosts")
	if got := b.out.String(); strings.Contains(got, "prod") {
		t.Fatalf("resolving the kept removal did not remove the host everywhere:\n%s", got)
	}
}
