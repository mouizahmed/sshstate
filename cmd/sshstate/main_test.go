// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/cli"
)

func TestUsageListsEveryRegisteredVerb(t *testing.T) {
	text := usage(nil)
	for _, c := range cli.Commands() {
		if !strings.Contains(text, c.Name) {
			t.Errorf("usage omits the %q verb", c.Name)
		}
		if !strings.Contains(text, c.Summary) {
			t.Errorf("usage omits the summary for %q", c.Name)
		}
	}
	if !strings.Contains(text, "version") {
		t.Error("usage omits version")
	}
}

func TestUsageDoesNotAdvertiseAVerbItAlsoDefers(t *testing.T) {
	registered := map[string]bool{}
	for _, c := range cli.Commands() {
		registered[c.Name] = true
	}
	for name := range laterMilestones {
		if registered[name] {
			t.Errorf("%q is both implemented and listed as not yet implemented", name)
		}
	}
	for name := range withdrawn {
		if registered[name] {
			t.Errorf("%q is both implemented and listed as withdrawn", name)
		}
		if laterMilestones[name] != "" {
			t.Errorf("%q is both deferred and withdrawn", name)
		}
	}
}

func TestDeferredVerbsExplainThemselves(t *testing.T) {
	for name, reason := range laterMilestones {
		if reason == "" {
			t.Errorf("%q is deferred with no reason", name)
		}
		if strings.ContainsAny(name, " \t") {
			t.Errorf("%q is not a flat verb; decision record 0003 settles that", name)
		}
	}
	for name, reason := range withdrawn {
		if reason == "" {
			t.Errorf("%q is withdrawn with no reason", name)
		}
	}
}

func runWith(t *testing.T, args ...string) error {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	old := os.Args
	os.Args = append([]string{"sshstate"}, args...)
	t.Cleanup(func() { os.Args = old })
	return run()
}

func TestRunReportsAnUnimplementedVerb(t *testing.T) {
	for name, reason := range laterMilestones {
		err := runWith(t, name)
		if err == nil {
			t.Fatalf("%q ran", name)
		}
		if !strings.Contains(err.Error(), reason) {
			t.Errorf("%q did not explain itself: %v", name, err)
		}
	}
	for name, reason := range withdrawn {
		err := runWith(t, name)
		if err == nil {
			t.Fatalf("%q ran", name)
		}
		if !strings.Contains(err.Error(), reason) {
			t.Errorf("%q did not explain itself: %v", name, err)
		}
	}
}

func TestRunPrintsTheVersion(t *testing.T) {
	if err := runWith(t, "version"); err != nil {
		t.Fatalf("version: %v", err)
	}
}

func TestRunReachesACommandThatNeedsNoDaemon(t *testing.T) {
	err := runWith(t, "trust", "abc", "--all")
	if err == nil {
		t.Fatal("contradictory arguments were accepted")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("run did not dispatch to the verb: %v", err)
	}
}
