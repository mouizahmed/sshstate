// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	for name := range unimplementedVerbs {
		if registered[name] {
			t.Errorf("%q is both implemented and listed as not yet implemented", name)
		}
	}
	for name := range withdrawn {
		if registered[name] {
			t.Errorf("%q is both implemented and listed as withdrawn", name)
		}
		if unimplementedVerbs[name] != "" {
			t.Errorf("%q is both deferred and withdrawn", name)
		}
	}
}

func TestDeferredVerbsExplainThemselves(t *testing.T) {
	for name, reason := range unimplementedVerbs {
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
	for name, reason := range unimplementedVerbs {
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

func TestEverySuggestedCommandExists(t *testing.T) {
	registered := map[string]bool{"version": true}
	for _, c := range cli.Commands() {
		registered[c.Name] = true
	}
	suggestion := regexp.MustCompile(`(?:run|with|Next|Try|re-register it with|start it with|finish setting it up with):\s+sshstate ([a-z][a-z-]*)`)
	root := filepath.Join("..", "..", "internal")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range suggestion.FindAllStringSubmatch(string(body), -1) {
			if !registered[m[1]] {
				t.Errorf("%s tells users to run \"sshstate %s\", which is not a command", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHelpForOneCommandSucceeds(t *testing.T) {
	for _, args := range [][]string{{"help", "import"}, {"import", "--help"}, {"status", "-h"}} {
		var out strings.Builder
		env := &cli.Env{Stdout: &out, Stderr: &out}
		if err := dispatch(env, args[0], args[1:]); err != nil {
			t.Errorf("%v: %v", args, err)
		}
		if !strings.Contains(out.String(), "usage: sshstate") {
			t.Errorf("%v printed no usage:\n%s", args, out.String())
		}
	}
}

func TestUsageListsEachCommandUnderItsGroup(t *testing.T) {
	sections := map[string][]string{}
	var order []string
	current := ""
	for _, line := range strings.Split(usage(nil), "\n") {
		switch {
		case strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " "):
			current = strings.TrimSuffix(line, ":")
			order = append(order, current)
		case strings.HasPrefix(line, "  ") && current != "":
			sections[current] = append(sections[current], strings.Fields(line)[0])
		}
	}
	groups := cli.Groups()
	if len(order) < len(groups) || !slices.Equal(order[:len(groups)], groups) {
		t.Fatalf("usage headings are %v, want %v first", order, groups)
	}
	for _, c := range cli.Commands() {
		if !slices.Contains(sections[c.Group], c.Name) {
			t.Errorf("%q is not listed under %q: %v", c.Name, c.Group, sections[c.Group])
		}
	}
}
