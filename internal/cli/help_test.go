package cli

import (
	"errors"
	"flag"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var helpFlag = regexp.MustCompile(`(?m)^  (-+)([a-z][a-z-]*)`)

func TestEveryCommandAnswersHelp(t *testing.T) {
	for _, c := range Commands() {
		t.Run(c.Name, func(t *testing.T) {
			s := newScripted(t)
			err := s.run(t, c.Name, "--help")
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("--help returned %v, not a help request", err)
			}
			out := s.out.String()
			if !strings.HasPrefix(out, "usage: sshstate "+c.Name) {
				t.Fatalf("help does not start with the usage line:\n%s", out)
			}
			if !strings.Contains(out, sentence(c.Summary)) {
				t.Fatalf("help does not say what the command does:\n%s", out)
			}
			for _, m := range helpFlag.FindAllStringSubmatch(out, -1) {
				dashes, name := m[1], m[2]
				if len(name) > 1 && dashes != "--" {
					t.Errorf("help shows %s%s instead of --%s", dashes, name, name)
				}
				if !regexp.MustCompile(`(^|[\s\[|])` + dashes + regexp.QuoteMeta(name) + `\b`).MatchString(c.Args) {
					t.Errorf("the usage line %q omits %s%s", c.Args, dashes, name)
				}
			}
		})
	}
}

func TestEveryCommandIsInAKnownGroup(t *testing.T) {
	for _, c := range Commands() {
		if !slices.Contains(Groups(), c.Group) {
			t.Errorf("%q is in group %q, which usage never prints", c.Name, c.Group)
		}
	}
}

func TestAFlagMistakeShowsTheUsageLine(t *testing.T) {
	s := newScripted(t)
	err := s.run(t, "add", "prod", "--bogus")
	if err == nil {
		t.Fatal("an unknown flag was accepted")
	}
	for _, want := range []string{"--bogus", "usage: sshstate add <alias>", "sshstate add --help"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

func TestPositionalVerbsAcceptFlagsFirst(t *testing.T) {
	s := newScripted(t)
	err := s.run(t, "revoke", "--yes")
	if err == nil || !strings.Contains(err.Error(), "usage: sshstate revoke") {
		t.Fatalf("revoke with no device did not print its usage: %v", err)
	}
}

func TestLockOnALockedVaultSaysSo(t *testing.T) {
	s, _ := newUnlocked(t)
	s.mustRun(t, "lock")
	s.out.Reset()
	s.mustRun(t, "lock")
	if !strings.Contains(s.out.String(), "Already locked") {
		t.Fatalf("locking a locked vault did not say so:\n%s", s.out.String())
	}
}
