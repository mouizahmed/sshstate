// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func listReady(t *testing.T) (*scripted, string, string) {
	t.Helper()
	s := newScripted(t)
	kitPath := filepath.Join(t.TempDir(), "kit.txt")
	s.secrets = []string{password, password}
	s.answer = func(string) (string, error) {
		body, _ := os.ReadFile(kitPath)
		kit, err := vault.ParseKit(string(body))
		if err != nil {
			return "", err
		}
		return kit.Checksum(), nil
	}
	s.mustRun(t, "init", "--kit", kitPath)
	s.answer = nil
	s.startDaemon(t)
	s.secrets = []string{password}
	s.mustRun(t, "unlock")

	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	writeTestKey(t, first, "laptop@home")
	writeTestKey(t, second, "work-key")
	s.out.Reset()
	s.mustRun(t, "add-key", first)
	firstID := extractRecordID(t, s.out.String())
	s.out.Reset()
	s.mustRun(t, "add-key", second)
	secondID := extractRecordID(t, s.out.String())
	s.out.Reset()
	s.errOut.Reset()
	return s, firstID, secondID
}

func TestKeysListsWhatAddKeyPrintedOnce(t *testing.T) {
	s, firstID, secondID := listReady(t)
	s.mustRun(t, "keys")
	out := s.out.String()
	for _, want := range []string{firstID, secondID, "laptop@home", "work-key", "SHA256:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("keys did not show %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "offered to nothing") {
		t.Fatalf("an unreferenced key was not reported as such:\n%s", out)
	}
}

func TestHostsShowsTheDefinitionAndItsKeys(t *testing.T) {
	s, firstID, _ := listReady(t)
	s.mustRun(t, "add", "bastion", "--hostname", "10.0.0.1", "--user", "ubuntu")
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu",
		"--port", "2222", "--jump", "bastion", "--key", firstID)
	s.out.Reset()
	s.mustRun(t, "hosts")
	out := s.out.String()
	for _, want := range []string{"prod", "ubuntu@10.0.0.5:2222", "jump    bastion", firstID[:8], "2 hosts"} {
		if !strings.Contains(out, want) {
			t.Fatalf("hosts did not show %q:\n%s", want, out)
		}
	}
	if !strings.Contains(s.errOut.String(), "no keys") {
		t.Fatalf("a host with no keys was not flagged:\n%s", s.errOut)
	}

	s.out.Reset()
	s.mustRun(t, "keys")
	if !strings.Contains(s.out.String(), "offered to prod") {
		t.Fatalf("keys did not say which host uses it:\n%s", s.out)
	}
}

func TestAKeyCanBeNamedByPrefixFingerprintOrComment(t *testing.T) {
	s, firstID, _ := listReady(t)
	keys, err := s.Env.Client().Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	for _, k := range keys {
		if k.RecordID == firstID {
			fingerprint = k.Fingerprint
		}
	}

	for i, want := range []string{firstID[:8], fingerprint, "laptop@home"} {
		alias := []string{"a", "b", "c"}[i]
		s.mustRun(t, "add", alias, "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", want)
		hosts, err := s.Env.Client().Hosts(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, h := range hosts {
			if h.Alias == alias {
				found = true
				if len(h.KeyIDs) != 1 || h.KeyIDs[0] != firstID {
					t.Fatalf("%q resolved to %v, expected %s", want, h.KeyIDs, firstID)
				}
			}
		}
		if !found {
			t.Fatalf("host %s was not created from key reference %q", alias, want)
		}
	}
}

func TestAnUnknownKeyReferenceIsRefused(t *testing.T) {
	s, _, _ := listReady(t)
	err := s.run(t, "add", "y", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", "nosuchkey")
	if err == nil || !strings.Contains(err.Error(), "sshstate keys") {
		t.Fatalf("expected a refusal pointing at the listing, got %v", err)
	}
	hosts, herr := s.Env.Client().Hosts(context.Background())
	if herr != nil {
		t.Fatal(herr)
	}
	for _, h := range hosts {
		if h.Alias == "y" {
			t.Fatal("the host was created despite the unresolvable key")
		}
	}
}

func TestResolveKeyIDMatching(t *testing.T) {
	keys := []control.KeyResponse{
		{RecordID: "aaaa1111aaaa1111aaaa1111aaaa1111", Fingerprint: "SHA256:AAAduplicate", Algorithm: "ssh-ed25519", Comment: "laptop"},
		{RecordID: "aaaa2222aaaa2222aaaa2222aaaa2222", Fingerprint: "SHA256:BBBunique", Algorithm: "ssh-ed25519", Comment: "desktop"},
		{RecordID: "bbbb3333bbbb3333bbbb3333bbbb3333", Fingerprint: "SHA256:CCCother", Algorithm: "ssh-rsa", Comment: ""},
	}
	for _, tc := range []struct{ want, expect string }{
		{"aaaa1111aaaa1111aaaa1111aaaa1111", keys[0].RecordID},
		{"aaaa1", keys[0].RecordID},
		{"SHA256:BBBunique", keys[1].RecordID},
		{"BBBunique", keys[1].RecordID},
		{"desktop", keys[1].RecordID},
		{"DESKTOP", keys[1].RecordID},
		{"bbbb", keys[2].RecordID},
	} {
		got, err := resolveKeyID(keys, tc.want)
		if err != nil {
			t.Errorf("%q: %v", tc.want, err)
			continue
		}
		if got != tc.expect {
			t.Errorf("%q resolved to %s, expected %s", tc.want, got, tc.expect)
		}
	}

	if _, err := resolveKeyID(keys, "aaaa"); err == nil {
		t.Fatal("a prefix shared by two keys was accepted")
	} else {
		if !strings.Contains(err.Error(), "matches 2 keys") {
			t.Fatalf("the refusal does not say how many matched: %v", err)
		}
		for _, want := range []string{"aaaa1111", "aaaa2222", "laptop", "desktop"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not list %q: %v", want, err)
			}
		}
	}
	if _, err := resolveKeyID(keys, "nothing"); err == nil {
		t.Fatal("an unmatched reference was accepted")
	}
	if _, err := resolveKeyID(keys, "  "); err == nil {
		t.Fatal("a blank reference was accepted")
	}
}

func TestResolveRecordIDMatching(t *testing.T) {
	ids := []string{"ab11111111111111111111111111111e", "ab22222222222222222222222222222f", "cd3333333333333333333333333333aa"}
	if got, err := resolveRecordID(ids, "cd", "conflict"); err != nil || got != ids[2] {
		t.Fatalf("unique prefix resolved to %q, %v", got, err)
	}
	if got, err := resolveRecordID(ids, ids[0], "conflict"); err != nil || got != ids[0] {
		t.Fatalf("a full id resolved to %q, %v", got, err)
	}
	if _, err := resolveRecordID(ids, "ab", "conflict"); err == nil {
		t.Fatal("an ambiguous prefix was accepted")
	} else if !strings.Contains(err.Error(), "more characters") {
		t.Fatalf("unhelpful refusal: %v", err)
	}
	if _, err := resolveRecordID(ids, "zz", "conflict"); err == nil {
		t.Fatal("an unmatched prefix was accepted")
	}
}
