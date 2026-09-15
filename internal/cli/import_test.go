// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/vault"
)

func importReady(t *testing.T) *scripted {
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
	s.out.Reset()
	s.errOut.Reset()
	return s
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportCreatesHostsAndResolvesDefaults(t *testing.T) {
	s := importReady(t)
	path := writeConfig(t, "Host bastion\n HostName 10.0.0.1\n User ubuntu\n\nHost prod\n HostName 10.0.0.5\n ProxyJump bastion\n")

	s.mustRun(t, "import", path)

	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("imported %d hosts:\n%s", len(hosts), s.out)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.Port != 22 {
			t.Errorf("%s got port %d; an omitted Port must be stored as 22", h.Alias, h.Port)
		}
		if h.Alias == "prod" {
			if h.User != me.Username {
				t.Errorf("an omitted User became %q, expected this machine's %q", h.User, me.Username)
			}
			if h.ProxyJump == nil || *h.ProxyJump != "bastion" {
				t.Errorf("ProxyJump is %v", h.ProxyJump)
			}
		}
	}
	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Host prod") {
		t.Fatalf("the generated config was not rewritten:\n%s", body)
	}
}

func TestImportDryRunWritesNothing(t *testing.T) {
	s := importReady(t)
	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n")

	s.mustRun(t, "import", path, "--dry-run")

	if !strings.Contains(s.out.String(), "new") {
		t.Fatalf("the plan did not report the new host:\n%s", s.out)
	}
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Fatalf("--dry-run created %d hosts", len(hosts))
	}
}

func TestReimportingTheSameDefinitionChangesNothing(t *testing.T) {
	s := importReady(t)
	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n Port 22\n")
	s.mustRun(t, "import", path)
	before, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	s.out.Reset()
	s.mustRun(t, "import", path)
	if !strings.Contains(s.out.String(), "unchanged") {
		t.Fatalf("a repeat import did not report the host as unchanged:\n%s", s.out)
	}
	after, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].RecordID != before[0].RecordID {
		t.Fatalf("a repeat import produced %d hosts", len(after))
	}
	conflicts, err := s.Env.Client().Conflicts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts.Conflicts) != 0 {
		t.Fatalf("an identical re-import preserved %d conflicts", len(conflicts.Conflicts))
	}
}

func TestADifferingDefinitionBecomesAConflict(t *testing.T) {
	s := importReady(t)
	s.mustRun(t, "import", writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n"))
	s.out.Reset()

	s.mustRun(t, "import", writeConfig(t, "Host prod\n HostName 10.9.9.9\n User root\n"))

	if !strings.Contains(s.out.String(), "conflict") {
		t.Fatalf("the differing definition was not reported as a conflict:\n%s", s.out)
	}
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("the import added a second host under the same alias: %d hosts", len(hosts))
	}
	if hosts[0].HostName != "10.0.0.5" || hosts[0].User != "ubuntu" {
		t.Fatalf("the existing host was overwritten: %s@%s", hosts[0].User, hosts[0].HostName)
	}
	conflicts, err := s.Env.Client().Conflicts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts.Conflicts) != 1 {
		t.Fatalf("%d conflicts were preserved, expected 1", len(conflicts.Conflicts))
	}
}

func TestImportingTheSameConflictTwicePreservesOne(t *testing.T) {
	s := importReady(t)
	s.mustRun(t, "import", writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n"))
	differing := writeConfig(t, "Host prod\n HostName 10.9.9.9\n User ubuntu\n")
	s.mustRun(t, "import", differing)
	s.mustRun(t, "import", differing)

	conflicts, err := s.Env.Client().Conflicts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts.Conflicts) != 1 {
		t.Fatalf("importing the same differing file twice preserved %d conflicts", len(conflicts.Conflicts))
	}
}

func TestImportRefusesTheWholeFileForOneBadLine(t *testing.T) {
	s := importReady(t)
	path := writeConfig(t, "Host good\n HostName 10.0.0.1\n User ubuntu\n\nHost bad\n HostName 10.0.0.2\n ProxyCommand nc %h %p\n")

	err := s.run(t, "import", path)
	if err == nil {
		t.Fatal("a file with an unsupported directive was imported")
	}
	if !strings.Contains(s.errOut.String(), path+":7") {
		t.Fatalf("the diagnostic does not name the file and line:\n%s", s.errOut)
	}
	hosts, herr := s.Env.Client().Hosts(context.Background())
	if herr != nil {
		t.Fatal(herr)
	}
	if len(hosts) != 0 {
		t.Fatalf("%d hosts were imported from a refused file; §3.2 forbids a partial import", len(hosts))
	}
}

func TestImportResolvesIdentityFilesToVaultKeys(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	writeTestKey(t, first, "first")
	writeTestKey(t, second, "second")
	s.mustRun(t, "add-key", first)
	firstID := extractRecordID(t, s.out.String())
	s.out.Reset()
	s.mustRun(t, "add-key", second)
	secondID := extractRecordID(t, s.out.String())
	s.out.Reset()

	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+second+"\n IdentityFile "+first+"\n")
	s.mustRun(t, "import", path)

	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts[0].KeyIDs) != 2 {
		t.Fatalf("the host references %d keys", len(hosts[0].KeyIDs))
	}
	if hosts[0].KeyIDs[0] != secondID || hosts[0].KeyIDs[1] != firstID {
		t.Fatalf("IdentityFile order was not preserved: %v", hosts[0].KeyIDs)
	}
}

func TestImportNamesAnIdentityFileTheVaultDoesNotHave(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	stray := filepath.Join(dir, "stray")
	writeTestKey(t, stray, "stray")

	err := s.run(t, "import", writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+stray+"\n"))
	if err == nil {
		t.Fatal("a host referencing an unknown key was imported")
	}
	out := s.errOut.String()
	if !strings.Contains(out, "--with-keys") {
		t.Fatalf("the diagnostic does not say how to fix it:\n%s", out)
	}
	if !strings.Contains(out, stray) {
		t.Fatalf("the diagnostic does not name the file that is missing:\n%s", out)
	}
}

func TestImportRejectsAnUppercaseAlias(t *testing.T) {
	s := importReady(t)
	err := s.run(t, "import", writeConfig(t, "Host Prod\n HostName 10.0.0.5\n User ubuntu\n"))
	if err == nil {
		t.Fatal("an uppercase alias was imported")
	}
	if !strings.Contains(s.errOut.String(), "lowercase") {
		t.Fatalf("the diagnostic does not explain the alias rule:\n%s", s.errOut)
	}
}

func TestImportWithKeysAdoptsTheKeysTheConfigNames(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")

	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+key+"\n")

	if err := s.run(t, "import", path); err == nil {
		t.Fatal("import took a host whose key is not in the vault")
	}
	if !strings.Contains(s.errOut.String(), "--with-keys") {
		t.Fatalf("the refusal does not mention the flag that fixes it:\n%s", s.errOut)
	}
	s.errOut.Reset()
	s.out.Reset()

	s.mustRun(t, "import", path, "--with-keys")

	keys, err := s.Env.Client().Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Comment != "laptop@home" {
		t.Fatalf("the key was not adopted: %+v", keys)
	}
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || len(hosts[0].KeyIDs) != 1 || hosts[0].KeyIDs[0] != keys[0].RecordID {
		t.Fatalf("the host does not reference the adopted key: %+v", hosts)
	}
}

func TestImportDryRunPreviewsTheKeysToo(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")
	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+key+"\n")

	s.mustRun(t, "import", path, "--with-keys", "--dry-run")

	out := s.out.String()
	if !strings.Contains(out, "key       SHA256:") {
		t.Fatalf("the preview did not list the key it would import:\n%s", out)
	}
	if !strings.Contains(out, "new       prod") {
		t.Fatalf("the preview did not list the host:\n%s", out)
	}
	keys, err := s.Env.Client().Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("--dry-run imported %d keys", len(keys))
	}
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Fatalf("--dry-run imported %d hosts", len(hosts))
	}
}

func TestImportWithKeysIsIdempotent(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")
	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+key+"\n")

	s.mustRun(t, "import", path, "--with-keys")
	s.out.Reset()
	s.mustRun(t, "import", path, "--with-keys")

	if !strings.Contains(s.out.String(), "unchanged") {
		t.Fatalf("a repeat import was not a no-op:\n%s", s.out)
	}
	keys, err := s.Env.Client().Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("the key was imported %d times", len(keys))
	}
}

func TestImportWarnsTheSourceConfigStillDefinesTheHosts(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")

	if err := os.MkdirAll(filepath.Dir(s.Layout.UserSSHConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile " + key + "\n"
	if err := os.WriteFile(s.Layout.UserSSHConfig, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s.mustRun(t, "import", s.Layout.UserSSHConfig, "--with-keys")

	warned := s.errOut.String()
	if !strings.Contains(warned, "still defined") || !strings.Contains(warned, "prod") {
		t.Fatalf("no warning that the source config still defines the host:\n%s", warned)
	}
	if !strings.Contains(warned, "sshstate doctor") {
		t.Fatalf("the warning does not say how to check:\n%s", warned)
	}
}

func TestImportFromElsewhereDoesNotWarn(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")
	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+key+"\n")

	s.mustRun(t, "import", path, "--with-keys")

	if strings.Contains(s.errOut.String(), "still defined") {
		t.Fatalf("a config that is not the user's own was warned about:\n%s", s.errOut)
	}
}

func TestGeneratedPublicKeysAreNotWorldReadable(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")
	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+key+"\n")
	s.mustRun(t, "import", path, "--with-keys")

	entries, err := os.ReadDir(s.Layout.PublicDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no public key files were generated")
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is mode %04o; OpenSSH will ignore it", e.Name(), info.Mode().Perm())
		}
	}
}

const supersededNote = "superseded by sshstate"

func TestCommentSourceCommentsRatherThanDeletes(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")

	if err := os.MkdirAll(filepath.Dir(s.Layout.UserSSHConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "Host keepme\n HostName 10.0.0.9\n\nHost prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile " + key + "\n\n# a trailing note\n"
	if err := os.WriteFile(s.Layout.UserSSHConfig, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s.mustRun(t, "import", s.Layout.UserSSHConfig, "--with-keys", "--comment-source")

	after, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	text := string(after)
	if strings.Contains(text, "\nHost prod") {
		t.Fatalf("the prod block is still active:\n%s", text)
	}
	if !strings.Contains(text, "# Host prod") {
		t.Fatalf("the prod block was not commented:\n%s", text)
	}
	if !strings.Contains(text, "#  IdentityFile "+key) {
		t.Fatalf("the IdentityFile line survived uncommented:\n%s", text)
	}
	if strings.Count(text, supersededNote) != 2 {
		t.Fatalf("each commented block needs its own explanation:\n%s", text)
	}
	if !strings.Contains(text, "# a trailing note") {
		t.Fatalf("an unrelated comment was lost:\n%s", text)
	}
	if !strings.Contains(text, "# Host keepme") {
		t.Fatalf("keepme was imported but left active, so it still shadows the generated block:\n%s", text)
	}
	if strings.Contains(text, "\nHost keepme") {
		t.Fatalf("keepme is still an active block:\n%s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "#" {
			t.Fatalf("a blank separator line was commented:\n%s", text)
		}
	}

	out := s.out.String()
	if !strings.Contains(out, "Backed up your SSH config to") {
		t.Fatalf("no backup was reported:\n%s", out)
	}
	var backup string
	for _, f := range strings.Fields(out) {
		if strings.Contains(f, "sshstate-backup-") {
			backup = f
		}
	}
	saved, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("the reported backup is not readable: %v", err)
	}
	if string(saved) != body {
		t.Fatal("the backup is not the file as it was")
	}
}

func TestCommentSourceRefusesAConfigThatIsNotYours(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")
	path := writeConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile "+key+"\n")

	err := s.run(t, "import", path, "--with-keys", "--comment-source")
	if err == nil {
		t.Fatal("--comment-source edited a file that is not the user's own config")
	}
	if !strings.Contains(err.Error(), s.Layout.UserSSHConfig) {
		t.Fatalf("the refusal does not name the only file it will edit: %v", err)
	}
}

func TestCommentSourceWritesNothingOnADryRun(t *testing.T) {
	s := importReady(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	writeTestKey(t, key, "laptop@home")
	if err := os.MkdirAll(filepath.Dir(s.Layout.UserSSHConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile " + key + "\n"
	if err := os.WriteFile(s.Layout.UserSSHConfig, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s.mustRun(t, "import", s.Layout.UserSSHConfig, "--with-keys", "--comment-source", "--dry-run")

	after, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != body {
		t.Fatalf("--dry-run edited the config:\n%s", after)
	}
	if !strings.Contains(s.out.String(), "would be commented out") {
		t.Fatalf("the dry run did not say what it would do:\n%s", s.out)
	}
}
