// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/paths"
)

func testLayout(t *testing.T) paths.Layout {
	t.Helper()
	root := t.TempDir()
	return paths.Layout{
		Data:          filepath.Join(root, "data"),
		SSH:           filepath.Join(root, "ssh", "sshstate"),
		UserSSHConfig: filepath.Join(root, "ssh", "config"),
		Runtime:       filepath.Join(root, "ssh", "sshstate"),
	}
}

const testPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGojuCT4bZ6NILqlxW/foRBkfl6/+ZhoCElID73mV2mG me@laptop"

func digest(n byte) string { return strings.Repeat(string('a'+n%6), 64) }

func sampleHosts() []Host {
	jump := "bastion"
	return []Host{
		{
			Alias: "prod", HostName: "10.0.0.5", User: "ubuntu", Port: 22,
			ProxyJump:  &jump,
			Identities: []Identity{{Slot: 1, Digest: digest(0), PublicKey: testPub}},
		},
		{
			Alias: "bastion", HostName: "bastion.example.com", User: "admin", Port: 2222,
			Identities: []Identity{
				{Slot: 1, Digest: digest(1), PublicKey: testPub},
				{Slot: 2, Digest: digest(2), PublicKey: testPub},
			},
		},
	}
}

func TestRenderWritesEveryManagedField(t *testing.T) {
	l := testLayout(t)
	out, err := Render(sampleHosts(), l)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Host prod", "HostName 10.0.0.5", "User ubuntu", "Port 22",
		"ProxyJump bastion", "IdentitiesOnly yes", "ForwardAgent no",
		"StrictHostKeyChecking ask", "UpdateHostKeys no",
		"IdentityAgent " + l.AgentSocket(),
		"UserKnownHostsFile " + l.CaptureFile() + " " + l.KnownHosts(),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated config is missing %q", want)
		}
	}
	if !strings.Contains(out, "ProxyJump none") {
		t.Error("a host without a jump host did not write ProxyJump none")
	}
}

func TestRenderIsStableAndSorted(t *testing.T) {
	l := testLayout(t)
	hosts := sampleHosts()
	first, err := Render(hosts, l)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []Host{hosts[1], hosts[0]}
	second, err := Render(reversed, l)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("input order changed the generated config")
	}
	if strings.Index(first, "Host bastion") > strings.Index(first, "Host prod") {
		t.Fatal("hosts are not sorted by alias")
	}
}

func TestRenderPreservesIdentityOrder(t *testing.T) {
	l := testLayout(t)
	out, err := Render(sampleHosts(), l)
	if err != nil {
		t.Fatal(err)
	}
	one := strings.Index(out, "bastion-01-")
	two := strings.Index(out, "bastion-02-")
	if one < 0 || two < 0 || one > two {
		t.Fatalf("identity order lost: slot1 at %d, slot2 at %d", one, two)
	}
}

func TestPublicFileNameCarriesFullDigest(t *testing.T) {
	h := sampleHosts()[0]
	name := h.PublicFileName(h.Identities[0])
	if !strings.HasPrefix(name, "prod-01-") || !strings.HasSuffix(name, ".pub") {
		t.Fatalf("unexpected filename %q", name)
	}
	if len(name) != len("prod-01-")+64+len(".pub") {
		t.Fatalf("filename %q does not carry the full 64-character digest", name)
	}
}

func TestRenderRejectsUnrenderableHosts(t *testing.T) {
	l := testLayout(t)
	bad := map[string]Host{
		"newline in hostname": {Alias: "a", HostName: "x\nProxyCommand id", User: "u", Port: 22},
		"empty user":          {Alias: "a", HostName: "x", User: "", Port: 22},
		"port zero":           {Alias: "a", HostName: "x", User: "u", Port: 0},
		"short digest":        {Alias: "a", HostName: "x", User: "u", Port: 22, Identities: []Identity{{Slot: 1, Digest: "abc"}}},
		"slot zero":           {Alias: "a", HostName: "x", User: "u", Port: 22, Identities: []Identity{{Slot: 0, Digest: digest(0)}}},
		"duplicate slot": {Alias: "a", HostName: "x", User: "u", Port: 22, Identities: []Identity{
			{Slot: 1, Digest: digest(0)}, {Slot: 1, Digest: digest(1)},
		}},
	}
	for name, h := range bad {
		if _, err := Render([]Host{h}, l); err == nil {
			t.Errorf("%s: rendered an invalid host", name)
		}
	}
}

func TestPublishWritesKeysBeforeConfig(t *testing.T) {
	l := testLayout(t)
	hosts := sampleHosts()
	if err := Publish(hosts, l); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(l.Config())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		for _, id := range h.Identities {
			path := filepath.Join(l.PublicDir(), h.PublicFileName(id))
			if _, err := os.Stat(path); err != nil {
				t.Errorf("config references a missing file: %v", err)
			}
			if !strings.Contains(string(body), path) {
				t.Errorf("config does not reference %s", filepath.Base(path))
			}
		}
	}
	fi, err := os.Stat(l.Config())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("generated config mode is %o", fi.Mode().Perm())
	}
}

func TestObsoletePublicFilesFindsStaleKeys(t *testing.T) {
	l := testLayout(t)
	hosts := sampleHosts()
	if err := Publish(hosts, l); err != nil {
		t.Fatal(err)
	}
	old := hosts[0].PublicFileName(hosts[0].Identities[0])
	hosts[0].Identities[0].Digest = digest(5)
	if err := Publish(hosts, l); err != nil {
		t.Fatal(err)
	}
	stale, err := ObsoletePublicFiles(hosts, l)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || filepath.Base(stale[0]) != old {
		t.Fatalf("stale set is %v, expected only %s", stale, old)
	}
	if _, err := os.Stat(stale[0]); err != nil {
		t.Fatal("the obsolete file was removed; an in-flight reader would break")
	}
}

func TestInstallAddsMarkedIncludeAtTop(t *testing.T) {
	l := testLayout(t)
	existing := "Host legacy\n    HostName old.example.com\n"
	if err := os.MkdirAll(filepath.Dir(l.UserSSHConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.UserSSHConfig, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Install(l)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.BackupPath == "" {
		t.Fatalf("install reported %+v; a backup is required before an edit", res)
	}
	body, err := os.ReadFile(l.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.HasPrefix(got, MarkerBegin) {
		t.Fatal("the managed block is not at the top; OpenSSH takes the first value")
	}
	if !strings.Contains(got, "Include "+l.Config()) {
		t.Fatal("the Include line is missing")
	}
	if !strings.Contains(got, existing) {
		t.Fatal("existing configuration was not preserved byte for byte")
	}
	backup, err := os.ReadFile(res.BackupPath)
	if err != nil || string(backup) != existing {
		t.Fatalf("backup does not hold the original: %v", err)
	}

	again, err := Install(l)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed {
		t.Fatal("a second install modified the file")
	}
	if strings.Count(string(mustRead(t, l.UserSSHConfig)), MarkerBegin) != 1 {
		t.Fatal("a second block was added")
	}
}

func TestUninstallRemovesOnlyTheManagedBlock(t *testing.T) {
	l := testLayout(t)
	existing := "Include ~/.ssh/other-config\nHost legacy\n    HostName old.example.com\n"
	if err := os.MkdirAll(filepath.Dir(l.UserSSHConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.UserSSHConfig, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(l); err != nil {
		t.Fatal(err)
	}
	if ok, _ := IsInstalled(l); !ok {
		t.Fatal("IsInstalled did not see the block")
	}
	if _, err := Uninstall(l); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, l.UserSSHConfig))
	if got != existing {
		t.Fatalf("uninstall did not restore the file exactly:\n%q\nwant\n%q", got, existing)
	}
	if ok, _ := IsInstalled(l); ok {
		t.Fatal("the block is still present")
	}
}

func TestInstallRefusesSymlink(t *testing.T) {
	l := testLayout(t)
	dir := filepath.Dir(l.UserSSHConfig)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("Host x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, l.UserSSHConfig); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Install(l); err == nil {
		t.Fatal("installed through a symlink")
	}
	if body := string(mustRead(t, target)); body != "Host x\n" {
		t.Fatal("the symlink target was modified")
	}
}

func TestInstallCreatesConfigWhenAbsent(t *testing.T) {
	l := testLayout(t)
	res, err := Install(l)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.BackupPath != "" {
		t.Fatalf("creating a new file should need no backup: %+v", res)
	}
	body := string(mustRead(t, l.UserSSHConfig))
	if !strings.HasPrefix(body, MarkerBegin) || !strings.Contains(body, MarkerEnd) {
		t.Fatalf("unexpected new config:\n%s", body)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestBackupsTakenInTheSameSecondKeepEveryVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	versions := []string{"Host original\n", "Host second\n", "Host third\n"}
	seen := map[string]bool{}
	for _, body := range versions {
		backup, err := backupUserConfig(path, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if seen[backup] {
			t.Fatalf("%s was reused for a later backup", backup)
		}
		seen[backup] = true
	}
	matches, err := filepath.Glob(path + ".sshstate-backup-*")
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, m := range matches {
		body, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		kept[string(body)] = true
	}
	for _, body := range versions {
		if !kept[body] {
			t.Fatalf("the backup holding %q was overwritten; kept %v", body, kept)
		}
	}
}
