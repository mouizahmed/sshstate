// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package paths

import (
	"path/filepath"
	"testing"
)

func TestDefaultResolvesFromTheEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")

	l, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if l.Data != filepath.Join(home, ".local", "share", "sshstate") {
		t.Fatalf("data is %s", l.Data)
	}
	if l.SSH != filepath.Join(home, ".ssh", "sshstate") {
		t.Fatalf("ssh dir is %s", l.SSH)
	}
	if l.UserSSHConfig != filepath.Join(home, ".ssh", "config") {
		t.Fatalf("user config is %s", l.UserSSHConfig)
	}
	if l.Runtime != l.SSH {
		t.Fatalf("runtime %s is not the generated directory; the generated config names the agent socket by path", l.Runtime)
	}
}

func TestXDGDataHomeIsHonoured(t *testing.T) {
	home := t.TempDir()
	data := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", data)

	l, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if l.Data != filepath.Join(data, "sshstate") {
		t.Fatalf("data is %s, expected it under XDG_DATA_HOME", l.Data)
	}
	if l.SSH != filepath.Join(home, ".ssh", "sshstate") {
		t.Fatalf("XDG_DATA_HOME moved the SSH directory to %s", l.SSH)
	}
}

func TestDerivedPathsHangOffTheLayout(t *testing.T) {
	l := Layout{Data: "/d", SSH: "/s", UserSSHConfig: "/u/config", Runtime: "/r"}
	for name, got := range map[string]string{
		"Database":       l.Database(),
		"Config":         l.Config(),
		"PublicDir":      l.PublicDir(),
		"KnownHosts":     l.KnownHosts(),
		"UserKnownHosts": l.UserKnownHosts(),
		"CaptureFile":    l.CaptureFile(),
		"AgentSocket":    l.AgentSocket(),
		"ControlSocket":  l.ControlSocket(),
		"DaemonLock":     l.DaemonLock(),
	} {
		if got == "" {
			t.Errorf("%s is empty", name)
		}
	}
	if l.AgentSocket() == l.ControlSocket() {
		t.Fatal("the agent and control sockets are the same file; §3.3 keeps them separate")
	}
	if l.CaptureFile() == l.KnownHosts() {
		t.Fatal("the capture file and the generated trust file are the same path")
	}
}
