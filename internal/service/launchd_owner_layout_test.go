// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mouizahmed/sshstate/internal/paths"
)

func TestLaunchdInstalledOnlyForTheHomeItWasRegisteredFor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mine := paths.Layout{Data: home + "/data", SSH: home + "/ssh", Runtime: home + "/ssh", UserSSHConfig: home + "/config"}
	other := paths.Layout{Data: home + "/other/data", SSH: home + "/other/ssh", Runtime: home + "/other/ssh", UserSSHConfig: home + "/other/config"}
	d := launchd{}

	if registered, err := d.Registered(); err != nil || registered {
		t.Fatalf("a home with no plist reports registered: %v %v", registered, err)
	}
	body, err := RenderPlist("/bin/sshstate", other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(d.DefinitionPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.DefinitionPath(), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if registered, err := d.Registered(); err != nil || !registered {
		t.Fatalf("an existing plist is not reported as registered: %v %v", registered, err)
	}
	if installed, err := d.Installed(mine); err != nil || installed {
		t.Fatalf("a plist for another home was taken as this home's service: %v %v", installed, err)
	}
	if installed, err := d.Installed(other); err != nil || !installed {
		t.Fatalf("the plist is not recognised for the home it names: %v %v", installed, err)
	}
}
