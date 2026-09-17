// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mouizahmed/sshstate/internal/paths"
)

func TestSystemdInstalledOnlyForTheHomeItWasRegisteredFor(t *testing.T) {
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	home := t.TempDir()
	mine := paths.Layout{Data: home + "/data", SSH: home + "/ssh", Runtime: home + "/ssh", UserSSHConfig: home + "/config"}
	other := paths.Layout{Data: home + "/other/data", SSH: home + "/other/ssh", Runtime: home + "/other/ssh", UserSSHConfig: home + "/other/config"}
	s := systemd{}

	if registered, err := s.Registered(); err != nil || registered {
		t.Fatalf("no units, yet registered: %v %v", registered, err)
	}
	units, err := RenderUnits("/bin/sshstate", other)
	if err != nil {
		t.Fatal(err)
	}
	dir := unitDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range units {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if registered, err := s.Registered(); err != nil || !registered {
		t.Fatalf("existing units are not reported as registered: %v %v", registered, err)
	}
	if installed, err := s.Installed(mine); err != nil || installed {
		t.Fatalf("units for another home were taken as this home's service: %v %v", installed, err)
	}
	if installed, err := s.Installed(other); err != nil || !installed {
		t.Fatalf("the units are not recognised for the home they name: %v %v", installed, err)
	}
}
