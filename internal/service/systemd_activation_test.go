// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package service_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/paths"
	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func TestSystemdSocketActivation(t *testing.T) {
	if os.Getenv("SSHSTATE_SYSTEMD_TEST") != "1" {
		t.Skip("set SSHSTATE_SYSTEMD_TEST=1 to register real systemd user units")
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		t.Skip("no systemd user session ($XDG_RUNTIME_DIR is unset)")
	}

	root, err := os.MkdirTemp("/tmp", "sssl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	layout := paths.Layout{
		Data:          root + "/data",
		SSH:           root + "/ssh",
		UserSSHConfig: root + "/ssh/config",
		Runtime:       root,
	}

	store, err := vault.OpenStore(layout.Database())
	if err != nil {
		t.Fatal(err)
	}
	mgr, kit, err := vault.Init(store, vault.InitOptions{Password: []byte("pw"), DeviceLabel: "systemd-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.ConfirmRecoveryKit(kit.Checksum(), kit); err != nil {
		t.Fatal(err)
	}
	vaultID := string(mgr.VaultID())
	store.Close()

	binary := root + "/sshstate"
	build := exec.Command("go", "build", "-o", binary, "github.com/mouizahmed/sshstate/cmd/sshstate")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build the daemon binary: %v", err)
	}

	units, err := service.RenderUnits(binary, layout)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for name := range units {
		names[name] = strings.Replace(name, "sshstate", "sshstate-selftest", 1)
	}
	var socketUnits, written []string
	for name, body := range units {
		for from, to := range names {
			body = strings.ReplaceAll(body, from, to)
		}
		path := filepath.Join(dir, names[name])
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		written = append(written, path)
		if strings.HasSuffix(names[name], ".socket") {
			socketUnits = append(socketUnits, names[name])
		}
	}
	t.Cleanup(func() {
		for _, p := range written {
			os.Remove(p)
		}
	})

	systemctl := func(args ...string) (string, error) {
		out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if out, err := systemctl("daemon-reload"); err != nil {
		t.Fatalf("daemon-reload: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_, _ = systemctl(append([]string{"stop"}, socketUnits...)...)
		_, _ = systemctl("stop", names["sshstate.service"])
	})
	if _, err := exec.LookPath("systemd-analyze"); err == nil {
		for _, p := range written {
			out, err := exec.Command("systemd-analyze", "--user", "verify", p).CombinedOutput()
			if err != nil || len(out) > 0 {
				t.Fatalf("systemd-analyze verify %s: %v\n%s", filepath.Base(p), err, out)
			}
		}
	}
	if out, err := systemctl(append([]string{"start"}, socketUnits...)...); err != nil {
		t.Fatalf("start the socket units: %v: %s", err, out)
	}

	if out, _ := systemctl("is-active", names["sshstate.service"]); out == "active" {
		t.Fatal("the daemon was already running before activation")
	}
	before, err := os.Stat(layout.ControlSocket())
	if err != nil {
		t.Fatalf("systemd did not create the control socket: %v", err)
	}

	client := control.NewClient(layout.ControlSocket())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var st *control.StatusResponse
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err = client.Status(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			out, _ := systemctl("status", "--no-pager", names["sshstate.service"])
			t.Fatalf("the activated daemon never answered: %v\n%s", err, out)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if out, _ := systemctl("is-active", names["sshstate.service"]); out != "active" {
		t.Fatalf("status succeeded but the unit is %q", out)
	}
	after, err := os.Stat(layout.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("the daemon replaced systemd's socket instead of adopting it")
	}
	agentBefore, err := os.Stat(layout.AgentSocket())
	if err != nil {
		t.Fatalf("systemd did not create the agent socket: %v", err)
	}
	if err := exec.Command("env", "SSH_AUTH_SOCK="+layout.AgentSocket(), "ssh-add", "-l").Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			t.Fatalf("the agent socket is not serving the agent protocol: %v", err)
		}
	}
	agentAfter, err := os.Stat(layout.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(agentBefore, agentAfter) {
		t.Fatal("the daemon replaced systemd's agent socket instead of adopting it")
	}

	if st.VaultID != vaultID {
		t.Fatalf("the activated daemon serves vault %s, expected %s", st.VaultID, vaultID)
	}
	if st.Unlocked {
		t.Fatal("the activated daemon came up unlocked")
	}
	if _, err := client.Unlock(ctx, "pw"); err != nil {
		t.Fatalf("unlock through the activated daemon: %v", err)
	}
	if _, err := client.Lock(ctx); err != nil {
		t.Fatal(err)
	}
}
