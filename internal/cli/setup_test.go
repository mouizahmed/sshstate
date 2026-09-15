// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func TestSetupRefusesAnExistingVault(t *testing.T) {
	s, _, _ := listReady(t)
	err := s.run(t, "setup", "--kit", filepath.Join(t.TempDir(), "kit.txt"))
	if err == nil {
		t.Fatal("setup ran against a vault that already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unhelpful refusal: %v", err)
	}
}

func TestTrustTakesPositionalIDs(t *testing.T) {
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
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu")

	captureFile := s.Layout.CaptureFile()
	if err := os.MkdirAll(filepath.Dir(captureFile), 0o700); err != nil {
		t.Fatal(err)
	}
	first := hostKeyLine(t)
	second := hostKeyLine(t)
	if err := os.WriteFile(captureFile, []byte("10.0.0.5 "+first+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.mustRun(t, "trust")
	if err := os.WriteFile(captureFile, []byte("10.0.0.5 "+first+"\n10.0.0.5 "+second+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.out.Reset()
	s.mustRun(t, "trust")

	pending := ""
	for _, line := range strings.Split(s.out.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "pending" {
			pending = fields[1]
		}
	}
	if pending == "" {
		t.Fatalf("no pending observation to approve:\n%s", s.out)
	}

	s.out.Reset()
	s.mustRun(t, "trust", pending[:8])
	if !strings.Contains(s.out.String(), "Approved 1") {
		t.Fatalf("a positional prefix did not approve the observation:\n%s", s.out)
	}
	list, err := s.Env.Client().TrustList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list.Entries {
		if e.Status == "pending" {
			t.Fatalf("an observation is still pending: %+v", e)
		}
	}
}

func TestTrustRefusesIDsAndAllTogether(t *testing.T) {
	s, _, _ := listReady(t)
	err := s.run(t, "trust", "abcdef01", "--all")
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestDoctorReportsThroughTheCLI(t *testing.T) {
	s, _, _ := listReady(t)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu")
	s.out.Reset()

	if err := s.run(t, "doctor"); err != nil && !strings.Contains(err.Error(), "problem") {
		t.Fatalf("doctor: %v\n%s", err, s.errOut)
	}
	out := s.out.String()
	if !strings.Contains(out, "ssh config include") {
		t.Fatalf("doctor printed no findings:\n%s", out)
	}
	if !strings.Contains(out, "sshstate install") {
		t.Fatalf("doctor did not say the Include is missing:\n%s", out)
	}
}

func TestDoctorWithoutADaemonSaysHowToStartOne(t *testing.T) {
	s := newScripted(t)
	err := s.run(t, "doctor")
	if err == nil {
		t.Fatal("doctor answered with no daemon")
	}
	if !strings.Contains(err.Error(), "daemon") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestServiceRemoveWhenNotRegistered(t *testing.T) {
	s, _, _ := listReady(t)
	if service.For() == nil {
		t.Skip("no service manager on this platform")
	}
	installed, err := service.For().Installed()
	if err != nil {
		t.Fatal(err)
	}
	if installed {
		t.Skip("sshstate is registered on this machine; this test will not touch it")
	}
	s.out.Reset()
	s.mustRun(t, "service", "--remove")
	if !strings.Contains(s.out.String(), "Not registered") {
		t.Fatalf("unexpected output:\n%s", s.out)
	}
}

func TestServiceRejectsExtraArguments(t *testing.T) {
	s, _, _ := listReady(t)
	if err := s.run(t, "service", "install"); err == nil {
		t.Fatal("a stray argument was accepted")
	}
}

func TestSetupNeedsNoArguments(t *testing.T) {
	s := newScripted(t)
	if err := s.run(t, "setup", "extra"); err == nil {
		t.Fatal("a positional argument was accepted")
	}
}
