// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mouizahmed/sshstate/internal/vault"
)

func hostKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func installReady(t *testing.T, knownHosts string) *scripted {
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
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu")

	if knownHosts != "" {
		if err := os.MkdirAll(filepath.Dir(s.Layout.UserKnownHosts()), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.Layout.UserKnownHosts(), []byte(knownHosts), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.out.Reset()
	s.errOut.Reset()
	return s
}

func TestInstallRequiresATrustDecisionWhenNotInteractive(t *testing.T) {
	s := installReady(t, "10.0.0.5 "+hostKeyLine(t)+"\n")
	err := s.run(t, "install")
	if err == nil {
		t.Fatal("install proceeded without a trust decision")
	}
	for _, want := range []string{"--import-trust", "--skip-trust"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
	if _, statErr := os.Stat(s.Layout.UserSSHConfig); !os.IsNotExist(statErr) {
		t.Fatalf("the Include was written despite the refusal: %v", statErr)
	}
}

func TestInstallImportsReviewedTrust(t *testing.T) {
	key := hostKeyLine(t)
	s := installReady(t, "10.0.0.5 "+key+"\nunmanaged.example.com "+hostKeyLine(t)+"\n")
	s.mustRun(t, "install", "--import-trust")

	out := s.out.String()
	if !strings.Contains(out, "prod") || !strings.Contains(out, "SHA256:") {
		t.Fatalf("the preview did not show the entry and its fingerprint:\n%s", out)
	}
	generated, err := os.ReadFile(s.Layout.KnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(generated), key) {
		t.Fatalf("the imported key is not in the generated trust file:\n%s", generated)
	}
	userConfig, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(userConfig), "BEGIN sshstate managed include") {
		t.Fatal("the Include was not activated after a successful import")
	}
}

func TestInstallSkipTrustExplainsTheConsequence(t *testing.T) {
	key := hostKeyLine(t)
	s := installReady(t, "10.0.0.5 "+key+"\n")
	s.mustRun(t, "install", "--skip-trust")

	generated, err := os.ReadFile(s.Layout.KnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(generated), key) {
		t.Fatal("--skip-trust imported the entry anyway")
	}
	if !strings.Contains(s.errOut.String(), "prompted") {
		t.Fatalf("skipping did not explain the consequence:\n%s", s.errOut)
	}
	if _, err := os.Stat(s.Layout.UserSSHConfig); err != nil {
		t.Fatalf("--skip-trust did not activate the Include: %v", err)
	}
}

func TestInstallCancelChangesNothing(t *testing.T) {
	s := installReady(t, "10.0.0.5 "+hostKeyLine(t)+"\n")
	s.Interactive = true
	s.lines = []string{"c"}
	err := s.run(t, "install")
	if err == nil {
		t.Fatal("cancel was treated as success")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(s.Layout.UserSSHConfig); !os.IsNotExist(statErr) {
		t.Fatal("cancelling still wrote the Include")
	}
}

func TestInstallInteractiveImport(t *testing.T) {
	key := hostKeyLine(t)
	s := installReady(t, "10.0.0.5 "+key+"\n")
	s.Interactive = true
	s.lines = []string{"i"}
	s.mustRun(t, "install")
	generated, err := os.ReadFile(s.Layout.KnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(generated), key) {
		t.Fatal("answering 'i' did not import the entry")
	}
}

func TestInstallWithNoExistingTrustNeedsNoDecision(t *testing.T) {
	s := installReady(t, "")
	s.mustRun(t, "install")
	if _, err := os.Stat(s.Layout.UserSSHConfig); err != nil {
		t.Fatalf("install did not activate the Include: %v", err)
	}
}
