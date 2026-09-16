// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/control"

	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func TestSetupOnAFinishedMachineSaysSoAndChangesNothing(t *testing.T) {
	s, firstID, _ := listReady(t)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", firstID)
	s.mustRun(t, "install", "--skip-trust")
	before, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	s.out.Reset()

	s.mustRun(t, "setup")

	if !strings.Contains(s.out.String(), "already set up") {
		t.Fatalf("a finished machine was not reported as finished:\n%s", s.out)
	}
	after, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("setup on a finished machine rewrote the SSH config")
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
	if !strings.Contains(out, "Include is not installed") || !strings.Contains(out, "sshstate setup") {
		t.Fatalf("doctor did not say the Include is missing and how to finish:\n%s", out)
	}
}

func TestDoctorOnAFreshMachinePointsAtSetup(t *testing.T) {
	s := newScripted(t)
	err := s.run(t, "doctor")
	if err == nil {
		t.Fatal("doctor answered with no vault")
	}
	if !strings.Contains(err.Error(), "sshstate setup") {
		t.Fatalf("doctor on a fresh machine does not point at setup: %v", err)
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

func TestIsLockedMatchesOnlyTheLockedCode(t *testing.T) {
	if !isLocked(&control.APIError{Code: control.CodeLocked}) {
		t.Fatal("a locked API error was not recognised")
	}
	if isLocked(&control.APIError{Code: control.CodeBadRequest}) {
		t.Fatal("an unrelated code was treated as locked")
	}
	if isLocked(errors.New("plain")) {
		t.Fatal("a plain error was treated as locked")
	}
	if isLocked(fmt.Errorf("wrapped: %w", &control.APIError{Code: control.CodeLocked})) != true {
		t.Fatal("a wrapped locked error was not recognised")
	}
}

func TestReadLineTakesALineFromStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })

	if _, err := w.WriteString("  yes  \r\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	got, err := readLine("prompt: ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "  yes  " {
		t.Fatalf("readLine returned %q; it must strip the terminator and nothing else", got)
	}
}

func TestDefaultEnvResolvesFromTheEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")

	env, err := DefaultEnv()
	if err != nil {
		t.Fatal(err)
	}
	if env.Layout.Data == "" || env.Layout.SSH == "" {
		t.Fatalf("the layout is empty: %+v", env.Layout)
	}
	if !strings.HasPrefix(env.Layout.SSH, home) {
		t.Fatalf("the ssh directory %s is not under HOME %s", env.Layout.SSH, home)
	}
	if env.Stdout == nil || env.Stderr == nil {
		t.Fatal("DefaultEnv left a nil stream")
	}
	if env.ReadSecret == nil || env.ReadLine == nil {
		t.Fatal("DefaultEnv left a nil prompt")
	}
	if env.Client() == nil {
		t.Fatal("DefaultEnv produced an env with no control client")
	}
}

func TestSameFileRecognisesTheUsersOwnConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sameFile(p, p) {
		t.Fatal("a path does not match itself")
	}
	if !sameFile(filepath.Join(dir, ".", "config"), p) {
		t.Fatal("an equivalent path did not match")
	}
	if sameFile(p, filepath.Join(dir, "other")) {
		t.Fatal("two different paths matched")
	}
}

func vaultOnly(t *testing.T) *scripted {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
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
	s.out.Reset()
	s.errOut.Reset()
	return s
}

func TestAVaultWithNoDaemonPointsAtSetupNotTheDaemon(t *testing.T) {
	if service.For() == nil {
		t.Skip("no service manager here, so the daemon is the right advice")
	}
	s := vaultOnly(t)
	err := s.run(t, "status")
	if err == nil {
		t.Fatal("status answered with no daemon")
	}
	if !strings.Contains(err.Error(), "sshstate setup") {
		t.Fatalf("a half-set-up machine is not pointed at setup: %v", err)
	}
	if strings.Contains(err.Error(), "sshstate daemon") {
		t.Fatalf("a half-set-up machine is told to run a foreground daemon: %v", err)
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Fatalf("the message does not distinguish this from a machine with no vault: %v", err)
	}

	fresh := newScripted(t)
	freshErr := fresh.run(t, "status")
	if freshErr == nil || freshErr.Error() == err.Error() {
		t.Fatalf("no vault and a vault with no daemon read identically: %v", freshErr)
	}
}

func TestSetupResumesAMachineThatStoppedAfterTheVault(t *testing.T) {
	s := vaultOnly(t)
	s.startDaemon(t)
	s.secrets = []string{password}

	s.mustRun(t, "setup")

	out := s.out.String()
	for _, want := range []string{"already done: vault", "already done: the daemon is running", "No hosts yet"} {
		if !strings.Contains(out, want) {
			t.Fatalf("resuming setup did not report %q:\n%s", want, out)
		}
	}
	st, err := s.Env.Client().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unlocked {
		t.Fatal("setup resumed but did not unlock")
	}
}

func TestSetupFinishesOnceTheresSomethingToManage(t *testing.T) {
	s := vaultOnly(t)
	s.startDaemon(t)
	s.secrets = []string{password}
	s.mustRun(t, "setup")

	key := filepath.Join(t.TempDir(), "id")
	writeTestKey(t, key, "laptop@home")
	s.mustRun(t, "add-key", key)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", "laptop@home")
	s.out.Reset()

	s.lines = []string{"s"}
	s.mustRun(t, "setup")
	if !strings.Contains(s.out.String(), "Done") {
		t.Fatalf("setup did not finish once a host existed:\n%s", s.out)
	}
	installed, err := sshconfig.IsInstalled(s.Layout)
	if err != nil || !installed {
		t.Fatalf("the Include is not active after setup finished: %v", err)
	}

	s.out.Reset()
	s.mustRun(t, "setup")
	if !strings.Contains(s.out.String(), "already set up") {
		t.Fatalf("a third run did not recognise a finished machine:\n%s", s.out)
	}
}

func TestSetupImportIsSafeToRunTwice(t *testing.T) {
	s := vaultOnly(t)
	s.startDaemon(t)
	key := filepath.Join(t.TempDir(), "id")
	writeTestKey(t, key, "laptop@home")
	if err := os.MkdirAll(filepath.Dir(s.Layout.UserSSHConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile " + key + "\n"
	if err := os.WriteFile(s.Layout.UserSSHConfig, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s.secrets = []string{password}
	s.lines = []string{"s"}

	s.mustRun(t, "setup", "--import", s.Layout.UserSSHConfig)
	first, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "# Host prod") {
		t.Fatalf("setup left the imported block active:\n%s", first)
	}

	s.out.Reset()
	s.mustRun(t, "setup", "--import", s.Layout.UserSSHConfig)
	out := s.out.String()
	if !strings.Contains(out, "no hosts left to import") || !strings.Contains(out, "already set up") {
		t.Fatalf("a second setup --import did not recognise the finished state:\n%s", out)
	}
	second, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("a second setup --import changed the config:\n%s", second)
	}
}

func TestStatusOnAnUnfinishedMachineSaysSetupNotInstall(t *testing.T) {
	s := vaultOnly(t)
	s.startDaemon(t)
	s.mustRun(t, "status")
	out := s.out.String()
	if !strings.Contains(out, "Next: sshstate setup") {
		t.Fatalf("an unfinished machine is not pointed at setup:\n%s", out)
	}
	if strings.Contains(out, "sshstate install") {
		t.Fatalf("status suggests install, which fails while the vault is locked:\n%s", out)
	}
}

func TestStatusOnAFinishedLockedMachineSaysUnlock(t *testing.T) {
	s, firstID, _ := listReady(t)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", firstID)
	s.mustRun(t, "install", "--skip-trust")
	s.mustRun(t, "lock")
	s.out.Reset()

	s.mustRun(t, "status")
	out := s.out.String()
	if !strings.Contains(out, "Next: sshstate unlock") {
		t.Fatalf("a finished, locked machine is not told to unlock:\n%s", out)
	}
	if strings.Contains(out, "sshstate setup") {
		t.Fatalf("a finished machine is sent back to setup:\n%s", out)
	}
	if strings.Contains(out, "key epoch") {
		t.Fatalf("status still shows internal epoch numbers:\n%s", out)
	}
}

func TestUnlockDoesNotAskForAPasswordItCannotUse(t *testing.T) {
	s := newScripted(t)
	s.secrets = []string{password}
	if err := s.run(t, "unlock"); err == nil {
		t.Fatal("unlock succeeded with no daemon")
	}
	if len(s.secrets) != 1 {
		t.Fatal("unlock read the password before finding out there was no daemon to give it to")
	}
}

func TestUnlockOnAnUnlockedVaultDoesNotAsk(t *testing.T) {
	s, _, _ := listReady(t)
	s.secrets = []string{password}
	s.mustRun(t, "unlock")
	if len(s.secrets) != 1 {
		t.Fatal("unlock asked for a password the vault did not need")
	}
	if !strings.Contains(s.out.String(), "Already unlocked") {
		t.Fatalf("unlock did not say the vault was already unlocked:\n%s", s.out)
	}
}

func TestDoctorDoesNotCallANonfunctionalMachineHealthy(t *testing.T) {
	s, _, _ := listReady(t)
	s.mustRun(t, "doctor")
	out := s.out.String()
	if strings.Contains(out, "No problems found.") {
		t.Fatalf("doctor reported no problems while the Include is not installed:\n%s", out)
	}
	if !strings.Contains(out, "warning") {
		t.Fatalf("doctor's summary does not mention its warnings:\n%s", out)
	}
}

func setupWithConfig(t *testing.T, body string) (*scripted, string) {
	t.Helper()
	s := vaultOnly(t)
	s.startDaemon(t)
	key := filepath.Join(t.TempDir(), "id")
	writeTestKey(t, key, "laptop@home")
	writeUserConfig(t, s, strings.ReplaceAll(body, "KEY", key))
	return s, key
}

func TestSetupCancelledAtTheTrustPromptLeavesYourHostsWorking(t *testing.T) {
	s, _ := setupWithConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile KEY\n")
	if err := os.WriteFile(s.Layout.UserKnownHosts(), []byte("10.0.0.5 "+hostKeyLine(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, s.Layout.UserSSHConfig)
	s.Interactive = true
	s.secrets = []string{password}
	s.lines = []string{"c"}

	if err := s.run(t, "setup", "--import", s.Layout.UserSSHConfig); err == nil {
		t.Fatal("setup reported success after the trust prompt was cancelled")
	}
	if got := readFile(t, s.Layout.UserSSHConfig); got != before {
		t.Fatalf("a cancelled setup changed the config, so prod may no longer resolve:\n%s", got)
	}

	s.lines = []string{"s"}
	s.errOut.Reset()
	s.mustRun(t, "setup", "--import", s.Layout.UserSSHConfig)
	text := readFile(t, s.Layout.UserSSHConfig)
	installed, err := sshconfig.IsInstalled(s.Layout)
	if err != nil || !installed {
		t.Fatalf("setup run again did not activate the Include: %v", err)
	}
	if !strings.Contains(text, "# Host prod") {
		t.Fatalf("setup run again did not retire the imported block:\n%s", text)
	}
	if strings.Contains(s.errOut.String(), "still defined") {
		t.Fatalf("setup warned about a block it was about to retire:\n%s", s.errOut)
	}
}

func TestSetupStopsOnAConflictWithoutTouchingTheConfig(t *testing.T) {
	s, key := setupWithConfig(t, "")
	s.secrets = []string{password}
	s.mustRun(t, "setup")
	s.mustRun(t, "add-key", key)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.9", "--user", "ubuntu", "--key", "laptop@home")
	body := "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile " + key + "\n"
	writeUserConfig(t, s, body)
	s.out.Reset()

	err := s.run(t, "setup", "--import", s.Layout.UserSSHConfig)
	if err == nil {
		t.Fatal("setup finished while prod was still in conflict")
	}
	if got := readFile(t, s.Layout.UserSSHConfig); got != body {
		t.Fatalf("setup changed the config while prod was in conflict:\n%s", got)
	}
	if !strings.Contains(s.out.String(), "sshstate conflicts") {
		t.Fatalf("setup did not say how to resolve the conflict:\n%s", s.out)
	}

	listed, err := s.Client().Conflicts(context.Background())
	if err != nil || len(listed.Conflicts) != 1 {
		t.Fatalf("expected one conflict to resolve: %v %+v", err, listed)
	}
	s.mustRun(t, "resolve", listed.Conflicts[0].RecordID)
	s.mustRun(t, "setup", "--import", s.Layout.UserSSHConfig)
	if !strings.Contains(readFile(t, s.Layout.UserSSHConfig), "# Host prod") {
		t.Fatal("setup did not finish after the conflict was resolved")
	}
}

func TestSetupImportThroughASymlinkFinishes(t *testing.T) {
	s, _ := setupWithConfig(t, "Host prod\n HostName 10.0.0.5\n User ubuntu\n IdentityFile KEY\n")
	link := filepath.Join(t.TempDir(), "config")
	if err := os.Symlink(s.Layout.UserSSHConfig, link); err != nil {
		t.Fatal(err)
	}
	s.secrets = []string{password}
	s.lines = []string{"s"}

	s.mustRun(t, "setup", "--import", link)

	if !strings.Contains(readFile(t, s.Layout.UserSSHConfig), "# Host prod") {
		t.Fatal("setup through a symlink did not retire the imported block")
	}
}
