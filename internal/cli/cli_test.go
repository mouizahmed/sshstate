// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mouizahmed/sshstate/internal/paths"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const password = "correct horse battery staple"

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

type scripted struct {
	*Env
	out, errOut *syncBuffer
	secrets     []string
	lines       []string
	answer      func(prompt string) (string, error)
}

func newScripted(t *testing.T) *scripted {
	t.Helper()
	root := t.TempDir()
	runtime, err := os.MkdirTemp("", "ssc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runtime) })

	s := &scripted{out: &syncBuffer{}, errOut: &syncBuffer{}}
	s.Env = &Env{
		Layout: paths.Layout{
			Data:          filepath.Join(root, "data"),
			SSH:           filepath.Join(root, "ssh", "sshstate"),
			UserSSHConfig: filepath.Join(root, "ssh", "config"),
			Runtime:       runtime,
		},
		Stdout: s.out,
		Stderr: s.errOut,
		ReadSecret: func(string) ([]byte, error) {
			if len(s.secrets) == 0 {
				return nil, errors.New("no scripted secret available")
			}
			next := s.secrets[0]
			s.secrets = s.secrets[1:]
			return []byte(next), nil
		},
		ReadLine: func(prompt string) (string, error) {
			if s.answer != nil {
				return s.answer(prompt)
			}
			if len(s.lines) == 0 {
				return "", errors.New("no scripted line available")
			}
			next := s.lines[0]
			s.lines = s.lines[1:]
			return next, nil
		},
	}
	return s
}

func (s *scripted) run(t *testing.T, name string, args ...string) error {
	t.Helper()
	for _, c := range Commands() {
		if c.Name == name {
			return c.Run(context.Background(), s.Env, args)
		}
	}
	t.Fatalf("no such command %q", name)
	return nil
}

func (s *scripted) mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if err := s.run(t, name, args...); err != nil {
		t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", name, err, s.out, s.errOut)
	}
}

func (s *scripted) startDaemon(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	exited := make(chan error, 1)
	go func() {
		defer wg.Done()
		err := s.run(t, "daemon")
		exited <- err
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("daemon: %v", err)
		}
	}()
	_ = ctx
	t.Cleanup(func() {
		_ = s.Env.Client().Shutdown(context.Background())
		cancel()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("daemon did not stop")
		}
	})

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			t.Fatalf("the daemon exited instead of listening: %v", err)
		default:
		}
		if conn, err := net.Dial("unix", s.Layout.ControlSocket()); err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon did not start")
}

func TestInitWritesAndConfirmsRecoveryKit(t *testing.T) {
	s := newScripted(t)
	kitPath := filepath.Join(t.TempDir(), "kit.txt")
	s.secrets = []string{password, password}
	s.answer = func(string) (string, error) {
		body, err := os.ReadFile(kitPath)
		if err != nil {
			return "", err
		}
		kit, err := vault.ParseKit(string(body))
		if err != nil {
			return "", err
		}
		return kit.Checksum(), nil
	}

	s.mustRun(t, "init", "--kit", kitPath)

	fi, err := os.Stat(kitPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("recovery kit is mode %04o", got)
	}
	body, err := os.ReadFile(kitPath)
	if err != nil {
		t.Fatal(err)
	}
	kit, err := vault.ParseKit(string(body))
	if err != nil {
		t.Fatalf("the written kit does not parse: %v", err)
	}
	if kit.EncryptionIdentity == "" || len(kit.SigningSeed) == 0 {
		t.Fatal("the kit is missing one of its two key roles")
	}
	if strings.Contains(s.out.String(), kit.EncryptionIdentity) {
		t.Fatal("the recovery identity was printed despite --kit")
	}
}

func TestInitRefusesWithoutKitConfirmation(t *testing.T) {
	s := newScripted(t)
	s.secrets = []string{password, password}
	s.lines = []string{"WRONGVALUE", "STILLWRONG", "NOPENOPE00"}
	err := s.run(t, "init", "--kit", filepath.Join(t.TempDir(), "kit.txt"))
	if err == nil {
		t.Fatal("init completed without confirming the recovery kit")
	}
	if !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitRejectsMismatchedPasswords(t *testing.T) {
	s := newScripted(t)
	s.secrets = []string{password, "something else"}
	if err := s.run(t, "init"); err == nil {
		t.Fatal("init accepted two different passwords")
	}
}

func TestLocalWorkflow(t *testing.T) {
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

	err := s.run(t, "add", "prod", "--hostname", "10.0.0.5")
	if err == nil {
		t.Fatal("added a host to a locked vault")
	}
	if !strings.Contains(err.Error(), "sshstate unlock") {
		t.Fatalf("the locked error does not say what to do: %v", err)
	}

	s.secrets = []string{password}
	s.mustRun(t, "unlock")

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath, "me@laptop")
	s.out.Reset()
	s.mustRun(t, "add-key", keyPath)
	out := s.out.String()
	if !strings.Contains(out, "SHA256:") {
		t.Fatalf("add-key did not report a fingerprint:\n%s", out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("add-key printed private key material")
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("add-key disturbed the source key: %v", err)
	}
	recordID := extractRecordID(t, out)

	s.out.Reset()
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", recordID)

	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatalf("no generated config: %v", err)
	}
	if !strings.Contains(string(body), "Host prod") {
		t.Fatalf("generated config lacks the host:\n%s", body)
	}

	s.out.Reset()
	s.mustRun(t, "status")
	status := s.out.String()
	for _, want := range []string{"unlocked", "hosts        1", "keys         1"} {
		if !strings.Contains(status, want) {
			t.Errorf("status is missing %q:\n%s", want, status)
		}
	}

	s.mustRun(t, "install")
	userConfig, err := os.ReadFile(s.Layout.UserSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(userConfig), "# BEGIN sshstate managed include") {
		t.Fatalf("the Include is not at the top:\n%s", userConfig)
	}

	s.out.Reset()
	s.mustRun(t, "lock")
	if !strings.Contains(s.out.String(), "Locked") {
		t.Fatal("lock reported nothing")
	}

	s.lines = []string{"y"}
	s.mustRun(t, "uninstall")
	if _, err := os.Stat(s.Layout.Database()); err != nil {
		t.Fatalf("uninstall removed the vault: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("uninstall removed the user's source key: %v", err)
	}
}

func TestPurgeIsRefusedWithoutDeletingData(t *testing.T) {
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

	err := s.run(t, "uninstall", "--purge")
	if err == nil {
		t.Fatal("--purge was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "nothing was deleted") {
		t.Fatalf("unexpected message: %v", err)
	}
	if _, statErr := os.Stat(s.Layout.Database()); statErr != nil {
		t.Fatalf("--purge deleted data despite being refused: %v", statErr)
	}
}

func TestCommandsWithoutDaemonExplainThemselves(t *testing.T) {
	s := newScripted(t)
	for _, verb := range []string{"status", "hosts", "keys", "trust", "doctor", "sync", "lock", "install"} {
		err := s.run(t, verb)
		if err == nil {
			t.Fatalf("%s succeeded on a machine with no vault", verb)
		}
		if !strings.Contains(err.Error(), "sshstate setup") {
			t.Errorf("%s on a fresh machine does not point at setup: %v", verb, err)
		}
		if strings.Contains(err.Error(), "sshstate daemon") || strings.Contains(err.Error(), "sshstate init") {
			t.Errorf("%s on a fresh machine points at the half-setup path: %v", verb, err)
		}
	}
}

func writeTestKey(t *testing.T, path, comment string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), comment)
	if err := os.WriteFile(path+".pub", []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

func extractRecordID(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if id, ok := strings.CutPrefix(line, "record "); ok {
			return strings.TrimSpace(id)
		}
	}
	t.Fatalf("no record id in output:\n%s", out)
	return ""
}

func TestAHostWithoutKeysPointsAtEditToAttachOne(t *testing.T) {
	s, _ := ready(t)
	s.mustRun(t, "edit", "prod", "--port", "2201")
	if got := s.errOut.String(); !strings.Contains(got, "sshstate edit prod --key <key>") || strings.Contains(got, "now references") {
		t.Fatalf("edit did not point at attaching a key:\n%s", got)
	}
	s.errOut.Reset()
	s.mustRun(t, "add", "bare", "--hostname", "10.0.0.6", "--user", "ubuntu")
	if got := s.errOut.String(); !strings.Contains(got, "sshstate edit bare --key <key>") || strings.Contains(got, "recreate") {
		t.Fatalf("add did not point at attaching a key:\n%s", got)
	}
}

func TestChangePasswordRewrapsTheDeviceSecrets(t *testing.T) {
	s, _, _ := listReady(t)

	s.secrets = []string{"not the password", "new pass", "new pass"}
	if err := s.run(t, "change-password"); err == nil || !strings.Contains(err.Error(), "current password is wrong") {
		t.Fatalf("a wrong current password was accepted: %v", err)
	}
	s.secrets = []string{password, "new pass", "different"}
	if err := s.run(t, "change-password"); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched new passwords were accepted: %v", err)
	}

	s.secrets = []string{password, "new pass", "new pass"}
	s.mustRun(t, "change-password")
	s.mustRun(t, "lock")
	s.secrets = []string{password}
	if err := s.run(t, "unlock"); err == nil {
		t.Fatal("the old password still unlocks the vault")
	}
	s.secrets = []string{"new pass"}
	s.mustRun(t, "unlock")
	s.mustRun(t, "hosts")
}
