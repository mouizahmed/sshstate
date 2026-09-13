// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/export"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relay"
	"github.com/mouizahmed/sshstate/internal/vault"
)

type testRelay struct {
	url        string
	store      *relay.Store
	secretPath string
	secret     []byte
}

func newTestRelay(t *testing.T) *testRelay {
	t.Helper()
	dir := t.TempDir()
	store, err := relay.Open(filepath.Join(dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	secret := bytes.Repeat([]byte{0x5a}, protocol.BootstrapSecretBytes)
	if err := store.SetBootstrapSecret(secret); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(dir, "bootstrap.secret")
	if err := os.WriteFile(secretPath, []byte(protocol.EncodeBootstrapSecret(secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.NewServer(store, relay.Config{PublicHTTPS: false}).Handler())
	t.Cleanup(srv.Close)
	return &testRelay{url: srv.URL, store: store, secretPath: secretPath, secret: secret}
}

func ready(t *testing.T) (*scripted, string) {
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
	s.out.Reset()
	s.errOut.Reset()
	return s, kitPath
}

func TestConnectPublishesTheVault(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)

	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	out := s.out.String()
	if !strings.Contains(out, "created the vault there") {
		t.Fatalf("connect did not report bootstrap:\n%s", out)
	}
	if !strings.Contains(out, "Published") {
		t.Fatalf("connect published nothing:\n%s", out)
	}

	vaultID, err := r.store.VaultID()
	if err != nil {
		t.Fatal(err)
	}
	events, err := r.store.Membership(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("the relay holds %d membership events, want the root", len(events))
	}
	seq, err := r.store.CurrentSeq(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if seq == 0 {
		t.Fatal("the relay holds no records after connect")
	}

	if consumed, err := r.store.BootstrapConsumed(); err != nil || !consumed {
		t.Fatalf("bootstrap was not consumed (%v, %v)", consumed, err)
	}

	if _, err := r.store.RecoveryEnvelope(vaultID); err != nil {
		t.Fatalf("connect published no recovery envelope: %v", err)
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)
	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)

	s.out.Reset()
	s.mustRun(t, "sync")
	if got := s.out.String(); !strings.Contains(got, "Already up to date") {
		t.Fatalf("a second sync did work:\n%s", got)
	}

	s.mustRun(t, "add", "staging", "--hostname", "10.0.0.6", "--user", "ubuntu")
	s.out.Reset()
	s.mustRun(t, "sync")
	if got := s.out.String(); !strings.Contains(got, "Published") {
		t.Fatalf("the new host was not published:\n%s", got)
	}
	s.out.Reset()
	s.mustRun(t, "sync")
	if got := s.out.String(); !strings.Contains(got, "Already up to date") {
		t.Fatalf("the host was published twice:\n%s", got)
	}
}

func TestSyncWithoutARelayExplainsItself(t *testing.T) {
	s, _ := ready(t)
	err := s.run(t, "sync")
	if err == nil {
		t.Fatal("sync succeeded with no relay")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDevicesReflectsTheChain(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)
	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)

	s.out.Reset()
	s.mustRun(t, "devices")
	out := s.out.String()
	if !strings.Contains(out, "active") {
		t.Fatalf("no active device listed:\n%s", out)
	}
	if !strings.Contains(out, "*") {
		t.Fatalf("this device is not marked:\n%s", out)
	}
	if !strings.Contains(out, "signed membership chain") {
		t.Fatalf("the listing does not say what it reflects:\n%s", out)
	}
}

func TestTheLastDeviceCannotBeRevoked(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)
	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)

	s.out.Reset()
	s.mustRun(t, "devices")
	id := firstDeviceID(t, s.out.String())

	err := s.run(t, "revoke", id, "--yes")
	if err == nil {
		t.Fatal("the last device was revoked")
	}
	if !strings.Contains(err.Error(), "last authorized device") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRevokingThisDeviceNeedsConfirmation(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)
	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	s.out.Reset()
	s.mustRun(t, "devices")
	id := firstDeviceID(t, s.out.String())

	err := s.run(t, "revoke", id)
	if err == nil {
		t.Fatal("this device was revoked without confirmation")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("the refusal does not say how to proceed: %v", err)
	}
}

func firstDeviceID(t *testing.T, listing string) string {
	t.Helper()
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "*"))
		if len(fields) > 0 && protocol.ID(fields[0]).Valid() {
			return fields[0]
		}
	}
	t.Fatalf("no device id in the listing:\n%s", listing)
	return ""
}

func TestExportOpensWithTheRecoveryKit(t *testing.T) {
	s, kitPath := ready(t)
	path := filepath.Join(t.TempDir(), "vault.export")

	s.out.Reset()
	s.mustRun(t, "export", path)
	if got := s.out.String(); !strings.Contains(got, "recovery kit") {
		t.Fatalf("export did not say what opens it:\n%s", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the export is mode %o", perm)
	}

	body, err := os.ReadFile(kitPath)
	if err != nil {
		t.Fatal(err)
	}
	kit, err := vault.ParseKit(string(body))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := crypto.ParseEncryptionKey(kit.EncryptionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := export.Open(sealed, identity, kit.GenesisDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Contents.Records) == 0 {
		t.Fatal("the export carries no records")
	}
	if len(archive.Contents.Membership) != 1 {
		t.Fatalf("the export carries %d membership events", len(archive.Contents.Membership))
	}
	if archive.Manifest.VaultID != archive.Contents.Genesis.VaultID {
		t.Fatal("the manifest and the genesis disagree about the vault")
	}
}

func TestExportRefusesToOverwrite(t *testing.T) {
	s, _ := ready(t)
	path := filepath.Join(t.TempDir(), "vault.export")
	s.mustRun(t, "export", path)
	err := s.run(t, "export", path)
	if err == nil {
		t.Fatal("export overwrote an existing file")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportWorksOffline(t *testing.T) {
	s, _ := ready(t)
	path := filepath.Join(t.TempDir(), "offline.export")
	s.mustRun(t, "export", path)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestConflictsIsEmptyOnAQuietVault(t *testing.T) {
	s, _ := ready(t)
	s.out.Reset()
	s.mustRun(t, "conflicts")
	if got := s.out.String(); !strings.Contains(got, "No conflicts") {
		t.Fatalf("unexpected output:\n%s", got)
	}
}

func TestRestoreFromAnExportWithNoRelay(t *testing.T) {
	source, kitPath := ready(t)
	source.mustRun(t, "add", "staging", "--hostname", "10.0.0.6", "--user", "ubuntu")

	archivePath := filepath.Join(t.TempDir(), "vault.export")
	source.mustRun(t, "export", archivePath)

	replacement := newScripted(t)
	replacement.secrets = []string{"a different password", "a different password"}
	replacement.mustRun(t, "restore", archivePath, "--kit", kitPath)

	out := replacement.out.String()
	if !strings.Contains(out, "Restored vault") {
		t.Fatalf("restore reported nothing:\n%s", out)
	}
	if !strings.Contains(out, "authorized by the recovery kit") {
		t.Fatalf("restore did not say how the device is authorized:\n%s", out)
	}

	replacement.startDaemon(t)
	replacement.secrets = []string{"a different password"}
	replacement.mustRun(t, "unlock")
	replacement.out.Reset()
	replacement.mustRun(t, "status")
	status := replacement.out.String()
	if !strings.Contains(status, "hosts        2") {
		t.Fatalf("the restored vault does not hold both hosts:\n%s", status)
	}
	if !strings.Contains(status, "relay        none") {
		t.Fatalf("the restored vault claims a relay it never had:\n%s", status)
	}

	sourceVault := vaultIDOf(t, source)
	if !strings.Contains(status, sourceVault) {
		t.Fatalf("the restored vault has a different id:\n%s", status)
	}
	replacement.out.Reset()
	replacement.mustRun(t, "devices")
	devices := replacement.out.String()
	if strings.Count(devices, "active") != 2 {
		t.Fatalf("expected the original device and the replacement:\n%s", devices)
	}

	replacement.mustRun(t, "add", "third", "--hostname", "10.0.0.7", "--user", "ubuntu")
}

func TestRestoreNeedsItsOwnPassword(t *testing.T) {
	source, kitPath := ready(t)
	archivePath := filepath.Join(t.TempDir(), "vault.export")
	source.mustRun(t, "export", archivePath)

	replacement := newScripted(t)
	replacement.secrets = []string{"a different password", "a different password"}
	replacement.mustRun(t, "restore", archivePath, "--kit", kitPath)

	replacement.startDaemon(t)
	replacement.secrets = []string{password}
	if err := replacement.run(t, "unlock"); err == nil {
		t.Fatal("the exporting device's password unlocked the restored vault")
	}
}

func TestRestoreRefusesToOverwriteAVault(t *testing.T) {
	source, kitPath := ready(t)
	archivePath := filepath.Join(t.TempDir(), "vault.export")
	source.mustRun(t, "export", archivePath)

	source.secrets = []string{"another", "another"}
	err := source.run(t, "restore", archivePath, "--kit", kitPath)
	if err == nil {
		t.Fatal("restore overwrote an existing vault")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRestoreRefusesAnotherVaultsKit(t *testing.T) {
	source, _ := ready(t)
	archivePath := filepath.Join(t.TempDir(), "vault.export")
	source.mustRun(t, "export", archivePath)

	_, otherKit := ready(t)
	replacement := newScripted(t)
	replacement.secrets = []string{"pw", "pw"}
	if err := replacement.run(t, "restore", archivePath, "--kit", otherKit); err == nil {
		t.Fatal("another vault's kit opened this archive")
	}
}

func vaultIDOf(t *testing.T, s *scripted) string {
	t.Helper()
	s.out.Reset()
	s.mustRun(t, "status")
	for _, line := range strings.Split(s.out.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "vault" {
			return fields[1]
		}
	}
	t.Fatalf("no vault id in status:\n%s", s.out)
	return ""
}

func TestPurgeNeedsABackup(t *testing.T) {
	s, _ := ready(t)
	err := s.run(t, "uninstall", "--purge", "--yes")
	if err == nil {
		t.Fatal("--purge deleted a vault that had never been backed up")
	}
	if !strings.Contains(err.Error(), "backup first") {
		t.Fatalf("unexpected message: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "nothing was deleted") {
		t.Fatalf("the refusal does not say the vault survived: %v", err)
	}
	if _, statErr := os.Stat(s.Layout.Database()); statErr != nil {
		t.Fatalf("a refused purge deleted data: %v", statErr)
	}
}

func TestPurgeChecksTheBackupIsStillThere(t *testing.T) {
	s, _ := ready(t)
	path := filepath.Join(t.TempDir(), "vault.export")
	s.mustRun(t, "export", path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	err := s.run(t, "uninstall", "--purge", "--yes")
	if err == nil {
		t.Fatal("--purge accepted a backup that is gone")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "nothing was deleted") {
		t.Fatalf("unexpected message: %v", err)
	}
}

func TestPurgeRequiresTheVaultID(t *testing.T) {
	s, _ := ready(t)
	path := filepath.Join(t.TempDir(), "vault.export")
	s.mustRun(t, "export", path)

	s.lines = []string{"yes"}
	err := s.run(t, "uninstall", "--purge")
	if err == nil {
		t.Fatal("--purge accepted a confirmation that was not the vault id")
	}
	if !strings.Contains(err.Error(), "not this vault's id") {
		t.Fatalf("unexpected message: %v", err)
	}
	if _, statErr := os.Stat(s.Layout.Database()); statErr != nil {
		t.Fatalf("a refused purge deleted data: %v", statErr)
	}
}

func TestPurgeDeletesTheVaultAfterABackup(t *testing.T) {
	s, _ := ready(t)
	path := filepath.Join(t.TempDir(), "vault.export")
	s.mustRun(t, "export", path)
	vaultID := vaultIDOf(t, s)

	s.lines = []string{vaultID}
	s.out.Reset()
	if err := s.run(t, "uninstall", "--purge"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Layout.Database()); !os.IsNotExist(err) {
		t.Fatalf("the vault is still there: %v", err)
	}
	if got := s.out.String(); !strings.Contains(got, "Deleted:") {
		t.Fatalf("purge did not report the deletion:\n%s", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the purge deleted the backup: %v", err)
	}
}
