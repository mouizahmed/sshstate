// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestSyncOnASingleMachineVaultIsNotAnError(t *testing.T) {
	s, _ := ready(t)
	s.mustRun(t, "sync")
	out := s.out.String()
	if !strings.Contains(out, "nothing to sync") {
		t.Fatalf("sync on a local-only vault did not say there was nothing to do:\n%s", out)
	}
	if !strings.Contains(out, "sshstate connect") {
		t.Fatalf("sync did not say how to use more than one machine:\n%s", out)
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

func TestRestoreInstallsHostsAtTheirEditedRevision(t *testing.T) {
	source, kitPath := ready(t)
	source.mustRun(t, "edit", "prod", "--port", "2201")
	source.mustRun(t, "edit", "prod", "--port", "2202")
	archivePath := filepath.Join(t.TempDir(), "vault.export")
	source.mustRun(t, "export", archivePath)

	replacement := newScripted(t)
	replacement.secrets = []string{"a different password", "a different password"}
	if err := replacement.run(t, "restore", archivePath, "--kit", kitPath); err != nil {
		t.Fatalf("restore after edits: %v", err)
	}
	replacement.startDaemon(t)
	replacement.secrets = []string{"a different password"}
	replacement.mustRun(t, "unlock")
	replacement.out.Reset()
	replacement.mustRun(t, "hosts")
	if got := replacement.out.String(); !strings.Contains(got, "ubuntu@10.0.0.5:2202") {
		t.Fatalf("the restored host is not at its latest revision:\n%s", got)
	}
	replacement.mustRun(t, "edit", "prod", "--port", "2203")
}

func TestRestoreKeepsARemovedHostRemoved(t *testing.T) {
	source, kitPath := ready(t)
	source.mustRun(t, "add", "staging", "--hostname", "10.0.0.6", "--user", "ubuntu")
	source.mustRun(t, "remove", "staging", "--yes")
	archivePath := filepath.Join(t.TempDir(), "vault.export")
	source.mustRun(t, "export", archivePath)

	replacement := newScripted(t)
	replacement.secrets = []string{"a different password", "a different password"}
	replacement.mustRun(t, "restore", archivePath, "--kit", kitPath)
	if got := replacement.out.String(); !strings.Contains(got, " 1 record") {
		t.Fatalf("restore counted the removed host:\n%s", got)
	}
	replacement.startDaemon(t)
	replacement.secrets = []string{"a different password"}
	replacement.mustRun(t, "unlock")
	if aliases := hostAliases(t, replacement); aliases["staging"] || !aliases["prod"] {
		t.Fatalf("the restored hosts are wrong: %v", aliases)
	}
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

func TestPairingTwoDevicesThroughTheCLI(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "add", "gone", "--hostname", "10.0.0.8", "--user", "ubuntu")
	a.mustRun(t, "remove", "gone", "--yes")
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, a)

	b := newScripted(t)
	b.lines = []string{"y"}
	b.secrets = []string{"b's own password", "b's own password"}

	sessionCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- b.run(t, "pair", r.url, vaultID)
	}()

	deadline := time.Now().Add(20 * time.Second)
	var session string
	for session == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no pairing session appeared:\n%s", b.out)
		}
		for _, line := range strings.Split(b.out.String(), "\n") {
			if strings.HasPrefix(line, "Pairing session ") {
				session = strings.TrimSpace(strings.TrimPrefix(line, "Pairing session "))
			}
		}
		if session == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	sessionCh <- session

	a.lines = []string{"y"}
	a.out.Reset()
	if err := a.run(t, "approve", session); err != nil {
		t.Fatalf("approve: %v\nstdout:\n%s\nstderr:\n%s", err, a.out, a.errOut)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("pair: %v\nstdout:\n%s\nstderr:\n%s", err, b.out, b.errOut)
	}

	fpA := fingerprintFrom(t, a.out.String())
	fpB := fingerprintFrom(t, b.out.String())
	if fpA != fpB {
		t.Fatalf("the two machines displayed different fingerprints:\n%s\n%s", fpA, fpB)
	}
	if !strings.Contains(a.out.String(), "sent it 1 record") || !strings.Contains(b.out.String(), "Installed 1 record ") {
		t.Fatalf("the two machines counted the hand-over differently:\n%s\n%s", a.out, b.out)
	}

	b.startDaemon(t)
	b.secrets = []string{"b's own password"}
	b.mustRun(t, "unlock")
	b.out.Reset()
	b.mustRun(t, "status")
	status := b.out.String()
	if !strings.Contains(status, vaultID) {
		t.Fatalf("the joined device is in a different vault:\n%s", status)
	}
	if !strings.Contains(status, "hosts        1") {
		t.Fatalf("the snapshot did not arrive:\n%s", status)
	}

	b.mustRun(t, "add", "from-b", "--hostname", "10.0.0.9", "--user", "ubuntu")
	b.mustRun(t, "sync")
	a.out.Reset()
	a.mustRun(t, "sync")
	if got := a.out.String(); !strings.Contains(got, "Applied") {
		t.Fatalf("the first machine did not receive the second's edit:\n%s", got)
	}
	a.out.Reset()
	a.mustRun(t, "devices")
	if n := strings.Count(a.out.String(), "active"); n != 2 {
		t.Fatalf("expected two active devices:\n%s", a.out)
	}

	deviceB := deviceIDFrom(t, b)
	a.out.Reset()
	a.mustRun(t, "revoke", deviceB)
	b.mustRun(t, "add", "after-revocation", "--hostname", "10.0.0.10", "--user", "ubuntu")
	if err := b.run(t, "sync"); err == nil {
		t.Fatal("a revoked device published successfully")
	}
}

func TestPairingInstallsHostsAtTheirEditedRevision(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "edit", "prod", "--port", "2201")
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	a.mustRun(t, "edit", "prod", "--port", "2202")
	a.mustRun(t, "sync")

	b := pairInto(t, r.url, a, vaultIDOf(t, a), "b's own password")
	b.mustRun(t, "hosts")
	if got := b.out.String(); !strings.Contains(got, "ubuntu@10.0.0.5:2202") {
		t.Fatalf("the joined device did not get the latest revision:\n%s", got)
	}
	b.mustRun(t, "edit", "prod", "--port", "2203")
	b.mustRun(t, "sync")
	a.mustRun(t, "sync")
	a.out.Reset()
	a.mustRun(t, "hosts")
	if got := a.out.String(); !strings.Contains(got, "ubuntu@10.0.0.5:2203") {
		t.Fatalf("an edit made on the joined device did not reach the first:\n%s", got)
	}
}

func TestPairingAVaultWithNoHostsYet(t *testing.T) {
	r := newTestRelay(t)
	a := initWithoutDaemon(t)
	a.startDaemon(t)
	a.secrets = []string{password}
	a.mustRun(t, "unlock")
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)

	b := pairInto(t, r.url, a, vaultIDOf(t, a), "b's own password")
	b.mustRun(t, "add", "first", "--hostname", "10.0.0.11", "--user", "ubuntu")
	b.mustRun(t, "sync")
	a.mustRun(t, "sync")
	if !hostAliases(t, a)["first"] {
		t.Fatal("the first host added on the joined device did not reach the vault's first device")
	}
}

func TestPairingWhileAnEditIsUnsyncedStillGivesTheJoinerThatHost(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	a.mustRun(t, "edit", "prod", "--port", "2201")

	b := pairInto(t, r.url, a, vaultIDOf(t, a), "b's own password")
	a.mustRun(t, "sync")
	if err := b.run(t, "sync"); err != nil {
		t.Fatalf("the joined device could not apply an edit made before it joined: %v", err)
	}
	b.out.Reset()
	b.mustRun(t, "hosts")
	if got := b.out.String(); !strings.Contains(got, "ubuntu@10.0.0.5:2201") {
		t.Fatalf("the joined device does not have the edited host:\n%s", got)
	}
}

func TestApproveCancelledSendsNothing(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, a)

	b := newScripted(t)
	b.lines = []string{"n"}
	errCh := make(chan error, 1)
	go func() { errCh <- b.run(t, "pair", r.url, vaultID) }()

	deadline := time.Now().Add(20 * time.Second)
	var session string
	for session == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no pairing session appeared:\n%s", b.out)
		}
		for _, line := range strings.Split(b.out.String(), "\n") {
			if strings.HasPrefix(line, "Pairing session ") {
				session = strings.TrimSpace(strings.TrimPrefix(line, "Pairing session "))
			}
		}
		if session == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}

	a.lines = []string{"n"}
	err := a.run(t, "approve", session)
	if err == nil {
		t.Fatal("approve succeeded after the user said the fingerprints differed")
	}
	if !strings.Contains(err.Error(), "no keys were sent") {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}
	if _, statErr := os.Stat(b.Layout.Database()); statErr == nil {
		store, err := vault.OpenStore(b.Layout.Database())
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if initialized, err := store.Initialized(); err != nil {
			t.Fatal(err)
		} else if initialized {
			t.Fatal("a vault was installed despite the comparison failing")
		}
	}

	a.out.Reset()
	a.mustRun(t, "devices")
	if n := strings.Count(a.out.String(), "active"); n != 1 {
		t.Fatalf("a device was enrolled anyway:\n%s", a.out)
	}
}

func fingerprintFrom(t *testing.T, out string) string {
	t.Helper()
	group := regexp.MustCompile(`\b(\d{1,2}) ([A-Z2-7]{4})\b`)
	numbered := map[int]string{}
	for _, m := range group.FindAllStringSubmatch(out, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 || n > protocol.FingerprintGroupCount {
			continue
		}
		if existing, ok := numbered[n]; ok && existing != m[2] {
			t.Fatalf("group %d appeared twice with different values", n)
		}
		numbered[n] = m[2]
	}
	if len(numbered) != protocol.FingerprintGroupCount {
		t.Fatalf("found %d of %d groups in the output:\n%s",
			len(numbered), protocol.FingerprintGroupCount, out)
	}
	var b strings.Builder
	for i := 1; i <= protocol.FingerprintGroupCount; i++ {
		b.WriteString(numbered[i])
	}
	return b.String()
}

func deviceIDFrom(t *testing.T, s *scripted) string {
	t.Helper()
	s.out.Reset()
	s.mustRun(t, "status")
	for _, line := range strings.Split(s.out.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "device" {
			return fields[1]
		}
	}
	t.Fatalf("no device id in status:\n%s", s.out)
	return ""
}

func TestRecoverFromTheRelayWithOnlyTheKit(t *testing.T) {
	r := newTestRelay(t)
	source, kitPath := ready(t)
	source.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	source.mustRun(t, "add", "staging", "--hostname", "10.0.0.6", "--user", "ubuntu")
	source.mustRun(t, "sync")
	vaultID := vaultIDOf(t, source)

	replacement := newScripted(t)
	replacement.secrets = []string{"recovered password", "recovered password"}
	replacement.mustRun(t, "recover", r.url, vaultID, "--kit", kitPath)
	out := replacement.out.String()
	if !strings.Contains(out, "Recovered vault") {
		t.Fatalf("recover reported nothing:\n%s", out)
	}
	if !strings.Contains(out, "still authorized") {
		t.Fatalf("recover did not mention the devices it cannot revoke:\n%s", out)
	}

	replacement.startDaemon(t)
	replacement.secrets = []string{"recovered password"}
	replacement.mustRun(t, "unlock")
	replacement.out.Reset()
	replacement.mustRun(t, "status")
	status := replacement.out.String()
	if !strings.Contains(status, vaultID) {
		t.Fatalf("the recovered device is in a different vault:\n%s", status)
	}
	if !strings.Contains(status, r.url) {
		t.Fatalf("the recovered device did not record the relay:\n%s", status)
	}

	replacement.out.Reset()
	replacement.mustRun(t, "devices")
	if n := strings.Count(replacement.out.String(), "active"); n != 2 {
		t.Fatalf("expected the lost device and the replacement:\n%s", replacement.out)
	}
	replacement.mustRun(t, "add", "after-recovery", "--hostname", "10.0.0.7", "--user", "ubuntu")
	replacement.mustRun(t, "sync")

	source.out.Reset()
	source.mustRun(t, "sync")
	source.out.Reset()
	source.mustRun(t, "devices")
	if n := strings.Count(source.out.String(), "active"); n != 2 {
		t.Fatalf("the original device did not learn about the replacement:\n%s", source.out)
	}
}

func recoverDevice(t *testing.T, r *testRelay, source *scripted, kitPath string) (*scripted, string) {
	t.Helper()
	replacement := newScripted(t)
	replacement.secrets = []string{"recovered password", "recovered password"}
	if err := replacement.run(t, "recover", r.url, vaultIDOf(t, source), "--kit", kitPath); err != nil {
		t.Fatalf("recover: %v\nstdout:\n%s\nstderr:\n%s", err, replacement.out, replacement.errOut)
	}
	m := regexp.MustCompile(`as new device ([0-9a-f]+)`).FindStringSubmatch(replacement.out.String())
	if m == nil {
		t.Fatalf("recover named no device:\n%s", replacement.out)
	}
	return replacement, m[1]
}

func TestRecoveryAfterPairingKnowsTheJoinedDevice(t *testing.T) {
	r := newTestRelay(t)
	a, kitPath := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	pairInto(t, r.url, a, vaultIDOf(t, a), "b's own password")
	recoverDevice(t, r, a, kitPath)
}

func TestRecoveryCarriesWhatTheLastSyncPublished(t *testing.T) {
	r := newTestRelay(t)
	a, kitPath := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	a.mustRun(t, "add", "later", "--hostname", "10.0.0.8", "--user", "ubuntu")
	a.mustRun(t, "sync")

	replacement, _ := recoverDevice(t, r, a, kitPath)
	replacement.startDaemon(t)
	replacement.secrets = []string{"recovered password"}
	replacement.mustRun(t, "unlock")
	replacement.out.Reset()
	replacement.mustRun(t, "hosts")
	if got := replacement.out.String(); !strings.Contains(got, "later") {
		t.Fatalf("the recovery copy predates the last sync:\n%s", got)
	}
}

func TestRecoveryAfterARevocationKnowsOfIt(t *testing.T) {
	r := newTestRelay(t)
	a, kitPath := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	_, lost := recoverDevice(t, r, a, kitPath)
	a.mustRun(t, "sync")
	a.mustRun(t, "revoke", lost, "--yes")
	recoverDevice(t, r, a, kitPath)
}

func TestBootstrappingASecondRelayIsRefusedBeforeTheSecretIsSpent(t *testing.T) {
	first := newTestRelay(t)
	second := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", first.url, "--bootstrap-secret", first.secretPath)

	err := a.run(t, "connect", second.url, "--bootstrap-secret", second.secretPath)
	if err == nil || !strings.Contains(err.Error(), "already lives on "+first.url) {
		t.Fatalf("connecting a second relay was not refused clearly: %v", err)
	}
	if spent, err := second.store.BootstrapConsumed(); err != nil || spent {
		t.Fatalf("the refused connect spent the second relay's bootstrap secret: %v %v", spent, err)
	}
	a.out.Reset()
	a.mustRun(t, "status")
	if got := a.out.String(); !strings.Contains(got, first.url) {
		t.Fatalf("the vault no longer points at its relay:\n%s", got)
	}
	a.mustRun(t, "sync")
}

func TestARestoredVaultCannotStartANewRelay(t *testing.T) {
	r := newTestRelay(t)
	source, kitPath := ready(t)
	source.mustRun(t, "edit", "prod", "--port", "2201")
	archive := filepath.Join(t.TempDir(), "vault.export")
	source.mustRun(t, "export", archive)

	restored := newScripted(t)
	restored.secrets = []string{"restored password", "restored password"}
	restored.mustRun(t, "restore", archive, "--kit", kitPath)
	restored.startDaemon(t)
	restored.secrets = []string{"restored password"}
	restored.mustRun(t, "unlock")

	err := restored.run(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	if err == nil || !strings.Contains(err.Error(), "cannot start a new relay") {
		t.Fatalf("a restored vault was allowed to start a relay: %v", err)
	}
	if spent, err := r.store.BootstrapConsumed(); err != nil || spent {
		t.Fatalf("the refused connect spent the relay's bootstrap secret: %v %v", spent, err)
	}
	restored.out.Reset()
	restored.mustRun(t, "status")
	if got := restored.out.String(); !strings.Contains(got, "relay        none") {
		t.Fatalf("the refused connect left a relay configured:\n%s", got)
	}

	source.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	recoverDevice(t, r, source, kitPath)
}

func TestAConnectThatFailsRecordsNoRelay(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	unreachable := httptest.NewServer(http.NotFoundHandler())
	dead := unreachable.URL
	unreachable.Close()

	if err := a.run(t, "connect", dead, "--bootstrap-secret", r.secretPath); err == nil {
		t.Fatal("a connect to a relay that is not there succeeded")
	}
	if err := a.run(t, "connect", r.url); err == nil {
		t.Fatal("a connect to a relay that holds no vault succeeded")
	}
	a.out.Reset()
	a.mustRun(t, "status")
	if got := a.out.String(); !strings.Contains(got, "relay        none") {
		t.Fatalf("a failed connect left a relay recorded:\n%s", got)
	}
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
}

func TestConnectingToTheSameRelayAtANewAddress(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)

	moved := httptest.NewServer(relay.NewServer(r.store, relay.Config{PublicHTTPS: false}).Handler())
	t.Cleanup(moved.Close)
	a.mustRun(t, "connect", moved.URL)
	a.mustRun(t, "add", "after-move", "--hostname", "10.0.0.12", "--user", "ubuntu")
	a.mustRun(t, "sync")
	a.out.Reset()
	a.mustRun(t, "status")
	if got := a.out.String(); !strings.Contains(got, moved.URL) {
		t.Fatalf("the vault did not switch to the new address:\n%s", got)
	}
}

func TestSyncReportsADeviceChangeInsteadOfNothing(t *testing.T) {
	r := newTestRelay(t)
	a, kitPath := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	recoverDevice(t, r, a, kitPath)

	a.out.Reset()
	a.mustRun(t, "sync")
	if got := a.out.String(); !strings.Contains(got, "Learned 1 device change") || strings.Contains(got, "Already up to date") {
		t.Fatalf("sync did not report the new device:\n%s", got)
	}
	a.out.Reset()
	a.mustRun(t, "sync")
	if got := a.out.String(); !strings.Contains(got, "Already up to date") {
		t.Fatalf("a quiet sync reported changes:\n%s", got)
	}
}

func TestRecoverRefusesAnotherVault(t *testing.T) {
	r := newTestRelay(t)
	source, _ := ready(t)
	source.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, source)

	_, otherKit := ready(t)
	replacement := newScripted(t)
	replacement.secrets = []string{"pw", "pw"}
	err := replacement.run(t, "recover", r.url, vaultID, "--kit", otherKit)
	if err == nil {
		t.Fatal("another vault's kit recovered this one")
	}
	if !strings.Contains(err.Error(), "not") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveRejectsAnUnknownConflict(t *testing.T) {
	s, _ := ready(t)
	err := s.run(t, "resolve", protocol.MustNewID().String())
	if err == nil {
		t.Fatal("resolve accepted an id that is not a conflict")
	}
	if err := s.run(t, "resolve", "not-an-id"); err == nil {
		t.Fatal("resolve accepted a malformed id")
	}
}

func pairSecondDevice(t *testing.T, r *testRelay, a *scripted, vaultID string) *scripted {
	t.Helper()
	b := newScripted(t)
	b.lines = []string{"y"}
	b.secrets = []string{"second password", "second password"}
	errCh := make(chan error, 1)
	go func() { errCh <- b.run(t, "pair", r.url, vaultID) }()

	deadline := time.Now().Add(20 * time.Second)
	var session string
	for session == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no pairing session appeared:\n%s", b.out)
		}
		for _, line := range strings.Split(b.out.String(), "\n") {
			if strings.HasPrefix(line, "Pairing session ") {
				session = strings.TrimSpace(strings.TrimPrefix(line, "Pairing session "))
			}
		}
		if session == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	a.lines = []string{"y"}
	if err := a.run(t, "approve", session); err != nil {
		t.Fatalf("approve: %v\n%s", err, a.errOut)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("pair: %v\n%s", err, b.errOut)
	}
	b.startDaemon(t)
	b.secrets = []string{"second password"}
	b.mustRun(t, "unlock")
	b.out.Reset()
	return b
}

func TestUninstallReportsIncompleteDeregistration(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)
	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	pairSecondDevice(t, r, s, vaultIDOf(t, s))
	deviceID := deviceIDFrom(t, s)

	s.mustRun(t, "lock")
	s.out.Reset()
	s.errOut.Reset()
	s.mustRun(t, "uninstall", "--yes")

	warning := s.errOut.String()
	if !strings.Contains(warning, "did not complete") {
		t.Fatalf("a failed deregistration was not reported:\n%s", warning)
	}
	if !strings.Contains(warning, "remains an authorized writer") {
		t.Fatalf("the warning does not say the device is still authorized:\n%s", warning)
	}
	if !strings.Contains(warning, "sshstate revoke "+deviceID) {
		t.Fatalf("the warning does not say how to revoke it:\n%s", warning)
	}
	vaultID, err := r.store.VaultID()
	if err != nil {
		t.Fatal(err)
	}
	events, err := r.store.Membership(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("the chain changed despite the failure: %d events", len(events))
	}
	if got := s.out.String(); !strings.Contains(got, "Preserved: the encrypted vault") {
		t.Fatalf("the local uninstall did not complete:\n%s", got)
	}
}

func TestUninstallOfTheOnlyDeviceDoesNotSendYouToAnother(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)
	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	s.out.Reset()
	s.errOut.Reset()
	s.mustRun(t, "uninstall", "--yes")

	all := s.out.String() + s.errOut.String()
	if !strings.Contains(all, "only device") {
		t.Fatalf("uninstall did not say this is the only device:\n%s", all)
	}
	for _, wrong := range []string{"from another device", "did not complete"} {
		if strings.Contains(all, wrong) {
			t.Fatalf("uninstall of the only device said %q:\n%s", wrong, all)
		}
	}
}

func TestPurgingTheOnlyDeviceDoesNotSendYouToAnother(t *testing.T) {
	r := newTestRelay(t)
	s, _ := ready(t)
	s.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	s.mustRun(t, "export", filepath.Join(t.TempDir(), "vault.export"))
	s.out.Reset()
	s.errOut.Reset()
	s.mustRun(t, "uninstall", "--purge", "--yes")

	all := s.out.String() + s.errOut.String()
	if !strings.Contains(all, "only device") {
		t.Fatalf("purge did not say this is the only device:\n%s", all)
	}
	for _, wrong := range []string{"from another device", "did not complete"} {
		if strings.Contains(all, wrong) {
			t.Fatalf("purge of the only device said %q:\n%s", wrong, all)
		}
	}
}

func initWithoutDaemon(t *testing.T) *scripted {
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
	s.errOut.Reset()
	return s
}

func TestUninstallWithNoDaemonSaysAConnectedDeviceWasNotDeregistered(t *testing.T) {
	s := initWithoutDaemon(t)
	store, err := vault.OpenStore(s.Layout.Database())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetMeta(vault.MetaRelayURL, "https://relay.example"); err != nil {
		t.Fatal(err)
	}
	store.Close()

	s.mustRun(t, "uninstall", "--yes")
	warning := s.errOut.String()
	if !strings.Contains(warning, "not deregistered from https://relay.example") {
		t.Fatalf("uninstall did not say the device was left registered:\n%s", warning)
	}
}

func TestUninstallWithNoDaemonDoesNotMentionARelayALocalVaultNeverHad(t *testing.T) {
	s := initWithoutDaemon(t)

	s.mustRun(t, "uninstall", "--yes")
	if strings.Contains(s.errOut.String()+s.out.String(), "deregister") {
		t.Fatalf("uninstall of a single-machine vault talked about deregistering:\n%s%s", s.out.String(), s.errOut.String())
	}
}

func TestUninstallDeregistersWhenItCan(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, a)
	b := pairSecondDevice(t, r, a, vaultID)
	deviceB := deviceIDFrom(t, b)

	b.lines = []string{"y", "y"}
	b.out.Reset()
	b.errOut.Reset()
	b.mustRun(t, "uninstall")
	if got := b.out.String(); !strings.Contains(got, "Deregistered this device") {
		t.Fatalf("uninstall did not deregister:\n%s\n%s", got, b.errOut)
	}

	a.mustRun(t, "sync")
	a.out.Reset()
	a.mustRun(t, "devices")
	listing := a.out.String()
	if !strings.Contains(listing, deviceB) || !strings.Contains(listing, "revoked") {
		t.Fatalf("the chain does not record the deregistration:\n%s", listing)
	}
}

func pairInto(t *testing.T, relayURL string, approver *scripted, vaultID, password string) *scripted {
	t.Helper()
	joiner := newScripted(t)
	joiner.lines = []string{"y"}
	joiner.secrets = []string{password, password}

	errCh := make(chan error, 1)
	go func() { errCh <- joiner.run(t, "pair", relayURL, vaultID) }()

	deadline := time.Now().Add(20 * time.Second)
	var session string
	for session == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no pairing session appeared:\n%s", joiner.out)
		}
		for _, line := range strings.Split(joiner.out.String(), "\n") {
			if strings.HasPrefix(line, "Pairing session ") {
				session = strings.TrimSpace(strings.TrimPrefix(line, "Pairing session "))
			}
		}
		if session == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}

	approver.lines = []string{"y"}
	approver.out.Reset()
	if err := approver.run(t, "approve", session); err != nil {
		t.Fatalf("approve: %v\nstdout:\n%s\nstderr:\n%s", err, approver.out, approver.errOut)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("pair: %v\nstdout:\n%s\nstderr:\n%s", err, joiner.out, joiner.errOut)
	}

	joiner.startDaemon(t)
	joiner.secrets = []string{password}
	joiner.mustRun(t, "unlock")
	joiner.out.Reset()
	joiner.errOut.Reset()
	return joiner
}

func hostAliases(t *testing.T, s *scripted) map[string]bool {
	t.Helper()
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, h := range hosts {
		out[h.Alias] = true
	}
	return out
}

func TestThreeDevicesShareOneVault(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, a)

	b := pairInto(t, r.url, a, vaultID, "b's own password")
	c := pairInto(t, r.url, a, vaultID, "c's own password")

	a.out.Reset()
	a.mustRun(t, "devices")
	if n := strings.Count(a.out.String(), "active"); n != 3 {
		t.Fatalf("expected three active devices:\n%s", a.out)
	}

	c.mustRun(t, "add", "from-c", "--hostname", "10.0.0.30", "--user", "ubuntu")
	c.mustRun(t, "sync")
	a.mustRun(t, "sync")
	b.mustRun(t, "sync")

	for name, s := range map[string]*scripted{"a": a, "b": b, "c": c} {
		if !hostAliases(t, s)["from-c"] {
			t.Fatalf("device %s never saw the host device c added", name)
		}
	}

	b.mustRun(t, "add", "from-b", "--hostname", "10.0.0.20", "--user", "ubuntu")
	b.mustRun(t, "sync")
	c.mustRun(t, "sync")
	if !hostAliases(t, c)["from-b"] {
		t.Fatal("device c never saw the host device b added")
	}

	deviceB := deviceIDFrom(t, b)
	a.out.Reset()
	a.mustRun(t, "revoke", deviceB)

	b.mustRun(t, "add", "after-revocation", "--hostname", "10.0.0.21", "--user", "ubuntu")
	if err := b.run(t, "sync"); err == nil {
		t.Fatal("a revoked device published successfully")
	}

	c.mustRun(t, "add", "from-c-again", "--hostname", "10.0.0.31", "--user", "ubuntu")
	c.mustRun(t, "sync")
	a.mustRun(t, "sync")
	if !hostAliases(t, a)["from-c-again"] {
		t.Fatal("revoking b stopped c from publishing")
	}
	if hostAliases(t, a)["after-revocation"] {
		t.Fatal("a revoked device's edit reached another device")
	}

	a.out.Reset()
	a.mustRun(t, "devices")
	var active, revoked int
	for _, line := range strings.Split(a.out.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch {
		case contains(fields, "active"):
			active++
		case contains(fields, "revoked") && len(fields) > 2:
			revoked++
		}
	}
	if active != 2 || revoked != 1 {
		t.Fatalf("expected two active devices and one revoked, got %d and %d:\n%s", active, revoked, a.out)
	}
	if !strings.Contains(a.out.String(), deviceB) {
		t.Fatalf("the revoked device left the chain:\n%s", a.out)
	}
}

func contains(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

func TestMergesThatBreakReferencesKeepSyncWorkingAndCanBeRepaired(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	b := pairInto(t, r.url, a, vaultIDOf(t, a), "b's own password")

	dir := t.TempDir()
	writeTestKey(t, filepath.Join(dir, "doomed"), "doomed")
	writeTestKey(t, filepath.Join(dir, "spare"), "spare")
	a.mustRun(t, "add-key", filepath.Join(dir, "doomed"))
	a.mustRun(t, "sync")
	b.mustRun(t, "sync")

	b.mustRun(t, "add", "db", "--hostname", "10.0.0.2", "--user", "pg", "--key", "doomed")
	a.mustRun(t, "remove-key", "doomed", "--yes")
	a.mustRun(t, "add", "dup", "--hostname", "10.0.0.10", "--user", "x")
	b.mustRun(t, "add", "dup", "--hostname", "10.0.0.11", "--user", "y")
	a.mustRun(t, "sync")
	b.errOut.Reset()
	if err := b.run(t, "sync"); err != nil {
		t.Fatalf("a merge that broke a reference made sync fail: %v", err)
	}
	a.errOut.Reset()
	if err := a.run(t, "sync"); err != nil {
		t.Fatalf("the other device could not sync the broken reference either: %v", err)
	}

	for name, s := range map[string]*scripted{"a": a, "b": b} {
		config := readFile(t, s.Layout.Config())
		if !strings.Contains(config, "Host prod\n") || !strings.Contains(config, "Host db\n") {
			t.Fatalf("device %s: consistent hosts were not rendered:\n%s", name, config)
		}
		if strings.Contains(config, "Host dup\n") {
			t.Fatalf("device %s: an ambiguous alias was rendered:\n%s", name, config)
		}
		s.errOut.Reset()
		s.mustRun(t, "status")
		problems := s.errOut.String()
		if !strings.Contains(problems, "db offers key") || !strings.Contains(problems, "dup shares the alias") {
			t.Fatalf("device %s: status did not report the broken references:\n%s", name, problems)
		}
	}

	if err := b.run(t, "edit", "db", "--port", "2201"); err != nil {
		t.Fatalf("a host with a removed key could not have an unrelated field edited: %v", err)
	}
	if err := b.run(t, "edit", "dup", "--port", "2200"); err == nil || !strings.Contains(err.Error(), "name one by its record id") {
		t.Fatalf("editing an ambiguous alias did not ask for a record id: %v", err)
	}
	hosts, err := b.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var dupID string
	for _, h := range hosts {
		if h.Alias == "dup" && h.User == "y" {
			dupID = h.RecordID
		}
	}
	b.mustRun(t, "edit", dupID, "--alias", "dup-b")
	b.mustRun(t, "add-key", filepath.Join(dir, "spare"))
	b.mustRun(t, "edit", "db", "--key", "spare")
	b.mustRun(t, "sync")
	a.mustRun(t, "sync")
	for name, s := range map[string]*scripted{"a": a, "b": b} {
		s.errOut.Reset()
		s.mustRun(t, "status")
		if got := s.errOut.String(); strings.Contains(got, "need attention") || strings.Contains(got, "needs attention") {
			t.Fatalf("device %s: the repairs did not clear the problems:\n%s", name, got)
		}
		config := readFile(t, s.Layout.Config())
		if !strings.Contains(config, "Host dup\n") || !strings.Contains(config, "Host dup-b\n") {
			t.Fatalf("device %s: the renamed hosts are not both in the config:\n%s", name, config)
		}
	}
}

func TestARevokedDeviceIsToldWhyItNoLongerSyncs(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	b := pairInto(t, r.url, a, vaultIDOf(t, a), "b's own password")
	a.mustRun(t, "revoke", deviceIDFrom(t, b))

	err := b.run(t, "sync")
	if err == nil || !strings.Contains(err.Error(), "another device revoked it") || !strings.Contains(err.Error(), "sshstate uninstall --purge, then sshstate pair") {
		t.Fatalf("the revoked device was not told what happened: %v", err)
	}
	b.out.Reset()
	b.mustRun(t, "status")
	if !strings.Contains(b.out.String(), "revoked by another device") {
		t.Fatalf("status on the revoked device does not say so:\n%s", b.out)
	}
}

func TestPairingWithAWrongVaultIDSaysWhereToFindIt(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	joiner := newScripted(t)
	err := joiner.run(t, "pair", r.url, "00000000000000000000000000000000")
	if err == nil || !strings.Contains(err.Error(), "holds no vault") || strings.Contains(err.Error(), "this machine still has the vault") {
		t.Fatalf("a mistyped vault id was not explained for a joining machine: %v", err)
	}
	err = a.run(t, "approve", "00000000000000000000000000000000")
	if err == nil || !strings.Contains(err.Error(), "no pairing session") {
		t.Fatalf("an unknown session was not explained: %v", err)
	}
}
