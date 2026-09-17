// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relay"
)

func backupRelay(t *testing.T, r *testRelay) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backup.db")
	db, err := sql.Open("sqlite", "file:"+r.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`VACUUM INTO ?`, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func restoreRelay(t *testing.T, backup string) string {
	t.Helper()
	store, err := relay.Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := httptest.NewServer(relay.NewServer(store, relay.Config{PublicHTTPS: false}).Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

func hostsOf(t *testing.T, s *scripted) string {
	t.Helper()
	s.out.Reset()
	s.mustRun(t, "hosts")
	return s.out.String()
}

func TestOtherMachinesRejoinARelayStartedFromOneOfThem(t *testing.T) {
	lost := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", lost.url, "--bootstrap-secret", lost.secretPath)
	vaultID := vaultIDOf(t, a)
	b := pairInto(t, lost.url, a, vaultID, "b's own password")
	c := pairInto(t, lost.url, a, vaultID, "c's own password")
	c.mustRun(t, "add", "from-c", "--hostname", "10.0.0.21", "--user", "ubuntu")
	c.mustRun(t, "sync")
	a.mustRun(t, "sync")
	a.mustRun(t, "revoke", deviceIDFrom(t, c))
	a.mustRun(t, "edit", "prod", "--port", "2301")
	a.mustRun(t, "sync")
	b.mustRun(t, "sync")

	b.mustRun(t, "add", "cache", "--hostname", "10.0.0.20", "--user", "ubuntu")

	fresh := newTestRelay(t)
	a.mustRun(t, "connect", fresh.url, "--bootstrap-secret", fresh.secretPath, "--yes")

	err := b.run(t, "connect", fresh.url)
	if err == nil || !strings.Contains(err.Error(), "sshstate connect "+fresh.url+" --rejoin") {
		t.Fatalf("a machine on the old history was not told to rejoin: %v", err)
	}
	b.out.Reset()
	b.mustRun(t, "connect", fresh.url, "--rejoin")
	if got := b.out.String(); !strings.Contains(got, "Rejoined "+fresh.url) || !strings.Contains(got, "continues with: sshstate connect "+fresh.url+" --rejoin") {
		t.Fatalf("rejoining did not say so:\n%s", got)
	}
	if got := hostsOf(t, b); !strings.Contains(got, "ubuntu@10.0.0.5:2301") || !strings.Contains(got, "cache") || !strings.Contains(got, "from-c") {
		t.Fatalf("the rejoined machine is missing hosts:\n%s", got)
	}

	a.mustRun(t, "sync")
	if got := hostsOf(t, a); !strings.Contains(got, "cache") {
		t.Fatalf("the edit made while the relay was gone did not reach the seeding machine:\n%s", got)
	}

	joined := pairInto(t, fresh.url, a, vaultID, "joined's own password")
	joined.mustRun(t, "sync")
	if got := hostsOf(t, joined); !strings.Contains(got, "cache") {
		t.Fatalf("a machine paired onto the new relay is missing hosts:\n%s", got)
	}

	chain, err := fresh.store.Chain(protocol.ID(vaultID))
	if err != nil {
		t.Fatal(err)
	}
	revoked := 0
	for _, d := range chain.Devices() {
		if d.Revoked {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatalf("the new relay holds %d revoked devices, want 1", revoked)
	}
	if err := c.run(t, "connect", fresh.url, "--rejoin"); err == nil {
		t.Fatal("a revoked machine rejoined the new relay")
	}
}

func TestARelayRestoredFromAnOlderBackupLosesNothing(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, a)
	b := pairInto(t, r.url, a, vaultID, "b's own password")
	offline := pairInto(t, r.url, a, vaultID, "offline's own password")
	gone := pairInto(t, r.url, a, vaultID, "gone's own password")
	a.mustRun(t, "edit", "prod", "--port", "2400")
	a.mustRun(t, "add", "twice", "--hostname", "10.0.0.40", "--user", "ubuntu")
	a.mustRun(t, "sync")
	b.mustRun(t, "sync")
	offline.mustRun(t, "sync")

	backup := backupRelay(t, r)

	a.mustRun(t, "edit", "twice", "--port", "2402")
	a.mustRun(t, "edit", "twice", "--port", "2403")
	a.mustRun(t, "edit", "prod", "--port", "2401")
	a.mustRun(t, "revoke", deviceIDFrom(t, gone))
	a.mustRun(t, "sync")
	b.mustRun(t, "add", "late", "--hostname", "10.0.0.30", "--user", "ubuntu")
	b.mustRun(t, "sync")
	a.mustRun(t, "sync")

	restored := restoreRelay(t, backup)

	offline.mustRun(t, "connect", restored)
	offline.mustRun(t, "edit", "prod", "--port", "2499")
	offline.mustRun(t, "sync")

	err := a.run(t, "connect", restored)
	if err == nil || !strings.Contains(err.Error(), "older backup") || !strings.Contains(err.Error(), "--rejoin") {
		t.Fatalf("a machine ahead of the restored relay was not told to rejoin: %v", err)
	}
	a.out.Reset()
	a.mustRun(t, "connect", restored, "--rejoin")
	if got := a.out.String(); !strings.Contains(got, "Kept 1 edit") {
		t.Fatalf("the edit that diverged from the offline machine's was not kept aside:\n%s", got)
	}

	err = b.run(t, "connect", restored)
	if err == nil || !strings.Contains(err.Error(), "started again from another machine or restored from a backup") {
		t.Fatalf("a machine on the history before the restore was not told to rejoin: %v", err)
	}
	b.mustRun(t, "connect", restored, "--rejoin")
	offline.mustRun(t, "connect", restored, "--rejoin")

	if err := gone.run(t, "connect", restored, "--rejoin"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a device revoked after the backup was let back in: %v", err)
	}

	for name, s := range map[string]*scripted{"a": a, "b": b, "offline": offline} {
		s.mustRun(t, "sync")
		got := hostsOf(t, s)
		if !strings.Contains(got, "late") || !strings.Contains(got, "ubuntu@10.0.0.5:2499") || !strings.Contains(got, "ubuntu@10.0.0.40:2403") {
			t.Fatalf("%s does not have every host after the restore:\n%s", name, got)
		}
		if ids := conflictIDs(t, s); len(ids) != 1 {
			t.Fatalf("%s holds %d kept edits, want the one that diverged:\n%s", name, len(ids), s.out)
		}
		if !strings.Contains(s.out.String(), "2401") {
			t.Fatalf("%s's kept edit is not the port 2401 change:\n%s", name, s.out)
		}
	}
}
