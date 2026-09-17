// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func hostKey(t *testing.T) string {
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

func captureHarness(t *testing.T) *harness {
	t.Helper()
	h := start(t)
	if _, err := h.client.Unlock(context.Background(), testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.AddHost(context.Background(), control.AddHostRequest{
		Alias: "prod", HostName: "10.0.0.5", User: "ubuntu",
	}); err != nil {
		t.Fatal(err)
	}
	return h
}

func writeCapture(t *testing.T, h *harness, body string) {
	t.Helper()
	if err := os.MkdirAll(h.layout.SSH, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.CaptureFile(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendCapture(t *testing.T, h *harness, body string) {
	t.Helper()
	f, err := os.OpenFile(h.layout.CaptureFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
}

func trustLines(t *testing.T, h *harness) []vault.KnownHostView {
	t.Helper()
	views, err := h.mgr.KnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	return views
}

func TestCaptureTakesManagedDestinationsOnly(t *testing.T) {
	h := captureHarness(t)
	managed := hostKey(t)
	writeCapture(t, h, "10.0.0.5 "+managed+"\nsomewhere.example.com "+hostKey(t)+"\n")

	res, err := h.daemon.reconcileCapture()
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved != 1 {
		t.Fatalf("approved %d observations, expected 1: %+v", res.Approved, res)
	}
	views := trustLines(t, h)
	if len(views) != 1 {
		t.Fatalf("stored %d observations; an unmanaged destination joined the vault", len(views))
	}
	if !strings.Contains(views[0].Line, managed) {
		t.Fatalf("the wrong entry was stored: %s", views[0].Line)
	}
}

func TestCaptureIsIdempotent(t *testing.T) {
	h := captureHarness(t)
	writeCapture(t, h, "10.0.0.5 "+hostKey(t)+"\n")

	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	res, err := h.daemon.reconcileCapture()
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved != 0 || res.Skipped != 1 {
		t.Fatalf("a second pass stored the same line again: %+v", res)
	}
	if got := len(trustLines(t, h)); got != 1 {
		t.Fatalf("%d records after two passes", got)
	}
}

func TestADisagreeingKeyIsHeldPending(t *testing.T) {
	h := captureHarness(t)
	first := hostKey(t)
	writeCapture(t, h, "10.0.0.5 "+first+"\n")
	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}

	appendCapture(t, h, "10.0.0.5 "+hostKey(t)+"\n")
	res, err := h.daemon.reconcileCapture()
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending != 1 || res.Approved != 0 {
		t.Fatalf("a changed key was not held for review: %+v", res)
	}

	lines, err := h.mgr.ApprovedTrustLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], first) {
		t.Fatalf("the pending key reached the generated file: %v", lines)
	}
}

func TestAnUnterminatedLineIsRetriedNotStored(t *testing.T) {
	h := captureHarness(t)
	first := hostKey(t)
	second := hostKey(t)
	writeCapture(t, h, "10.0.0.5 "+first+"\n10.0.0.5 "+second)

	res, err := h.daemon.reconcileCapture()
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved != 1 {
		t.Fatalf("%+v", res)
	}
	views := trustLines(t, h)
	if len(views) != 1 {
		t.Fatalf("%d records; the line still being appended was stored", len(views))
	}
	if !strings.Contains(views[0].Line, first) {
		t.Fatalf("the wrong line was stored: %s", views[0].Line)
	}

	appendCapture(t, h, "\n")
	res, err = h.daemon.reconcileCapture()
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending != 1 {
		t.Fatalf("the completed line was not picked up: %+v", res)
	}
	if got := len(trustLines(t, h)); got != 2 {
		t.Fatalf("%d records after the line was terminated", got)
	}
}

func TestAMalformedLineIsReportedNotStored(t *testing.T) {
	h := captureHarness(t)
	writeCapture(t, h, "10.0.0.5 ssh-ed25519 not-base64\n")

	res, err := h.daemon.reconcileCapture()
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved != 0 || res.Ignored == 0 {
		t.Fatalf("a malformed line was not reported as ignored: %+v", res)
	}
	if got := len(trustLines(t, h)); got != 0 {
		t.Fatalf("%d records from a malformed line", got)
	}
}

func TestRemovingTheCaptureFileRemovesNoTrust(t *testing.T) {
	h := captureHarness(t)
	writeCapture(t, h, "10.0.0.5 "+hostKey(t)+"\n")
	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.layout.CaptureFile()); err != nil {
		t.Fatal(err)
	}

	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	if got := len(trustLines(t, h)); got != 1 {
		t.Fatalf("removing the capture file left %d records", got)
	}
}

func TestALockedVaultStoresNothing(t *testing.T) {
	h := captureHarness(t)
	writeCapture(t, h, "10.0.0.5 "+hostKey(t)+"\n")
	h.mgr.Lock()

	res, err := h.daemon.reconcileCapture()
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved != 0 {
		t.Fatalf("a locked vault ingested %+v", res)
	}
}

func TestMarkersAreNotFlattenedIntoOrdinaryTrust(t *testing.T) {
	h := captureHarness(t)
	writeCapture(t, h, "@cert-authority 10.0.0.5 "+hostKey(t)+"\n")

	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	views := trustLines(t, h)
	if len(views) != 1 {
		t.Fatalf("stored %d observations", len(views))
	}
	if views[0].Marker != "@cert-authority" {
		t.Fatalf("the marker became %q", views[0].Marker)
	}
}

func TestConcurrentAppendersAreAllPickedUp(t *testing.T) {
	h := captureHarness(t)
	writeCapture(t, h, "")

	const writers = 8
	keys := make([]string, writers)
	for i := range keys {
		keys[i] = hostKey(t)
	}
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f, err := os.OpenFile(h.layout.CaptureFile(), os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			if _, err := f.WriteString("10.0.0.5 " + keys[i] + "\n"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()

	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	views := trustLines(t, h)
	if len(views) != writers {
		t.Fatalf("%d of %d concurrently appended lines were stored", len(views), writers)
	}
	stored := map[string]bool{}
	for _, v := range views {
		stored[v.Line] = true
	}
	for _, k := range keys {
		if !stored["10.0.0.5 "+k] {
			t.Fatalf("an appended line is missing: %s", k)
		}
	}
	approved := 0
	for _, v := range views {
		if v.Status == vault.TrustApproved {
			approved++
		}
	}
	if approved != 1 {
		t.Fatalf("%d of %d concurrent first-use keys were approved", approved, writers)
	}
}

func TestObservationsMadeWhileLockedArriveOnUnlock(t *testing.T) {
	h := captureHarness(t)
	key := hostKey(t)
	if _, err := h.client.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeCapture(t, h, "10.0.0.5 "+key+"\n")
	if _, err := h.mgr.KnownHosts(); err == nil {
		t.Fatal("a locked vault answered a read")
	}

	if _, err := h.client.Unlock(context.Background(), testPassword); err != nil {
		t.Fatal(err)
	}
	views := trustLines(t, h)
	if len(views) != 1 {
		t.Fatalf("unlocking picked up %d of 1 observation", len(views))
	}
	if views[0].Status != vault.TrustApproved || !strings.Contains(views[0].Line, key) {
		t.Fatalf("stored %+v", views[0])
	}
	lines, err := h.mgr.ApprovedTrustLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 {
		t.Fatalf("the generated trust file has %d lines after unlock", len(lines))
	}
}

func TestApprovingAChangedKeyPublishesItOnceTheOldOneIsRevoked(t *testing.T) {
	h := captureHarness(t)
	first := hostKey(t)
	second := hostKey(t)
	writeCapture(t, h, "10.0.0.5 "+first+"\n")
	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	appendCapture(t, h, "10.0.0.5 "+second+"\n")
	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}

	list, err := h.client.TrustList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var pendingID, firstID string
	for _, e := range list.Entries {
		switch e.Status {
		case "pending":
			pendingID = e.RecordID
		case "approved":
			firstID = e.RecordID
		}
	}
	if pendingID == "" || firstID == "" {
		t.Fatalf("expected one approved and one pending: %+v", list.Entries)
	}

	if _, err := h.client.TrustApprove(context.Background(), control.TrustApproveRequest{RecordIDs: []string{pendingID}}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(h.layout.KnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), first) || strings.Contains(string(body), second) {
		t.Fatalf("two approved keys that disagree were shared before one was revoked:\n%s", body)
	}
	status, err := h.client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Issues) != 1 || !strings.Contains(status.Issues[0].Problem, "disagree") {
		t.Fatalf("the disagreement was not reported: %+v", status.Issues)
	}

	if _, err := h.client.TrustRevoke(context.Background(), control.TrustRevokeRequest{RecordIDs: []string{firstID}}); err != nil {
		t.Fatal(err)
	}
	body, err = os.ReadFile(h.layout.KnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "\n10.0.0.5 "+second) || !strings.Contains(string(body), "@revoked 10.0.0.5 "+first) {
		t.Fatalf("after revoking the old key, the new one was not published:\n%s", body)
	}
}

func TestARevokedLineStaysRevokedInTheGeneratedFile(t *testing.T) {
	h := captureHarness(t)
	key := hostKey(t)
	writeCapture(t, h, "@revoked 10.0.0.5 "+key+"\n")
	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	views := trustLines(t, h)
	if len(views) != 1 {
		t.Fatalf("stored %d", len(views))
	}
	if views[0].Marker != "@revoked" {
		t.Fatalf("the marker became %q", views[0].Marker)
	}
	lines, err := h.mgr.ApprovedTrustLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "@revoked ") {
		t.Fatalf("the revocation did not survive into the generated file: %v", lines)
	}
}

func TestApprovingARevokedObservationIsRefused(t *testing.T) {
	h := captureHarness(t)
	writeCapture(t, h, "@revoked 10.0.0.5 "+hostKey(t)+"\n")
	if _, err := h.daemon.reconcileCapture(); err != nil {
		t.Fatal(err)
	}
	views := trustLines(t, h)
	if err := h.mgr.SetKnownHostPending(views[0].RecordID); err != nil {
		t.Fatal(err)
	}
	if err := h.mgr.ApproveKnownHost(views[0].RecordID); err == nil {
		t.Fatal("a pending @revoked observation was approved into ordinary trust")
	}
}
