package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func publicKeyLine(t *testing.T) string {
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

func trustHarness(t *testing.T, knownHosts string) *harness {
	t.Helper()
	h := start(t)
	if _, err := h.client.Unlock(context.Background(), testPassword); err != nil {
		t.Fatal(err)
	}
	for _, host := range []control.AddHostRequest{
		{Alias: "prod", HostName: "10.0.0.5", User: "ubuntu", Port: 2222},
		{Alias: "web", HostName: "192.0.2.10", User: "ubuntu"},
	} {
		if _, err := h.client.AddHost(context.Background(), host); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(strings.TrimSuffix(h.layout.UserKnownHosts(), "/known_hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.UserKnownHosts(), []byte(knownHosts), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTrustPreviewMatchesManagedDestinations(t *testing.T) {
	prodKey := publicKeyLine(t)
	webKey := publicKeyLine(t)
	revoked := publicKeyLine(t)
	file := strings.Join([]string{
		"# a comment",
		"[10.0.0.5]:2222 " + prodKey,
		"192.0.2.10 " + webKey,
		"10.0.0.5 " + publicKeyLine(t),
		"someone-elses-host.example.com " + publicKeyLine(t),
		"@revoked 192.0.2.10 " + revoked,
		"this is not a known_hosts line",
		"",
	}, "\n")
	h := trustHarness(t, file)

	preview, err := h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Candidates) != 3 {
		for _, c := range preview.Candidates {
			t.Logf("candidate: %s %v %s", c.Aliases, c.Destinations, c.Fingerprint)
		}
		t.Fatalf("got %d candidates, want 3", len(preview.Candidates))
	}
	if preview.Unrelated != 2 {
		t.Errorf("got %d unrelated entries, want 2", preview.Unrelated)
	}
	if len(preview.Problems) != 1 {
		t.Errorf("got %d problems, want 1: %v", len(preview.Problems), preview.Problems)
	}
	var sawRevoked bool
	for _, c := range preview.Candidates {
		if c.Status != control.TrustStatusNew {
			t.Errorf("candidate %s is %q on a fresh vault", c.Fingerprint, c.Status)
		}
		if c.Marker == "@revoked" {
			sawRevoked = true
			if !strings.Contains(c.Line, "@revoked") {
				t.Error("the revoked marker was dropped from the previewed line")
			}
		}
	}
	if !sawRevoked {
		t.Error("the @revoked entry was not offered for import")
	}
}

func TestTrustImportPublishesAndPreservesTheSource(t *testing.T) {
	prodKey := publicKeyLine(t)
	webKey := publicKeyLine(t)
	file := "[10.0.0.5]:2222 " + prodKey + "\n192.0.2.10 " + webKey + "\n"
	h := trustHarness(t, file)
	before, err := os.ReadFile(h.layout.UserKnownHosts())
	if err != nil {
		t.Fatal(err)
	}

	preview, err := h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var digests []string
	for _, c := range preview.Candidates {
		digests = append(digests, c.Digest)
	}
	res, err := h.client.TrustImport(context.Background(), digests)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 2 || res.Pending != 0 {
		t.Fatalf("imported %d (%d pending), want 2 and 0", res.Imported, res.Pending)
	}

	generated, err := os.ReadFile(h.layout.KnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"[10.0.0.5]:2222 " + prodKey, "192.0.2.10 " + webKey} {
		if !strings.Contains(string(generated), line) {
			t.Fatalf("generated known_hosts is missing %q:\n%s", line, generated)
		}
	}
	if fi, err := os.Stat(h.layout.KnownHosts()); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("generated known_hosts is mode %04o", got)
	}
	if _, err := os.Stat(h.layout.CaptureFile()); err != nil {
		t.Errorf("the capture file was not created: %v", err)
	}

	after, err := os.ReadFile(h.layout.UserKnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("importing modified the user's own known_hosts")
	}

	preview, err = h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range preview.Candidates {
		if c.Status != control.TrustStatusImported {
			t.Errorf("entry %s is %q after import, want %q", c.Fingerprint, c.Status, control.TrustStatusImported)
		}
	}
	res, err = h.client.TrustImport(context.Background(), digests)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 0 || res.Skipped != 2 {
		t.Fatalf("re-import added %d and skipped %d, want 0 and 2", res.Imported, res.Skipped)
	}
	stored, err := h.mgr.KnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Fatalf("the vault holds %d known_host records after two imports, want 2", len(stored))
	}
}

func TestConflictingTrustImportsAsPending(t *testing.T) {
	first := publicKeyLine(t)
	h := trustHarness(t, "[10.0.0.5]:2222 "+first+"\n")
	preview, err := h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.TrustImport(context.Background(), []string{preview.Candidates[0].Digest}); err != nil {
		t.Fatal(err)
	}

	second := publicKeyLine(t)
	body := "[10.0.0.5]:2222 " + first + "\n[10.0.0.5]:2222 " + second + "\n"
	if err := os.WriteFile(h.layout.UserKnownHosts(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err = h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var conflicting string
	for _, c := range preview.Candidates {
		if c.Status == control.TrustStatusConflict {
			conflicting = c.Digest
		}
	}
	if conflicting == "" {
		t.Fatalf("a second key for the same destination was not reported as a conflict: %+v", preview.Candidates)
	}
	res, err := h.client.TrustImport(context.Background(), []string{conflicting})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending != 1 {
		t.Fatalf("the conflict was imported as %d pending, want 1", res.Pending)
	}
	generated, err := os.ReadFile(h.layout.KnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(generated), second) {
		t.Fatal("a pending candidate reached the generated known_hosts file")
	}
	if !strings.Contains(string(generated), first) {
		t.Fatal("approved trust was lost when a conflict arrived")
	}
	stored, err := h.mgr.KnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	var pending int
	for _, s := range stored {
		if s.Status == vault.TrustPending {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("the vault holds %d pending observations, want 1", pending)
	}
}

func TestTrustImportRejectsUnknownDigest(t *testing.T) {
	h := trustHarness(t, "[10.0.0.5]:2222 "+publicKeyLine(t)+"\n")
	_, err := h.client.TrustImport(context.Background(),
		[]string{"0000000000000000000000000000000000000000000000000000000000000000"})
	if err == nil {
		t.Fatal("an unknown digest was accepted")
	}
	stored, err := h.mgr.KnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatalf("a rejected import stored %d records", len(stored))
	}
}

func TestTrustPreviewWithNoSourceFile(t *testing.T) {
	h := start(t)
	if _, err := h.client.Unlock(context.Background(), testPassword); err != nil {
		t.Fatal(err)
	}
	preview, err := h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatalf("preview failed with no known_hosts file: %v", err)
	}
	if len(preview.Candidates) != 0 {
		t.Fatalf("got candidates from a missing file: %+v", preview.Candidates)
	}
}

func TestTrustPreviewMatchesHashedEntries(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	prodKey := publicKeyLine(t)
	h := trustHarness(t, "[10.0.0.5]:2222 "+prodKey+"\nunmanaged.example.com "+publicKeyLine(t)+"\n")
	if out, err := exec.Command("ssh-keygen", "-H", "-f", h.layout.UserKnownHosts()).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -H: %v: %s", err, out)
	}
	preview, err := h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Candidates) != 1 {
		t.Fatalf("got %d candidates from a hashed file, want 1", len(preview.Candidates))
	}
	if preview.Candidates[0].Aliases[0] != "prod" {
		t.Fatalf("hashed entry matched %v", preview.Candidates[0].Aliases)
	}
	if preview.Opaque != 1 || preview.Unrelated != 0 {
		t.Fatalf("opaque=%d unrelated=%d, want 1 and 0", preview.Opaque, preview.Unrelated)
	}
}
