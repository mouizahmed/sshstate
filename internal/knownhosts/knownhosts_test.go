package knownhosts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sampleKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBQZsd/6fZ4a9AzCNzT0ldGBHyPtkQxFZMKf/+iCJI0V"

func TestParsePlainEntry(t *testing.T) {
	e, err := ParseLine("10.0.0.5 " + sampleKey)
	if err != nil {
		t.Fatal(err)
	}
	if e.KeyType != "ssh-ed25519" {
		t.Fatalf("key type is %q", e.KeyType)
	}
	if !strings.HasPrefix(e.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint is %q", e.Fingerprint)
	}
	if e.Marker != "" || e.Hashed {
		t.Fatalf("plain entry reported marker %q hashed %v", e.Marker, e.Hashed)
	}
	if !e.Matches("10.0.0.5") {
		t.Fatal("entry did not match its own host")
	}
	if e.Matches("10.0.0.6") {
		t.Fatal("entry matched a different host")
	}
}

func TestMarkersPreserved(t *testing.T) {
	for _, marker := range []string{MarkerRevoked, MarkerCertAuthority} {
		e, err := ParseLine(marker + " 10.0.0.5 " + sampleKey)
		if err != nil {
			t.Fatalf("%s: %v", marker, err)
		}
		if e.Marker != marker {
			t.Fatalf("marker %q parsed as %q", marker, e.Marker)
		}
		if !strings.HasPrefix(e.Line, marker) {
			t.Fatalf("stored line lost its marker: %q", e.Line)
		}
	}
}

func TestPortedDestination(t *testing.T) {
	if got := Destination("10.0.0.5", 22); got != "10.0.0.5" {
		t.Fatalf("port 22 rendered as %q", got)
	}
	if got := Destination("10.0.0.5", 2222); got != "[10.0.0.5]:2222" {
		t.Fatalf("non-default port rendered as %q", got)
	}
	e, err := ParseLine("[10.0.0.5]:2222 " + sampleKey)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Matches(Destination("10.0.0.5", 2222)) {
		t.Fatal("ported entry did not match its own destination")
	}
	if e.Matches(Destination("10.0.0.5", 22)) {
		t.Fatal("ported entry matched the same host on port 22")
	}
}

func TestPatternsAndNegation(t *testing.T) {
	e, err := ParseLine("*.example.com,!secret.example.com " + sampleKey)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Matches("db.example.com") {
		t.Fatal("wildcard did not match")
	}
	if e.Matches("secret.example.com") {
		t.Fatal("negated pattern was trusted anyway")
	}
	if e.Matches("db.example.org") {
		t.Fatal("wildcard matched a different domain")
	}
}

func TestCommaSeparatedHosts(t *testing.T) {
	e, err := ParseLine("alpha.example.com,10.0.0.5 " + sampleKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"alpha.example.com", "10.0.0.5"} {
		if !e.Matches(host) {
			t.Fatalf("entry did not match %q", host)
		}
	}
}

func TestHashedEntryMatchesOpenSSHHashing(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	body := "10.0.0.5 " + sampleKey + "\n[10.0.0.5]:2222 " + sampleKey + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(keygen, "-H", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -H: %v: %s", err, out)
	}
	entries, problems, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("hashed file produced problems: %v", problems)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	var matchedPlain, matchedPorted bool
	for _, e := range entries {
		if !e.Hashed {
			t.Fatalf("ssh-keygen -H left entry %d unhashed: %q", e.LineNo, e.Line)
		}
		if e.Matches(Destination("10.0.0.5", 22)) {
			matchedPlain = true
		}
		if e.Matches(Destination("10.0.0.5", 2222)) {
			matchedPorted = true
		}
	}
	if !matchedPlain || !matchedPorted {
		t.Fatalf("hashed matching missed an entry (plain=%v ported=%v)", matchedPlain, matchedPorted)
	}
	for _, e := range entries {
		if e.Matches(Destination("10.0.0.6", 22)) {
			t.Fatal("hashed entry matched an unrelated host")
		}
	}
}

func TestBadLineDoesNotHideGoodOnes(t *testing.T) {
	text := strings.Join([]string{
		"# a comment",
		"",
		"10.0.0.5 " + sampleKey,
		"this line is not a known_hosts entry at all",
		"10.0.0.6 " + sampleKey,
	}, "\n")
	entries, problems := Parse(text)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if len(problems) != 1 {
		t.Fatalf("got %d problems, want 1: %v", len(problems), problems)
	}
	if problems[0].LineNo != 4 {
		t.Fatalf("problem reported at line %d, want 4", problems[0].LineNo)
	}
	if entries[1].LineNo != 5 {
		t.Fatalf("second entry reported at line %d, want 5", entries[1].LineNo)
	}
}

func TestLineDigestIdentity(t *testing.T) {
	a := LineDigest("10.0.0.5 " + sampleKey)
	b := LineDigest("10.0.0.5   " + sampleKey + "  ")
	if a != b {
		t.Fatal("spacing changed the line digest")
	}
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA0kJz7Yy3xLmQXQ7d0T+Kk2gk5mBv1nJc8v5PXRGKcS"
	if LineDigest("10.0.0.5 "+other) == a {
		t.Fatal("a different key produced the same line digest")
	}
}
