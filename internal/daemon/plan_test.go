package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func planKey(t *testing.T) vault.KeyView {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return vault.KeyView{RecordID: protocol.MustNewID(), PublicKey: string(ssh.MarshalAuthorizedKey(key))}
}

func planHost(alias string, jump string, keys ...protocol.ID) vault.HostView {
	h := vault.HostView{RecordID: protocol.MustNewID(), Alias: alias, HostName: "10.0.0.1", User: "u", Port: 22, KeyIDs: keys}
	if jump != "" {
		h.ProxyJump = &jump
	}
	return h
}

func renderedAliases(t *testing.T, hosts []vault.HostView, keys []vault.KeyView) ([]string, []control.HostIssue) {
	t.Helper()
	out, issues, err := planHosts(hosts, keys)
	if err != nil {
		t.Fatalf("an inconsistent vault stopped the whole config from rendering: %v", err)
	}
	var aliases []string
	for _, h := range out {
		aliases = append(aliases, h.Alias)
	}
	sort.Strings(aliases)
	return aliases, issues
}

func issueFor(issues []control.HostIssue, alias, fragment string) *control.HostIssue {
	for i := range issues {
		if issues[i].Alias == alias && strings.Contains(issues[i].Problem, fragment) {
			return &issues[i]
		}
	}
	return nil
}

func TestPlanRendersEverythingConsistentAndReportsTheRest(t *testing.T) {
	kept := planKey(t)
	removed := protocol.MustNewID()
	hosts := []vault.HostView{
		planHost("fine", "", kept.RecordID),
		planHost("lostkey", "", removed, kept.RecordID),
		planHost("dup", ""),
		planHost("dup", ""),
		planHost("orphan", "gone"),
		planHost("a", "b"),
		planHost("b", "a"),
		planHost("behindloop", "a"),
		planHost("behinddup", "dup"),
	}
	aliases, issues := renderedAliases(t, hosts, []vault.KeyView{kept})
	if strings.Join(aliases, ",") != "fine,lostkey" {
		t.Fatalf("rendered %v, want only fine and lostkey", aliases)
	}

	lost := issueFor(issues, "lostkey", "no longer in the vault")
	if lost == nil || lost.Omitted || !strings.Contains(lost.Remedy, "sshstate edit lostkey --key") {
		t.Fatalf("the removed key was not reported with a way to fix it: %+v", issues)
	}
	out, _, _ := planHosts(hosts, []vault.KeyView{kept})
	for _, h := range out {
		if h.Alias == "lostkey" && (len(h.Identities) != 1 || h.Identities[0].Slot != 1) {
			t.Fatalf("lostkey should keep its remaining key in slot 1: %+v", h.Identities)
		}
	}

	for alias, fragment := range map[string]string{
		"dup":        "shares the alias",
		"orphan":     "not a host in this vault",
		"a":          "loop",
		"b":          "loop",
		"behindloop": "left out of the SSH config",
		"behinddup":  "more than one host is named",
	} {
		issue := issueFor(issues, alias, fragment)
		if issue == nil || !issue.Omitted || !strings.Contains(issue.Remedy, "sshstate edit ") {
			t.Fatalf("host %q: want an omitted issue containing %q with a remedy, got %+v", alias, fragment, issues)
		}
	}
	if dup := issueFor(issues, "dup", "shares the alias"); !strings.Contains(dup.Remedy, dup.RecordID) {
		t.Fatalf("a duplicate alias must be fixed by record id, the alias is ambiguous: %s", dup.Remedy)
	}
}
