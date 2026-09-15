// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package sshconfig

import (
	"strings"
	"testing"
)

func problemText(ps []ImportProblem) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString(p.String())
		b.WriteString("\n")
	}
	return b.String()
}

func TestImportsTheSupportedSubset(t *testing.T) {
	hosts, problems := ParseImport(`
# a comment
Host bastion
    HostName 10.0.0.1
    User ubuntu

Host prod
    HostName=10.0.0.5
    User ubuntu
    Port 2222
    ProxyJump bastion
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile ~/.ssh/id_rsa
`)
	if len(problems) != 0 {
		t.Fatalf("supported input produced problems:\n%s", problemText(problems))
	}
	if len(hosts) != 2 {
		t.Fatalf("parsed %d hosts", len(hosts))
	}
	if hosts[0].Alias != "bastion" || hosts[0].HostName != "10.0.0.1" || hosts[0].User != "ubuntu" {
		t.Fatalf("bastion parsed as %+v", hosts[0])
	}
	if hosts[0].Port != 0 {
		t.Fatalf("an omitted Port became %d instead of staying unset for the caller to default", hosts[0].Port)
	}
	p := hosts[1]
	if p.Alias != "prod" || p.HostName != "10.0.0.5" || p.Port != 2222 {
		t.Fatalf("prod parsed as %+v", p)
	}
	if p.ProxyJump == nil || *p.ProxyJump != "bastion" {
		t.Fatalf("ProxyJump is %v", p.ProxyJump)
	}
	if len(p.IdentityFiles) != 2 || p.IdentityFiles[0] != "~/.ssh/id_ed25519" || p.IdentityFiles[1] != "~/.ssh/id_rsa" {
		t.Fatalf("IdentityFile order is %v", p.IdentityFiles)
	}
	if p.Line != 7 {
		t.Fatalf("prod's block is reported at line %d", p.Line)
	}
}

func TestProxyJumpNoneIsNoJumpHost(t *testing.T) {
	hosts, problems := ParseImport("Host a\n HostName h\n ProxyJump none\n")
	if len(problems) != 0 {
		t.Fatalf("%s", problemText(problems))
	}
	if hosts[0].ProxyJump != nil {
		t.Fatalf("ProxyJump none became %q", *hosts[0].ProxyJump)
	}
}

func TestRejectsWhatIsNotInTheSubset(t *testing.T) {
	cases := []struct {
		name, text, want string
		line             int
	}{
		{"wildcard", "Host *\n HostName h\n", "wildcard", 1},
		{"question mark", "Host web?\n HostName h\n", "wildcard", 1},
		{"negated", "Host !a\n HostName h\n", "negated", 1},
		{"several patterns", "Host a b\n HostName h\n", "one literal alias per block", 1},
		{"match", "Match host a\n HostName h\n", "match exec", 1},
		{"include", "Include other\n", "Include is not imported", 1},
		{"proxycommand", "Host a\n HostName h\n ProxyCommand nc %h %p\n", "runs a command", 3},
		{"localcommand", "Host a\n HostName h\n LocalCommand id\n", "runs a command", 3},
		{"certificate", "Host a\n HostName h\n CertificateFile c\n", "certificates", 3},
		{"unknown directive", "Host a\n HostName h\n Compression yes\n", "not in the v1 import subset", 3},
		{"directive before host", "HostName h\n", "before any Host block", 1},
		{"bad port", "Host a\n HostName h\n Port 70000\n", "between 1 and 65535", 3},
		{"port not a number", "Host a\n HostName h\n Port ssh\n", "between 1 and 65535", 3},
		{"chained jump", "Host a\n HostName h\n ProxyJump b,c\n", "chains several hosts", 3},
		{"jump with user", "Host a\n HostName h\n ProxyJump me@b\n", "carries a user or port", 3},
		{"jump with port", "Host a\n HostName h\n ProxyJump b:22\n", "carries a user or port", 3},
		{"no hostname", "Host a\n User u\n", "has no HostName", 1},
		{"duplicate host", "Host a\n HostName h\nHost a\n HostName i\n", "already defined on line 1", 3},
		{"duplicate directive", "Host a\n HostName h\n HostName i\n", "set twice", 3},
		{"unbalanced quote", "Host \"a\n", "unbalanced quote", 1},
		{"empty quoted alias", "Host \"\"\n HostName h\n", "empty alias", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, problems := ParseImport(tc.text)
			if len(problems) == 0 {
				t.Fatalf("%q was accepted", tc.text)
			}
			found := false
			for _, p := range problems {
				if strings.Contains(strings.ToLower(p.Text), strings.ToLower(tc.want)) {
					found = true
					if p.Line != tc.line {
						t.Errorf("reported at line %d, expected %d: %s", p.Line, tc.line, p.Text)
					}
				}
			}
			if !found {
				t.Fatalf("no problem mentioned %q:\n%s", tc.want, problemText(problems))
			}
		})
	}
}

func TestACaseDifferingAliasCollides(t *testing.T) {
	_, problems := ParseImport("Host prod\n HostName h\nHost PROD\n HostName i\n")
	if len(problems) == 0 {
		t.Fatal("two aliases differing only by case were both accepted")
	}
}

func TestKeywordsAreCaseInsensitive(t *testing.T) {
	hosts, problems := ParseImport("HOST a\n hostname 10.0.0.1\n PORT 22\n")
	if len(problems) != 0 {
		t.Fatalf("%s", problemText(problems))
	}
	if hosts[0].HostName != "10.0.0.1" || hosts[0].Port != 22 {
		t.Fatalf("parsed as %+v", hosts[0])
	}
}

func TestQuotedAndCommentedValues(t *testing.T) {
	hosts, problems := ParseImport("Host a\n HostName \"10.0.0.1\" # inline\n IdentityFile \"/path/with space/key\"\n")
	if len(problems) != 0 {
		t.Fatalf("%s", problemText(problems))
	}
	if hosts[0].HostName != "10.0.0.1" {
		t.Fatalf("HostName is %q", hosts[0].HostName)
	}
	if hosts[0].IdentityFiles[0] != "/path/with space/key" {
		t.Fatalf("IdentityFile is %q", hosts[0].IdentityFiles[0])
	}
}

func TestAFileWithAnyProblemImportsNothing(t *testing.T) {
	hosts, problems := ParseImport("Host good\n HostName 10.0.0.1\nHost bad\n Compression yes\n")
	if len(problems) == 0 {
		t.Fatal("the bad block was accepted")
	}
	if len(hosts) != 0 {
		t.Fatalf("%d hosts were returned alongside problems; §3.2 forbids a partial import", len(hosts))
	}
}

func TestEveryProblemIsReportedNotJustTheFirst(t *testing.T) {
	_, problems := ParseImport("Host a\n HostName h\n Compression yes\n Cipher aes\n")
	if len(problems) != 2 {
		t.Fatalf("expected both bad lines, got:\n%s", problemText(problems))
	}
}
