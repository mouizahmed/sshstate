package sshconfig

import (
	"strings"
	"testing"
)

func FuzzParseImport(f *testing.F) {
	f.Add("Host a\n HostName 10.0.0.1\n")
	f.Add("Host *\n")
	f.Add("Host a\n Port =\n")
	f.Add("HostName=\"\n")
	f.Add("Host a\n ProxyJump b,c\n IdentityFile x\n")
	f.Add("=\n")
	f.Add("Host \"a b\"\n HostName h\n")

	f.Fuzz(func(t *testing.T, text string) {
		hosts, problems := ParseImport(text)
		for _, h := range hosts {
			if h.Alias == "" {
				t.Fatalf("a host with no alias was returned from %q", text)
			}
			if strings.ContainsAny(h.Alias, "*?") || strings.HasPrefix(h.Alias, "!") {
				t.Fatalf("pattern %q was returned as an alias", h.Alias)
			}
			if h.HostName == "" {
				t.Fatalf("host %q has no HostName but was returned without a problem", h.Alias)
			}
			if h.Port < 0 || h.Port > 65535 {
				t.Fatalf("host %q has port %d", h.Alias, h.Port)
			}
			if h.ProxyJump != nil && strings.ContainsAny(*h.ProxyJump, ",@:*?!") {
				t.Fatalf("host %q has ProxyJump %q", h.Alias, *h.ProxyJump)
			}
			if h.Line < 1 {
				t.Fatalf("host %q is reported at line %d", h.Alias, h.Line)
			}
		}
		for _, p := range problems {
			if p.Line < 1 {
				t.Fatalf("problem %q is reported at line %d", p.Text, p.Line)
			}
			if p.Text == "" {
				t.Fatalf("a problem was reported with no explanation")
			}
		}
	})
}
