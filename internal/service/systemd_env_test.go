//go:build linux

package service

import (
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/paths"
)

func TestUnitCarriesTheRegisteringShellsCertificateAndProxySettings(t *testing.T) {
	l := paths.Layout{Data: "/d", SSH: "/s", Runtime: "/s", UserSSHConfig: "/u/config"}
	units, err := RenderUnits("/bin/sshstate", l, map[string]string{
		"SSL_CERT_FILE": `/etc/corp/ca "certs".pem`,
		"HTTPS_PROXY":   "http://proxy.corp:3128/%path",
	})
	if err != nil {
		t.Fatal(err)
	}
	service := units[unitService]
	for _, want := range []string{
		"Environment=\"HTTPS_PROXY=http://proxy.corp:3128/%%path\"\n",
		"Environment=\"SSL_CERT_FILE=/etc/corp/ca \\\"certs\\\".pem\"\n",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("missing %q in:\n%s", want, service)
		}
	}
}
