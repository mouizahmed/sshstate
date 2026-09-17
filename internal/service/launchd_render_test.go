//go:build darwin

package service_test

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/paths"
	"github.com/mouizahmed/sshstate/internal/service"
)

func testLayout() paths.Layout {
	return paths.Layout{
		Data:          "/tmp/d",
		SSH:           "/tmp/s",
		UserSSHConfig: "/tmp/u/config",
		Runtime:       "/tmp/r",
	}
}

func TestPlistIsWellFormedAndPinsTheLayout(t *testing.T) {
	l := testLayout()
	body, err := service.RenderPlist("/usr/local/bin/sshstate", l, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal([]byte(body), new(struct {
		XMLName xml.Name `xml:"plist"`
	})); err != nil {
		t.Fatalf("the plist is not well-formed XML: %v\n%s", err, body)
	}
	for _, want := range []string{
		service.Label,
		"/usr/local/bin/sshstate",
		"--data", l.Data,
		"--ssh-dir", l.SSH,
		"--runtime", l.Runtime,
		"--user-config", l.UserSSHConfig,
		l.ControlSocket(),
		l.AgentSocket(),
		"SockPathMode",
		"<integer>384</integer>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the plist omits %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "<key>RunAtLoad</key>\n  <false/>") {
		t.Errorf("the agent would start at load rather than on demand:\n%s", body)
	}
}

func TestPlistIsByteStableAcrossRenders(t *testing.T) {
	l := testLayout()
	first, err := service.RenderPlist("/bin/sshstate", l, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := service.RenderPlist("/bin/sshstate", l, nil)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatal("two renders of the same layout differ; map iteration is leaking into the file")
		}
	}
}

func TestPlistEscapesPathsThatWouldBreakTheXML(t *testing.T) {
	l := paths.Layout{
		Data:          `/tmp/a&b`,
		SSH:           `/tmp/<s>`,
		UserSSHConfig: `/tmp/"q"/config`,
		Runtime:       `/tmp/r`,
	}
	body, err := service.RenderPlist(`/bin/ssh"state`, l, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal([]byte(body), new(struct {
		XMLName xml.Name `xml:"plist"`
	})); err != nil {
		t.Fatalf("an awkward path produced invalid XML: %v\n%s", err, body)
	}
	if strings.Contains(body, "/tmp/<s>") {
		t.Errorf("a path with angle brackets was written raw:\n%s", body)
	}
	if strings.Contains(body, "/tmp/a&b") {
		t.Errorf("a path with an ampersand was written raw:\n%s", body)
	}
}

func TestDefinitionPathIsUnderLaunchAgents(t *testing.T) {
	mgr := service.For()
	if mgr == nil {
		t.Fatal("no service manager on darwin")
	}
	if mgr.Name() != "launchd" {
		t.Fatalf("service manager is %q on darwin", mgr.Name())
	}
	p := mgr.DefinitionPath()
	if !strings.Contains(p, "Library/LaunchAgents") {
		t.Fatalf("the definition path is %q", p)
	}
	if !strings.HasSuffix(p, service.Label+".plist") {
		t.Fatalf("the definition is not named after the label: %q", p)
	}
}

func TestPlistCarriesTheRegisteringShellsCertificateAndProxySettings(t *testing.T) {
	l := paths.Layout{Data: "/d", SSH: "/s", Runtime: "/s", UserSSHConfig: "/u/config"}
	body, err := service.RenderPlist("/bin/sshstate", l, map[string]string{
		"SSL_CERT_FILE": "/etc/corp/ca & certs.pem",
		"HTTPS_PROXY":   "http://proxy.corp:3128",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal([]byte(body), new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("the plist is not well-formed XML: %v\n%s", err, body)
	}
	want := "<key>EnvironmentVariables</key>\n  <dict>\n    <key>HTTPS_PROXY</key>\n    <string>http://proxy.corp:3128</string>\n    <key>SSL_CERT_FILE</key>\n    <string>/etc/corp/ca &amp; certs.pem</string>\n  </dict>"
	if !strings.Contains(body, want) {
		t.Fatalf("the environment is missing or unescaped:\n%s", body)
	}
}
