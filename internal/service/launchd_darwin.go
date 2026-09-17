//go:build darwin

package service

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mouizahmed/sshstate/internal/activation"
	"github.com/mouizahmed/sshstate/internal/paths"
)

func platformManager() Manager { return launchd{} }

type launchd struct{}

func (launchd) Name() string { return "launchd" }

func (launchd) DefinitionPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist")
}

func RenderPlist(binary string, l paths.Layout, env map[string]string) (string, error) {
	def := plist{
		Environment: env,
		Label:       Label,
		ProgramArguments: []string{
			binary, "daemon",
			"--data", l.Data,
			"--ssh-dir", l.SSH,
			"--runtime", l.Runtime,
			"--user-config", l.UserSSHConfig,
		},
		RunAtLoad: false,
		Sockets: map[string]socket{
			activation.NameControl: {Path: l.ControlSocket(), Mode: 0o600},
			activation.NameAgent:   {Path: l.AgentSocket(), Mode: 0o600},
		},
		WorkingDirectory: l.Data,
	}
	return def.render()
}

type plist struct {
	Environment      map[string]string
	Label            string
	ProgramArguments []string
	RunAtLoad        bool
	Sockets          map[string]socket
	WorkingDirectory string
}

type socket struct {
	Path string
	Mode int
}

func (p plist) render() (string, error) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	fmt.Fprintf(&b, "  <key>Label</key>\n  <string>%s</string>\n", escape(p.Label))
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, arg := range p.ProgramArguments {
		fmt.Fprintf(&b, "    <string>%s</string>\n", escape(arg))
	}
	b.WriteString("  </array>\n")
	fmt.Fprintf(&b, "  <key>RunAtLoad</key>\n  <%t/>\n", p.RunAtLoad)
	fmt.Fprintf(&b, "  <key>WorkingDirectory</key>\n  <string>%s</string>\n", escape(p.WorkingDirectory))
	if len(p.Environment) > 0 {
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for _, name := range sortedNames(p.Environment) {
			fmt.Fprintf(&b, "    <key>%s</key>\n    <string>%s</string>\n", escape(name), escape(p.Environment[name]))
		}
		b.WriteString("  </dict>\n")
	}
	b.WriteString("  <key>Sockets</key>\n  <dict>\n")
	for _, name := range []string{activation.NameAgent, activation.NameControl} {
		s, ok := p.Sockets[name]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "    <key>%s</key>\n    <dict>\n", escape(name))
		fmt.Fprintf(&b, "      <key>SockPathName</key>\n      <string>%s</string>\n", escape(s.Path))
		fmt.Fprintf(&b, "      <key>SockPathMode</key>\n      <integer>%d</integer>\n", s.Mode)
		b.WriteString("      <key>SockFamily</key>\n      <string>Unix</string>\n")
		b.WriteString("      <key>SockType</key>\n      <string>stream</string>\n")
		b.WriteString("    </dict>\n")
	}
	b.WriteString("  </dict>\n</dict>\n</plist>\n")
	return b.String(), nil
}

func escape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return ""
	}
	return b.String()
}

func (d launchd) Install(binary string, l paths.Layout) error {
	path := d.DefinitionPath()
	if path == "" {
		return fmt.Errorf("cannot resolve ~/Library/LaunchAgents")
	}
	body, err := RenderPlist(binary, l, Environment())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	for _, dir := range []string{l.Data, l.SSH, l.Runtime} {
		if err := ownDirectory(dir, os.Getuid()); err != nil {
			return err
		}
	}
	_ = d.bootout()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	for _, sock := range []string{l.ControlSocket(), l.AgentSocket()} {
		if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale socket %s: %w", sock, err)
		}
	}
	out, err := exec.Command("launchctl", "bootstrap", domain(), path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ownDirectory(dir string, uid int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != uid {
		return fmt.Errorf("%s belongs to uid %d, not to you, so the daemon could not write there\n"+
			"remove it with: sudo rm -rf %s\nthen run this again", dir, st.Uid, dir)
	}
	return nil
}

func (d launchd) Uninstall(l paths.Layout) error {
	if err := d.bootout(); err != nil {
		return err
	}
	path := d.DefinitionPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func (d launchd) bootout() error {
	out, err := exec.Command("launchctl", "bootout", domain()+"/"+Label).CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(out))
	if strings.Contains(text, "No such process") || strings.Contains(text, "not find") {
		return nil
	}
	return fmt.Errorf("launchctl bootout: %w: %s", err, text)
}

func (d launchd) Registered() (bool, error) {
	path := d.DefinitionPath()
	if path == "" {
		return false, nil
	}
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (d launchd) Installed(l paths.Layout) (bool, error) {
	path := d.DefinitionPath()
	if path == "" {
		return false, nil
	}
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.Contains(string(body), "<string>"+escape(l.ControlSocket())+"</string>"), nil
}

func domain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }
