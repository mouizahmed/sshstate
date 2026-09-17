// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mouizahmed/sshstate/internal/activation"
	"github.com/mouizahmed/sshstate/internal/paths"
)

func platformManager() Manager { return systemd{} }

const (
	unitService = "sshstate.service"
	unitControl = "sshstate-control.socket"
	unitAgent   = "sshstate-agent.socket"
)

type systemd struct{}

func (systemd) Name() string { return "systemd" }

func unitDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "systemd", "user")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "systemd", "user")
}

func (systemd) DefinitionPath() string {
	dir := unitDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, unitService)
}

func RenderUnits(binary string, l paths.Layout) (map[string]string, error) {
	args := []string{
		binary, "daemon",
		"--data", l.Data,
		"--ssh-dir", l.SSH,
		"--runtime", l.Runtime,
		"--user-config", l.UserSSHConfig,
	}
	cmdline := make([]string, 0, len(args))
	for _, a := range args {
		q, err := execArg(a)
		if err != nil {
			return nil, err
		}
		cmdline = append(cmdline, q)
	}
	data, err := unitValue(l.Data)
	if err != nil {
		return nil, err
	}

	serviceUnit := "[Unit]\n" +
		"Description=sshstate SSH environment daemon\n" +
		"Documentation=https://github.com/mouizahmed/sshstate\n" +
		"\n[Service]\n" +
		"Type=exec\n" +
		"ExecStart=" + strings.Join(cmdline, " ") + "\n" +
		"WorkingDirectory=" + data + "\n" +
		"Restart=no\n"

	control, err := socketUnit("sshstate control socket", l.ControlSocket(), activation.NameControl)
	if err != nil {
		return nil, err
	}
	agent, err := socketUnit("sshstate agent socket", l.AgentSocket(), activation.NameAgent)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		unitService: serviceUnit,
		unitControl: control,
		unitAgent:   agent,
	}, nil
}

func socketUnit(description, path, name string) (string, error) {
	p, err := unitValue(path)
	if err != nil {
		return "", err
	}
	return "[Unit]\n" +
		"Description=" + description + "\n" +
		"\n[Socket]\n" +
		"Service=" + unitService + "\n" +
		"ListenStream=" + p + "\n" +
		"FileDescriptorName=" + name + "\n" +
		"SocketMode=0600\n" +
		"DirectoryMode=0700\n" +
		"RemoveOnStop=yes\n" +
		"\n[Install]\n" +
		"WantedBy=sockets.target\n", nil
}

func unitValue(s string) (string, error) {
	if strings.ContainsAny(s, "\n\r") {
		return "", fmt.Errorf("%q contains a newline and cannot appear in a systemd unit", s)
	}
	return strings.ReplaceAll(s, "%", "%%"), nil
}

func execArg(s string) (string, error) {
	v, err := unitValue(s)
	if err != nil {
		return "", err
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`, nil
}

func (d systemd) Install(binary string, l paths.Layout) error {
	dir := unitDir()
	if dir == "" {
		return fmt.Errorf("cannot resolve the systemd user unit directory")
	}
	if err := requireUserManager(); err != nil {
		return err
	}
	units, err := RenderUnits(binary, l)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	_ = d.down()
	for name, body := range units {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Join(dir, name), err)
		}
	}
	for _, sock := range []string{l.ControlSocket(), l.AgentSocket()} {
		if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale socket %s: %w", sock, err)
		}
	}
	if out, err := systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl --user daemon-reload: %w: %s", err, out)
	}
	if out, err := systemctl("enable", "--now", unitControl, unitAgent); err != nil {
		return fmt.Errorf("systemctl --user enable: %w: %s", err, out)
	}
	return nil
}

func (d systemd) Uninstall(l paths.Layout) error {
	dir := unitDir()
	if dir == "" {
		return fmt.Errorf("cannot resolve the systemd user unit directory")
	}
	if err := requireUserManager(); err != nil {
		return err
	}
	if err := d.down(); err != nil {
		return err
	}
	for _, name := range []string{unitService, unitControl, unitAgent} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", filepath.Join(dir, name), err)
		}
	}
	if out, err := systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl --user daemon-reload: %w: %s", err, out)
	}
	return nil
}

func (systemd) down() error {
	if out, err := systemctl("disable", "--now", unitControl, unitAgent); err != nil && !notLoaded(out) {
		return fmt.Errorf("systemctl --user disable: %w: %s", err, out)
	}
	if out, err := systemctl("stop", unitService); err != nil && !notLoaded(out) {
		return fmt.Errorf("systemctl --user stop: %w: %s", err, out)
	}
	return nil
}

func notLoaded(out string) bool {
	return strings.Contains(out, "not loaded") ||
		strings.Contains(out, "does not exist") ||
		strings.Contains(out, "No such file or directory")
}

func (systemd) Registered() (bool, error) {
	dir := unitDir()
	if dir == "" {
		return false, nil
	}
	_, err := os.Stat(filepath.Join(dir, unitService))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (systemd) Installed(l paths.Layout) (bool, error) {
	dir := unitDir()
	if dir == "" {
		return false, nil
	}
	body, err := os.ReadFile(filepath.Join(dir, unitControl))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	socket, err := unitValue(l.ControlSocket())
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(body), "\nListenStream="+socket+"\n"), nil
}

func requireUserManager() error {
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		return fmt.Errorf("no systemd user session here ($XDG_RUNTIME_DIR is unset); run the daemon in the foreground instead: sshstate daemon")
	}
	if out, err := systemctl("is-system-running"); err != nil && strings.TrimSpace(out) == "" {
		return fmt.Errorf("cannot reach the systemd user manager: %w", err)
	}
	return nil
}

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
