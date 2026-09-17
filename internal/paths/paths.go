package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

type Layout struct {
	Data          string
	SSH           string
	UserSSHConfig string
	Runtime       string
}

func Default() (Layout, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Layout{}, fmt.Errorf("resolve home directory: %w", err)
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		data = filepath.Join(home, ".local", "share")
	}
	ssh := filepath.Join(home, ".ssh", "sshstate")
	return Layout{
		Data:          filepath.Join(data, "sshstate"),
		SSH:           ssh,
		UserSSHConfig: filepath.Join(home, ".ssh", "config"),
		Runtime:       ssh,
	}, nil
}

func (l Layout) Database() string { return filepath.Join(l.Data, "vault.db") }

func (l Layout) Config() string { return filepath.Join(l.SSH, "config") }

func (l Layout) PublicDir() string { return filepath.Join(l.SSH, "public") }

func (l Layout) KnownHosts() string { return filepath.Join(l.SSH, "known_hosts") }

func (l Layout) UserKnownHosts() string {
	return filepath.Join(filepath.Dir(l.UserSSHConfig), "known_hosts")
}

func (l Layout) CaptureFile() string { return filepath.Join(l.SSH, "known_hosts.capture") }

func (l Layout) AgentSocket() string { return filepath.Join(l.Runtime, "agent.sock") }

func (l Layout) ControlSocket() string { return filepath.Join(l.Runtime, "control.sock") }

func (l Layout) DaemonLock() string { return filepath.Join(l.Data, "daemon.lock") }
