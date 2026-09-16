// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/paths"
	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/vault"
)

type Env struct {
	Layout      paths.Layout
	Stdout      io.Writer
	Stderr      io.Writer
	ReadSecret  func(prompt string) ([]byte, error)
	ReadLine    func(prompt string) (string, error)
	Interactive bool
}

type Command struct {
	Name    string
	Group   string
	Args    string
	Summary string
	Run     func(ctx context.Context, env *Env, args []string) error
}

func Commands() []Command {
	return []Command{
		{"setup", GroupStart, "[--import ~/.ssh/config] [--kit path] [--label name]", "set up this machine, or finish setting it up", runSetup},
		{"status", GroupStart, "", "show what sshstate is doing on this machine", runStatus},
		{"unlock", GroupStart, "[--password-fd n]", "unlock the vault so ssh can use your keys", runUnlock},
		{"lock", GroupStart, "", "lock the vault and drop keys from memory", runLock},
		{"doctor", GroupStart, "", "check that ssh is using sshstate correctly", runDoctor},

		{"hosts", GroupHosts, "", "list managed hosts", runHosts},
		{"add", GroupHosts, "<alias> --hostname <host> [--user name] [--port n] [--jump alias] [--key key,...]", "add a managed host", runAdd},
		{"edit", GroupHosts, "<alias> [--alias new] [--hostname host] [--user name] [--port n] [--jump alias|none] [--key key,...]", "change a managed host", runEdit},
		{"remove", GroupHosts, "<alias> [--yes]", "remove a managed host", runRemove},
		{"keys", GroupHosts, "", "list keys in the vault", runKeys},
		{"add-key", GroupHosts, "<private-key-file> [--comment text]", "import an SSH private key into the vault", runAddKey},
		{"remove-key", GroupHosts, "<key> [--yes]", "remove a key from the vault", runRemoveKey},
		{"import", GroupHosts, "<ssh-config> [--with-keys] [--comment-source] [--dry-run]", "import hosts from an existing SSH config", runImport},
		{"trust", GroupHosts, "[<id>...] [--all]", "review and approve host keys seen on first connection", runTrust},

		{"connect", GroupMachines, "<relay-url> [--bootstrap-secret file]", "connect this vault to a relay so other machines can join", runConnect},
		{"pair", GroupMachines, "<relay-url> <vault-id> [--label name]", "join this machine to a vault on another machine", runPair},
		{"approve", GroupMachines, "<session-id>", "let another machine join this vault", runApprove},
		{"sync", GroupMachines, "", "sync with the relay now", runSync},
		{"devices", GroupMachines, "", "list the machines that can change this vault", runDevices},
		{"revoke", GroupMachines, "<device-id> [--yes]", "remove a machine from this vault", runRevoke},
		{"conflicts", GroupMachines, "", "list edits kept aside when two machines changed the same thing", runConflicts},
		{"resolve", GroupMachines, "<conflict-id> [--resurrect]", "apply an edit that was kept aside", runResolve},

		{"export", GroupBackup, "<path>", "write an encrypted backup", runExport},
		{"restore", GroupBackup, "<export-file> --kit <kit-file> [--label name]", "rebuild this vault from a backup and the recovery kit", runRestore},
		{"recover", GroupBackup, "<relay-url> <vault-id> --kit <kit-file> [--label name]", "rebuild this vault from the relay and the recovery kit", runRecover},
		{"confirm-recovery", GroupBackup, "[--kit path]", "confirm you saved the recovery kit", runConfirmRecovery},

		{"init", GroupAdvanced, "[--kit path] [--label name]", "create a vault without the rest of setup", runInit},
		{"install", GroupAdvanced, "[--service] [--import-trust | --skip-trust]", "add the sshstate Include to ~/.ssh/config", runInstall},
		{"uninstall", GroupAdvanced, "[--purge] [--yes]", "remove the sshstate Include, keeping the vault", runUninstall},
		{"service", GroupAdvanced, "[--remove]", "start the daemon at login with the system service manager", runService},
		{"daemon", GroupAdvanced, "[--data dir] [--ssh-dir dir] [--runtime dir] [--user-config path] [-v]", "run the daemon in the foreground", runDaemon},
	}
}

func (e *Env) Client() *control.Client { return control.NewClient(e.Layout.ControlSocket()) }

func (e *Env) printf(format string, args ...any) {
	fmt.Fprintf(e.Stdout, format, args...)
}

func (e *Env) warnf(format string, args ...any) {
	fmt.Fprintf(e.Stderr, format, args...)
}

func (e *Env) vaultExists() bool {
	info, err := os.Stat(e.Layout.Database())
	if err != nil || info.Size() == 0 {
		return false
	}
	store, err := vault.OpenStore(e.Layout.Database())
	if err != nil {
		return false
	}
	defer store.Close()
	ok, err := store.Initialized()
	return err == nil && ok
}

func (e *Env) daemonUnavailable() error {
	if !e.vaultExists() {
		return errors.New("sshstate is not set up on this machine\nrun: sshstate setup")
	}
	mgr := service.For()
	if mgr == nil {
		return errors.New("the sshstate daemon is not running\nstart it with: sshstate daemon")
	}
	if installed, err := mgr.Installed(); err == nil && installed {
		return fmt.Errorf("the %s service is registered but did not answer\nre-register it with: sshstate service", mgr.Name())
	}
	return errors.New("sshstate is not running on this machine\nfinish setting it up with: sshstate setup")
}

func (e *Env) hint(err error) error {
	var api *control.APIError
	if !errors.As(err, &api) {
		if errors.Is(err, control.ErrDaemonUnavailable) {
			return e.daemonUnavailable()
		}
		return err
	}
	switch api.Code {
	case control.CodeLocked:
		return fmt.Errorf("%s\nrun: sshstate unlock", api.Message)
	case control.CodeRecoveryUnconfirmed:
		return errors.New(api.Message)
	case control.CodeNotInitialized:
		return fmt.Errorf("%s", api.Message)
	default:
		return api
	}
}

func withBypass(err error, flag string) error {
	if errors.Is(err, errNoAnswer) {
		return fmt.Errorf("%w; pass %s to answer without a prompt", err, flag)
	}
	return err
}

func (e *Env) confirm(question string) (bool, error) {
	answer, err := e.ReadLine(question + " [y/N]: ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func DefaultEnv() (*Env, error) {
	layout, err := paths.Default()
	if err != nil {
		return nil, err
	}
	return &Env{
		Layout:      layout,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		ReadSecret:  readSecret,
		ReadLine:    readLine,
		Interactive: term.IsTerminal(int(os.Stdin.Fd())),
	}, nil
}

func isLocked(err error) bool {
	var api *control.APIError
	return errors.As(err, &api) && api.Code == control.CodeLocked
}
