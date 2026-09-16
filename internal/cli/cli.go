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
	Summary string
	Run     func(ctx context.Context, env *Env, args []string) error
}

func Commands() []Command {
	return []Command{
		{"setup", "first run: vault, service, unlock, and your hosts", runSetup},
		{"init", "create a vault on this device", runInit},
		{"confirm-recovery", "confirm a saved recovery kit for an existing vault", runConfirmRecovery},
		{"unlock", "unlock the vault for this session", runUnlock},
		{"lock", "lock the vault and drop keys from memory", runLock},
		{"status", "show vault and integration status", runStatus},
		{"add-key", "import an SSH private key into the vault", runAddKey},
		{"add", "add a managed host", runAdd},
		{"edit", "change a managed host", runEdit},
		{"remove", "remove a managed host", runRemove},
		{"hosts", "list managed hosts", runHosts},
		{"keys", "list keys in the vault", runKeys},
		{"remove-key", "remove a key from the vault", runRemoveKey},
		{"import", "import hosts from an existing SSH config", runImport},
		{"trust", "review and approve host-key observations", runTrust},
		{"connect", "point this vault at a sync relay", runConnect},
		{"pair", "enrol this machine into an existing vault", runPair},
		{"approve", "authorize another machine to join this vault", runApprove},
		{"sync", "reconcile with the relay once", runSync},
		{"devices", "list the devices authorized to write", runDevices},
		{"revoke", "withdraw a device's authority", runRevoke},
		{"export", "write an encrypted backup", runExport},
		{"restore", "rebuild this vault from an export and the recovery kit", runRestore},
		{"recover", "rebuild this vault from the relay using the recovery kit", runRecover},
		{"conflicts", "list edits preserved after a race", runConflicts},
		{"resolve", "apply a preserved edit to the current version", runResolve},
		{"install", "activate the managed Include in ~/.ssh/config", runInstall},
		{"uninstall", "remove the managed Include, preserving vault data", runUninstall},
		{"doctor", "diagnose SSH integration problems", runDoctor},
		{"service", "register the daemon with the platform service manager", runService},
		{"daemon", "run the daemon in the foreground", runDaemon},
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
