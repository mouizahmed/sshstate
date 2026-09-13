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
		{"init", "create a vault on this device", runInit},
		{"confirm-recovery", "confirm a saved recovery kit for an existing vault", runConfirmRecovery},
		{"unlock", "unlock the vault for this session", runUnlock},
		{"lock", "lock the vault and drop keys from memory", runLock},
		{"status", "show vault and integration status", runStatus},
		{"add-key", "import an SSH private key into the vault", runAddKey},
		{"add", "add a managed host", runAdd},
		{"connect", "point this vault at a sync relay", runConnect},
		{"sync", "reconcile with the relay once", runSync},
		{"devices", "list the devices authorized to write", runDevices},
		{"revoke", "withdraw a device's authority", runRevoke},
		{"export", "write an encrypted backup", runExport},
		{"conflicts", "list edits preserved after a race", runConflicts},
		{"install", "activate the managed Include in ~/.ssh/config", runInstall},
		{"uninstall", "remove the managed Include, preserving vault data", runUninstall},
		{"doctor", "diagnose SSH integration problems", runDoctor},
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

func hint(err error) error {
	var api *control.APIError
	if !errors.As(err, &api) {
		if errors.Is(err, control.ErrDaemonUnavailable) {
			return fmt.Errorf("%w\nstart it with: sshstate daemon", err)
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
