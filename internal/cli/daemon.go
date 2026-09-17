// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mouizahmed/sshstate/internal/activation"
	"github.com/mouizahmed/sshstate/internal/daemon"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func runDaemon(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "daemon")
	verbose := fs.Bool("v", false, "log control requests")
	dataDir := fs.String("data", "", "vault data directory (defaults to the XDG data location)")
	sshDir := fs.String("ssh-dir", "", "generated SSH directory (defaults to ~/.ssh/sshstate)")
	runtimeDir := fs.String("runtime", "", "socket directory (defaults to the generated SSH directory)")
	userConfig := fs.String("user-config", "", "path to the user's SSH config (defaults to ~/.ssh/config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir != "" {
		env.Layout.Data = *dataDir
	}
	if *sshDir != "" {
		env.Layout.SSH = *sshDir
	}
	if *runtimeDir != "" {
		env.Layout.Runtime = *runtimeDir
	}
	if *userConfig != "" {
		env.Layout.UserSSHConfig = *userConfig
	}

	if err := refuseIfServiceOwnsTheSockets(env); err != nil {
		return err
	}

	store, err := vault.OpenStore(env.Layout.Database())
	if err != nil {
		return err
	}
	defer store.Close()

	mgr, err := vault.NewManager(store)
	if err != nil {
		if errors.Is(err, vault.ErrNotInitialized) {
			return err
		}
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(env.Stderr, &slog.HandlerOptions{Level: level}))

	d := daemon.New(mgr, env.Layout, log)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	d.OnListening(func() {
		env.printf("sshstate daemon running. Vault is locked; run: sshstate unlock\n")
	})
	return d.Run(ctx)
}

func refuseIfServiceOwnsTheSockets(env *Env) error {
	if activation.Available() {
		return nil
	}
	mgr := env.services()
	if mgr == nil {
		return nil
	}
	installed, err := mgr.Installed(env.Layout)
	if err != nil || !installed {
		return nil
	}
	return fmt.Errorf(`the %s service owns this vault's sockets, and a foreground daemon would replace them

That breaks on-demand start: the service would keep watching sockets this
process had unlinked, and ssh would find nothing there.

  sshstate status     to use the service, which starts on demand
  sshstate uninstall  to unregister it and run in the foreground instead`, mgr.Name())
}
