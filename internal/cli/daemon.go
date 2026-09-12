// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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

	env.printf("sshstate daemon running. Vault is locked; run: sshstate unlock\n")
	return d.Run(ctx)
}
