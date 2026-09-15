// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func runSetup(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "setup")
	kitPath := fs.String("kit", defaultKitPath(), "where to write the recovery kit")
	label := fs.String("label", defaultDeviceLabel(), "label for this device")
	importFrom := fs.String("import", "", "an SSH config to import hosts from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: sshstate setup [--kit path] [--label name] [--import ~/.ssh/config]")
	}

	store, err := vault.OpenStore(env.Layout.Database())
	if err != nil {
		return err
	}
	initialized, err := store.Initialized()
	store.Close()
	if err != nil {
		return err
	}
	if initialized {
		return fmt.Errorf("a vault already exists at %s; setup is for a new machine", env.Layout.Database())
	}

	env.printf("Step 1 of 4: creating the vault.\n\n")
	if err := initVault(ctx, env, []string{"--kit", *kitPath, "--label", *label}, false); err != nil {
		return err
	}

	env.printf("\nStep 2 of 4: starting the daemon.\n\n")
	if service.For() == nil {
		env.printf("No service manager ships for this platform, so the daemon runs in the\n")
		env.printf("foreground. Start it in another terminal and run setup again:\n")
		env.printf("  sshstate daemon\n")
		return errors.New("setup needs a running daemon on this platform")
	}
	if err := installService(env); err != nil {
		return err
	}

	env.printf("\nStep 3 of 4: unlocking.\n\n")
	if err := runUnlock(ctx, env, nil); err != nil {
		return err
	}

	env.printf("\nStep 4 of 4: your hosts.\n\n")
	if *importFrom != "" {
		if err := adoptIdentityFiles(ctx, env, *importFrom); err != nil {
			return err
		}
		if err := runImport(ctx, env, []string{*importFrom}); err != nil {
			return err
		}
		if err := runInstall(ctx, env, nil); err != nil {
			return err
		}
	} else {
		env.printf("Nothing imported. Add a key and a host, then activate the Include:\n")
		env.printf("  sshstate add-key ~/.ssh/id_ed25519\n")
		env.printf("  sshstate add <alias> --hostname <host> --key <fingerprint-or-comment>\n")
		env.printf("  sshstate install\n")
		return nil
	}

	env.printf("\nDone. Try: ssh <alias>\n")
	env.printf("Check anything unexpected with: sshstate doctor\n")
	return nil
}

func defaultKitPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "sshstate-recovery-kit.txt"
	}
	return filepath.Join(home, "sshstate-recovery-kit.txt")
}

func runService(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "service")
	remove := fs.Bool("remove", false, "unregister the service instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: sshstate service [--remove]")
	}
	mgr := service.For()
	if mgr == nil {
		return errors.New("no service manager integration ships for this platform; use: sshstate daemon")
	}
	if *remove {
		installed, err := mgr.Installed()
		if err != nil {
			return err
		}
		if !installed {
			env.printf("Not registered with %s.\n", mgr.Name())
			return nil
		}
		if err := mgr.Uninstall(env.Layout); err != nil {
			return err
		}
		env.printf("Unregistered from %s. Vault data is untouched.\n", mgr.Name())
		env.printf("Run the daemon yourself with: sshstate daemon\n")
		return nil
	}
	if err := installService(env); err != nil {
		return err
	}
	return nil
}

func adoptIdentityFiles(ctx context.Context, env *Env, configPath string) error {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}
	parsed, problems := sshconfig.ParseImport(string(body))
	if len(problems) > 0 {
		return importRefusal(env, configPath, problems)
	}
	seen := map[string]bool{}
	var paths []string
	for _, h := range parsed {
		for _, file := range h.IdentityFiles {
			if !seen[file] {
				seen[file] = true
				paths = append(paths, file)
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}
	keys, err := env.Client().Keys(ctx)
	if err != nil {
		return hint(err)
	}
	have := map[string]bool{}
	for _, k := range keys {
		have[k.Fingerprint] = true
	}
	for _, file := range paths {
		fingerprint, err := identityFingerprint(file)
		if err != nil {
			env.warnf("skipping IdentityFile %s: %v\n", file, err)
			continue
		}
		if have[fingerprint] {
			continue
		}
		expanded, err := expandHome(file)
		if err != nil {
			return err
		}
		env.printf("Importing the key %s references.\n", file)
		if err := runAddKey(ctx, env, []string{expanded}); err != nil {
			return err
		}
		have[fingerprint] = true
	}
	return nil
}
