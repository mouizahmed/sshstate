// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
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
		return errors.New("usage: sshstate setup [--import ~/.ssh/config] [--kit path] [--label name]")
	}

	did := 0

	env.printf("Step 1 of 4: the vault.\n")
	st, statusErr := env.Client().Status(ctx)
	switch {
	case statusErr == nil:
		env.printf("  already done: vault %s\n", st.VaultID)
	case env.vaultExists():
		env.printf("  already done: the vault exists\n")
	default:
		env.printf("\n")
		if err := initVault(ctx, env, []string{"--kit", *kitPath, "--label", *label}, false); err != nil {
			return err
		}
		did++
	}

	env.printf("\nStep 2 of 4: the daemon.\n")
	mgr := service.For()
	switch {
	case statusErr == nil:
		env.printf("  already done: the daemon is running\n")
	case mgr == nil:
		env.printf("\nNo service manager ships for this platform, so the daemon runs in the\n")
		env.printf("foreground. Start it in another terminal, then run setup again:\n")
		env.printf("  sshstate daemon\n")
		return errors.New("setup needs a running daemon on this platform")
	default:
		if installed, err := mgr.Installed(); err == nil && installed {
			env.printf("  already done: registered with %s\n", mgr.Name())
		} else {
			env.printf("\n")
			if err := installService(env); err != nil {
				return err
			}
			did++
		}
	}

	env.printf("\nStep 3 of 4: unlocking.\n")
	st, err := env.Client().Status(ctx)
	if err != nil {
		return env.hint(err)
	}
	if st.Unlocked {
		env.printf("  already done: the vault is unlocked\n")
	} else {
		env.printf("\n")
		if err := runUnlock(ctx, env, nil); err != nil {
			return err
		}
		did++
	}

	env.printf("\nStep 4 of 4: your hosts.\n")
	if *importFrom != "" {
		if hasHostBlocks(*importFrom) {
			env.printf("\n")
			importArgs := []string{*importFrom, "--with-keys"}
			if sameFile(*importFrom, env.Layout.UserSSHConfig) {
				importArgs = append(importArgs, "--comment-source")
			}
			if err := runImport(ctx, env, importArgs); err != nil {
				return err
			}
			did++
		} else {
			env.printf("  already done: %s has no hosts left to import\n", *importFrom)
		}
	}

	installed, err := sshconfig.IsInstalled(env.Layout)
	if err != nil {
		return err
	}
	st, err = env.Client().Status(ctx)
	if err != nil {
		return env.hint(err)
	}
	switch {
	case installed:
		env.printf("  already done: the Include is active in %s\n", env.Layout.UserSSHConfig)
	case st.Hosts == 0:
		env.printf("\nNo hosts yet. Add a key and a host, then run setup again to finish:\n")
		env.printf("  sshstate add-key ~/.ssh/id_ed25519\n")
		env.printf("  sshstate add <alias> --hostname <host> --key <fingerprint-or-comment>\n")
		env.printf("  sshstate setup\n")
		env.printf("\nOr import the hosts you already have:\n")
		env.printf("  sshstate setup --import ~/.ssh/config\n")
		return nil
	default:
		env.printf("\n")
		if err := runInstall(ctx, env, nil); err != nil {
			return err
		}
		did++
	}

	if did == 0 {
		env.printf("\nThis machine is already set up.\n")
	} else {
		env.printf("\nDone. Try: ssh <alias>\n")
	}
	env.printf("See what it manages with: sshstate hosts\n")
	return nil
}

func hasHostBlocks(path string) bool {
	expanded, err := expandHome(path)
	if err != nil {
		return true
	}
	body, err := os.ReadFile(expanded)
	if err != nil {
		return true
	}
	hosts, problems := sshconfig.ParseImport(string(body))
	return len(hosts) > 0 || len(problems) > 0
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

func adoptIdentityFiles(ctx context.Context, env *Env, hosts []sshconfig.ImportedHost) error {
	seen := map[string]bool{}
	var paths []string
	for _, h := range hosts {
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
		return env.hint(err)
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

func sameFile(a, b string) bool {
	ea, err := expandHome(a)
	if err != nil {
		return false
	}
	eb, err := expandHome(b)
	if err != nil {
		return false
	}
	ra, err := filepath.Abs(ea)
	if err != nil {
		return false
	}
	rb, err := filepath.Abs(eb)
	if err != nil {
		return false
	}
	if ra == rb {
		return true
	}
	fa, err := os.Stat(ra)
	if err != nil {
		return false
	}
	fb, err := os.Stat(rb)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}
