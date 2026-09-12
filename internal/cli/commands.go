// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func newFlagSet(env *Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet("sshstate "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

func splitPositional(args []string, n int) (positional, rest []string) {
	for len(args) > 0 && len(positional) < n && !strings.HasPrefix(args[0], "-") {
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional, args
}

func runInit(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "init")
	kitPath := fs.String("kit", "", "write the recovery kit to this path instead of printing it")
	label := fs.String("label", defaultDeviceLabel(), "label for this device")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := vault.OpenStore(env.Layout.Database())
	if err != nil {
		return err
	}
	defer store.Close()

	if initialized, err := store.Initialized(); err != nil {
		return err
	} else if initialized {
		return fmt.Errorf("a vault already exists at %s", env.Layout.Database())
	}

	password, err := env.ReadSecret("New device unlock password: ")
	if err != nil {
		return err
	}
	defer clear(password)
	again, err := env.ReadSecret("Repeat password: ")
	if err != nil {
		return err
	}
	defer clear(again)
	if string(password) != string(again) {
		return errors.New("passwords do not match")
	}

	mgr, kit, err := vault.Init(store, vault.InitOptions{Password: password, DeviceLabel: *label})
	if err != nil {
		return err
	}

	env.printf("Vault %s created for device %s.\n\n", mgr.VaultID(), mgr.DeviceID())
	if *kitPath != "" {
		if err := os.WriteFile(*kitPath, []byte(kit.Marshal()), 0o600); err != nil {
			return fmt.Errorf("write recovery kit: %w", err)
		}
		env.printf("Recovery kit written to %s (mode 0600).\n", *kitPath)
	} else {
		env.printf("%s\n", kit.Marshal())
	}
	env.printf("\nSave this kit offline now. It is the only way back into this vault\n")
	env.printf("if you lose every enrolled device, and it is not stored anywhere else.\n\n")

	for attempt := 0; attempt < 3; attempt++ {
		answer, err := env.ReadLine(fmt.Sprintf("Type the kit's checksum (%d characters) to confirm you saved it: ", vault.KitChecksumChars))
		if err != nil {
			return err
		}
		if err := mgr.ConfirmRecoveryKit(strings.TrimSpace(strings.ToUpper(answer)), kit); err == nil {
			env.printf("\nRecovery kit confirmed. The vault is unlocked and ready.\n")
			env.printf("Next: sshstate daemon, then sshstate add-key ~/.ssh/id_ed25519\n")
			return nil
		}
		env.warnf("That does not match. ")
	}
	return errors.New("recovery kit not confirmed; run sshstate init again after saving the kit")
}

func defaultDeviceLabel() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "device"
	}
	return host
}

func runUnlock(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "unlock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	password, err := env.ReadSecret("Device unlock password: ")
	if err != nil {
		return err
	}
	defer clear(password)
	st, err := env.Client().Unlock(ctx, string(password))
	if err != nil {
		return hint(err)
	}
	env.printf("Unlocked. Idle expiry %s, hard expiry %s.\n",
		st.IdleExpiresAt.Local().Format(time.Kitchen),
		st.HardExpiresAt.Local().Format(time.Kitchen))
	return nil
}

func runLock(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "lock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := env.Client().Lock(ctx); err != nil {
		return hint(err)
	}
	env.printf("Locked. Keys are out of daemon memory.\n")
	env.printf("SSH sessions already authenticated are unaffected.\n")
	return nil
}

func runStatus(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := env.Client().Status(ctx)
	if err != nil {
		return hint(err)
	}
	state := "locked"
	if st.Unlocked {
		state = "unlocked"
	}
	env.printf("vault        %s\n", st.VaultID)
	env.printf("device       %s", st.DeviceID)
	if st.DeviceLabel != "" {
		env.printf(" (%s)", st.DeviceLabel)
	}
	env.printf("\nstate        %s\n", state)
	if st.Unlocked {
		env.printf("             idle expiry %s, hard expiry %s\n",
			st.IdleExpiresAt.Local().Format(time.Kitchen),
			st.HardExpiresAt.Local().Format(time.Kitchen))
	}
	env.printf("key epoch    %s\n", st.KeyEpoch)
	env.printf("hosts        %d\n", st.Hosts)
	env.printf("keys         %d\n", st.Keys)
	env.printf("known hosts  %d\n", st.KnownHosts)
	env.printf("pending      %d\n", st.Pending)
	env.printf("config       %s\n", st.ConfigPath)
	if st.ConfigInstalled {
		env.printf("include      active in ~/.ssh/config\n")
	} else {
		env.printf("include      not installed (run: sshstate install)\n")
	}
	env.printf("agent socket %s\n", st.AgentSocket)
	if !st.RecoveryConfirmed {
		env.warnf("\nThe recovery kit has not been confirmed; the vault will refuse changes.\n")
	}
	if !st.Unlocked {
		env.printf("\nThe vault is locked, so the agent offers no identities.\n")
		env.printf("Run: sshstate unlock\n")
	}
	return nil
}

func runAddKey(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "add-key")
	comment := fs.String("comment", "", "comment to store with the key (defaults to the adjacent .pub file's comment)")
	positional, rest := splitPositional(args, 1)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return errors.New("usage: sshstate add-key /path/to/private_key")
	}
	path := positional[0]
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	if *comment == "" {
		*comment = commentFromPublicFile(path)
	}

	req := control.AddKeyRequest{PrivateKey: string(raw), Comment: *comment}
	key, err := env.Client().AddKey(ctx, req)
	if err != nil {
		var api *control.APIError
		if errors.As(err, &api) && strings.Contains(api.Message, "passphrase protected") {
			passphrase, perr := env.ReadSecret(fmt.Sprintf("Passphrase for %s: ", path))
			if perr != nil {
				return perr
			}
			req.Passphrase = string(passphrase)
			clear(passphrase)
			key, err = env.Client().AddKey(ctx, req)
		}
		if err != nil {
			return hint(err)
		}
	}
	env.printf("Added %s %s\n", key.Algorithm, key.Fingerprint)
	env.printf("record %s\n", key.RecordID)
	env.printf("\nThe private key is stored in the vault and served only over the agent\n")
	env.printf("socket. It is never written to a file. Your original at %s is untouched.\n", path)
	return nil
}

func commentFromPublicFile(privatePath string) string {
	body, err := os.ReadFile(privatePath + ".pub")
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(body)))
	if len(fields) < 3 {
		return ""
	}
	return strings.Join(fields[2:], " ")
}

func runAdd(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "add")
	hostname := fs.String("hostname", "", "HostName to connect to (required)")
	username := fs.String("user", "", "User to log in as (defaults to this machine's username)")
	port := fs.Int("port", 0, "Port (defaults to 22)")
	jump := fs.String("jump", "", "ProxyJump alias, which must already be a managed host")
	keys := fs.String("key", "", "comma-separated key record ids, in the order to offer them")
	positional, rest := splitPositional(args, 1)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return errors.New("usage: sshstate add <alias> --hostname <host> [--user u] [--port n] [--jump alias] [--key id,...]")
	}
	if *hostname == "" {
		return errors.New("--hostname is required")
	}

	req := control.AddHostRequest{
		Alias:    positional[0],
		HostName: *hostname,
		User:     *username,
		Port:     *port,
	}
	if req.User == "" {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("resolve current user for --user: %w", err)
		}
		req.User = u.Username
	}
	if *jump != "" {
		req.ProxyJump = jump
	}
	if *keys != "" {
		for _, id := range strings.Split(*keys, ",") {
			if id = strings.TrimSpace(id); id != "" {
				req.KeyIDs = append(req.KeyIDs, id)
			}
		}
	}

	host, err := env.Client().AddHost(ctx, req)
	if err != nil {
		return hint(err)
	}
	env.printf("Added host %s -> %s@%s:%d\n", host.Alias, host.User, host.HostName, host.Port)
	if len(host.KeyIDs) == 0 {
		env.warnf("\nThis host references no keys, so the agent will offer nothing for it.\n")
		env.warnf("Add one with: sshstate add-key, then recreate the host with --key <id>\n")
	}
	env.printf("\nConfig regenerated at %s\n", env.Layout.Config())
	return nil
}

func runInstall(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "install")
	withService := fs.Bool("service", false, "also register the daemon with the platform service manager")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := env.Client().Generate(ctx); err != nil {
		return hint(err)
	}
	res, err := sshconfig.Install(env.Layout)
	if err != nil {
		return err
	}
	if !res.Changed {
		env.printf("Already installed: %s\n", sshconfig.DescribeInclude(env.Layout))
		return nil
	}
	if res.BackupPath != "" {
		env.printf("Backed up your SSH config to %s\n", res.BackupPath)
	}
	env.printf("Installed: %s\n", sshconfig.DescribeInclude(env.Layout))
	if *withService {
		if err := installService(env); err != nil {
			return err
		}
	}
	env.printf("\nManaged hosts now resolve through OpenSSH. Check with: sshstate doctor\n")
	env.warnf("\nHost keys for managed hosts are read from the sshstate trust files, not\n")
	env.warnf("your existing ~/.ssh/known_hosts, so you may be prompted to accept a host\n")
	env.warnf("key you have already accepted before. Importing existing trust arrives in\n")
	env.warnf("the known-host milestone.\n")
	return nil
}

func runUninstall(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "uninstall")
	purge := fs.Bool("purge", false, "also delete vault data (not available until backup and restore are verified)")
	yes := fs.Bool("yes", false, "do not prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *purge {
		return errors.New("--purge is disabled until encrypted export and restore are verified; nothing was deleted")
	}
	if !*yes {
		ok, err := env.confirm("Remove the sshstate Include from ~/.ssh/config? Vault data is preserved.")
		if err != nil {
			return err
		}
		if !ok {
			env.printf("Nothing changed.\n")
			return nil
		}
	}
	if mgr := service.For(); mgr != nil {
		if installed, err := mgr.Installed(); err == nil && installed {
			if err := mgr.Uninstall(env.Layout); err != nil {
				return err
			}
			env.printf("Unregistered the %s service.\n", mgr.Name())
		}
	}
	res, err := sshconfig.Uninstall(env.Layout)
	if err != nil {
		return err
	}
	if !res.Changed {
		env.printf("The managed Include was not present. Nothing changed.\n")
	} else {
		if res.BackupPath != "" {
			env.printf("Backed up your SSH config to %s\n", res.BackupPath)
		}
		env.printf("Removed the managed Include from %s\n", env.Layout.UserSSHConfig)
	}
	env.printf("\nPreserved: the encrypted vault at %s\n", env.Layout.Database())
	env.printf("Preserved: your own SSH keys, config, and known_hosts\n")
	return nil
}

func runDoctor(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "doctor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := env.Client().Doctor(ctx)
	if err != nil {
		return hint(err)
	}
	problems := 0
	for _, f := range report.Findings {
		marker := "ok  "
		switch f.Severity {
		case "warn":
			marker = "warn"
		case "problem":
			marker = "FAIL"
			problems++
		}
		env.printf("%s  %-26s %s\n", marker, f.Check, f.Detail)
		if f.Remedy != "" {
			env.printf("      %s\n", f.Remedy)
		}
	}
	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	env.printf("\nNo problems found.\n")
	return nil
}

func installService(env *Env) error {
	mgr := service.For()
	if mgr == nil {
		return errors.New("no service manager integration ships for this platform yet; use: sshstate daemon")
	}
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve this binary's path: %w", err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return fmt.Errorf("resolve this binary's path: %w", err)
	}
	_ = env.Client().Shutdown(context.Background())

	if err := mgr.Install(binary, env.Layout); err != nil {
		return err
	}
	env.printf("Registered with %s: %s\n", mgr.Name(), mgr.DefinitionPath())
	env.printf("The daemon now starts on demand when SSH or the CLI connects.\n")
	env.printf("It starts locked; run sshstate unlock after login.\n")
	return nil
}
