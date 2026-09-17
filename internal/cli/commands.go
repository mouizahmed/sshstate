// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/daemon"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func splitPositional(args []string, n int) (positional, rest []string) {
	for len(args) > 0 && len(positional) < n && !strings.HasPrefix(args[0], "-") {
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional, args
}

func runInit(ctx context.Context, env *Env, args []string) error {
	return initVault(ctx, env, args, true)
}

func initVault(ctx context.Context, env *Env, args []string, showNext bool) error {
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

	kitSaved, err := env.saveKit(kit, *kitPath)
	if err != nil {
		return env.explainUnfinishedInit(kitSaved, *kitPath, err)
	}
	if err := env.confirmKitNow(mgr, kit); err != nil {
		return env.explainUnfinishedInit(kitSaved, *kitPath, err)
	}
	env.printf("\nRecovery kit confirmed.\n")
	if showNext {
		env.printf("Finish setting up this machine with: sshstate setup\n")
	}
	return nil
}

func (e *Env) saveKit(kit *vault.Kit, path string) (bool, error) {
	if path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return false, fmt.Errorf("write recovery kit: %w", err)
		}
		body := []byte(kit.Marshal())
		if _, err := f.Write(body); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return false, fmt.Errorf("write recovery kit: %w", err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return false, fmt.Errorf("sync recovery kit: %w", err)
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(path)
			return false, fmt.Errorf("close recovery kit: %w", err)
		}
		e.printf("Recovery kit written to %s (mode 0600).\n", path)
	} else {
		e.printf("%s\n", kit.Marshal())
	}
	e.printf("\nSave this kit offline now. It is the only way back into this vault\n")
	e.printf("if you lose every enrolled device, and it is not stored anywhere else.\n\n")
	return true, nil
}

func (e *Env) confirmKitNow(mgr *vault.Manager, kit *vault.Kit) error {
	for attempt := 0; attempt < 3; attempt++ {
		answer, err := e.ReadLine(fmt.Sprintf("Type the kit's checksum (%d characters) to confirm you saved it: ", vault.KitChecksumChars))
		if err != nil {
			return fmt.Errorf("read the confirmation: %w", err)
		}
		if err := mgr.ConfirmRecoveryKit(strings.TrimSpace(strings.ToUpper(answer)), kit); err == nil {
			return nil
		}
		e.warnf("That does not match. ")
	}
	return errors.New("recovery kit not confirmed")
}

func (e *Env) explainUnfinishedInit(kitSaved bool, kitPath string, cause error) error {
	e.warnf("\nThe vault at %s was created and is not confirmed, so it refuses changes.\n",
		e.Layout.Database())
	if !kitSaved {
		e.warnf("Its recovery kit was not saved anywhere, so this vault cannot be recovered.\n")
		e.warnf("Delete %s and run init again.\n", e.Layout.Database())
		return cause
	}
	where := kitPath
	if where == "" {
		where = "<the file you saved the kit to>"
	}
	e.warnf("Confirm it once the kit is saved:\n")
	e.warnf("    sshstate confirm-recovery --kit %s\n", where)
	e.warnf("If you no longer have the kit, delete %s and run init again.\n", e.Layout.Database())
	return cause
}

func runConfirmRecovery(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "confirm-recovery")
	kitPath := fs.String("kit", "", "path to the saved recovery kit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *kitPath
	if path == "" {
		answer, err := env.ReadLine("Path to your saved recovery kit: ")
		if err != nil {
			return withBypass(err, "--kit <path>")
		}
		path = strings.TrimSpace(answer)
	}
	if path == "" {
		return errors.New("no recovery kit path given")
	}
	data, err := readUserFile("recovery kit", path)
	if err != nil {
		return err
	}
	kit, err := vault.ParseKit(string(data))
	if err != nil {
		return err
	}
	signing, _, err := kit.Keys()
	if err != nil {
		return err
	}

	confirmed, err := env.confirmRecoveryViaDaemon(ctx, signing)
	if errors.Is(err, control.ErrDaemonUnavailable) {
		confirmed, err = env.confirmRecoveryInProcess(signing)
	}
	if err != nil {
		return err
	}
	env.printf("Recovery kit confirmed for vault %s. The vault now accepts changes.\n", confirmed)
	return nil
}

func (e *Env) confirmRecoveryViaDaemon(ctx context.Context, signing *crypto.SigningKey) (string, error) {
	challenge, err := e.Client().RecoveryChallenge(ctx)
	if err != nil {
		return "", err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return "", err
	}
	signature, err := signing.Sign(vault.RecoveryConfirmDomain, nonce)
	if err != nil {
		return "", err
	}
	st, err := e.Client().RecoveryConfirm(ctx, challenge.Nonce,
		base64.RawURLEncoding.EncodeToString(signature))
	if err != nil {
		return "", e.hint(err)
	}
	return st.VaultID, nil
}

func (e *Env) confirmRecoveryInProcess(signing *crypto.SigningKey) (string, error) {
	release, err := daemon.AcquireInstanceLock(e.Layout.DaemonLock())
	if err != nil {
		return "", fmt.Errorf("%w\nIf a daemon is running, its control socket is unreachable; "+
			"restart it and run this again", err)
	}
	defer release()

	store, err := vault.OpenStore(e.Layout.Database())
	if err != nil {
		return "", err
	}
	defer store.Close()
	mgr, err := vault.NewManager(store)
	if err != nil {
		return "", err
	}
	nonce, err := mgr.RecoveryChallenge()
	if err != nil {
		return "", err
	}
	signature, err := signing.Sign(vault.RecoveryConfirmDomain, nonce)
	if err != nil {
		return "", err
	}
	if err := mgr.ConfirmRecoveryProof(nonce, signature); err != nil {
		return "", err
	}
	return string(mgr.VaultID()), nil
}

func defaultDeviceLabel() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "device"
	}
	return host
}

func runChangePassword(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "change-password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("change-password")
	}
	if _, err := env.Client().Status(ctx); err != nil {
		return env.hint(err)
	}
	current, err := env.ReadSecret("Current unlock password: ")
	if err != nil {
		return err
	}
	defer clear(current)
	next, err := env.ReadSecret("New unlock password: ")
	if err != nil {
		return err
	}
	defer clear(next)
	again, err := env.ReadSecret("Repeat new password: ")
	if err != nil {
		return err
	}
	defer clear(again)
	if string(next) != string(again) {
		return errors.New("the new passwords do not match; nothing changed")
	}
	if err := env.Client().ChangePassword(ctx, string(current), string(next)); err != nil {
		return env.hint(err)
	}
	env.printf("Changed the unlock password for this device.\n")
	env.printf("Other devices keep their own passwords, and the recovery kit is unchanged.\n")
	return nil
}

func runUnlock(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "unlock")
	passwordFD := fs.Int("password-fd", -1, "read the password from this file descriptor instead of the terminal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := applySecretFD(env, *passwordFD); err != nil {
		return err
	}
	current, err := env.Client().Status(ctx)
	if err != nil {
		return env.hint(err)
	}
	if current.Unlocked {
		env.printf("Already unlocked. Idle expiry %s, hard expiry %s.\n",
			current.IdleExpiresAt.Local().Format(time.Kitchen),
			current.HardExpiresAt.Local().Format(time.Kitchen))
		return nil
	}
	password, err := env.ReadSecret("Device unlock password: ")
	if err != nil {
		return withBypass(err, "--password-fd <n>")
	}
	defer clear(password)
	st, err := env.Client().Unlock(ctx, string(password))
	if err != nil {
		return env.hint(err)
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
	current, err := env.Client().Status(ctx)
	if err != nil {
		return env.hint(err)
	}
	if !current.Unlocked {
		env.printf("Already locked.\n")
		return nil
	}
	if _, err := env.Client().Lock(ctx); err != nil {
		return env.hint(err)
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
	if errors.Is(err, control.ErrDaemonUnavailable) && env.vaultExists() {
		meta, _ := env.storedMeta(vault.MetaVaultID, vault.MetaDeviceID, vault.MetaDeviceLabel, vault.MetaRelayURL)
		env.printf("vault        %s\n", meta[vault.MetaVaultID])
		env.printf("device       %s", meta[vault.MetaDeviceID])
		if label := meta[vault.MetaDeviceLabel]; label != "" {
			env.printf(" (%s)", label)
		}
		env.printf("\nstate        daemon not running\n")
		if relay := meta[vault.MetaRelayURL]; relay != "" {
			env.printf("relay        %s\n", relay)
		} else {
			env.printf("relay        none (local only)\n")
		}
		env.printf("\n")
		return env.hint(err)
	}
	if err != nil {
		return env.hint(err)
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
	if st.RevokedHere {
		env.printf(" — revoked; nothing changed here syncs")
	}
	env.printf("\nstate        %s\n", state)
	if st.Unlocked {
		env.printf("             idle expiry %s, hard expiry %s\n",
			st.IdleExpiresAt.Local().Format(time.Kitchen),
			st.HardExpiresAt.Local().Format(time.Kitchen))
	}
	env.printf("hosts        %d\n", st.Hosts)
	env.printf("keys         %d\n", st.Keys)
	env.printf("known hosts  %d\n", st.KnownHosts)
	if st.Relay != "" {
		env.printf("unpublished  %d\n", st.Pending)
	} else if st.Pending > 0 {
		env.printf("unpublished  %d (no relay yet; they publish on connect)\n", st.Pending)
	}
	if st.Relay != "" {
		env.printf("relay        %s\n", st.Relay)
	} else {
		env.printf("relay        none (local only)\n")
	}
	env.printf("config       %s\n", st.ConfigPath)
	if st.ConfigInstalled {
		env.printf("include      active in ~/.ssh/config\n")
	} else {
		env.printf("include      not installed\n")
	}
	env.printf("agent socket %s\n", st.AgentSocket)
	env.printIssues(st.Issues)
	if !st.RecoveryConfirmed {
		env.warnf("\nThe recovery kit has not been confirmed; the vault will refuse changes.\n")
		env.warnf("Confirm it with: sshstate confirm-recovery\n")
		return nil
	}
	switch {
	case !st.ConfigInstalled || st.Hosts == 0:
		env.printf("\nThis machine is not fully set up yet.\n")
		env.printf("Next: sshstate setup\n")
	case !st.Unlocked:
		env.printf("\nThe vault is locked, so the agent offers no identities.\n")
		env.printf("Next: sshstate unlock\n")
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
		return usageError("add-key")
	}
	path := positional[0]
	raw, err := readUserFile("private key", path)
	if err != nil {
		return err
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
			return env.hint(err)
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
	keys := fs.String("key", "", "comma-separated keys by id, fingerprint, or comment, in the order to offer them")
	positional, rest := splitPositional(args, 1)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return usageError("add")
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
		ids, err := resolveKeyList(ctx, env, *keys)
		if err != nil {
			return err
		}
		req.KeyIDs = ids
	}

	host, err := env.Client().AddHost(ctx, req)
	if err != nil {
		return env.hint(err)
	}
	env.printf("Added host %s -> %s@%s:%d\n", host.Alias, host.User, host.HostName, host.Port)
	if len(host.KeyIDs) == 0 {
		env.warnf("\nThis host references no keys, so the agent will offer nothing for it.\n")
		env.warnf("Attach one with: sshstate edit %s --key <key>\n", host.Alias)
	}
	env.printf("\nConfig regenerated at %s\n", env.Layout.Config())
	return nil
}

func runEdit(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "edit")
	alias := fs.String("alias", "", "new alias for this host")
	hostname := fs.String("hostname", "", "HostName to connect to")
	username := fs.String("user", "", "User to log in as")
	port := fs.Int("port", 0, "Port")
	jump := fs.String("jump", "", `ProxyJump alias, or "none" to clear it`)
	keys := fs.String("key", "", "comma-separated keys by id, fingerprint, or comment, in the order to offer them")
	positional, rest := splitPositional(args, 1)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return usageError("edit")
	}

	hosts, err := env.Client().Hosts(ctx)
	if err != nil {
		return env.hint(err)
	}
	target, err := resolveHost(hosts, positional[0])
	if err != nil {
		return err
	}
	req := control.EditHostRequest{RecordID: target.RecordID}

	var given int
	var resolveErr error
	fs.Visit(func(f *flag.Flag) {
		given++
		switch f.Name {
		case "alias":
			req.Alias = alias
		case "hostname":
			req.HostName = hostname
		case "user":
			req.User = username
		case "port":
			req.Port = port
		case "jump":
			cleared := ""
			if *jump == "none" {
				req.ProxyJump = &cleared
			} else {
				req.ProxyJump = jump
			}
		case "key":
			ids, err := resolveKeyList(ctx, env, *keys)
			if err != nil {
				resolveErr = err
				return
			}
			req.KeyIDs = &ids
		}
	})
	if resolveErr != nil {
		return resolveErr
	}
	if given == 0 {
		return errors.New("nothing to change; pass at least one of --alias, --hostname, --user, --port, --jump, --key")
	}

	host, err := env.Client().EditHost(ctx, req)
	if err != nil {
		return env.hint(err)
	}
	env.printf("Updated host %s -> %s@%s:%d\n", host.Alias, host.User, host.HostName, host.Port)
	if len(host.KeyIDs) == 0 {
		env.warnf("\nThis host references no keys, so the agent will offer nothing for it.\n")
		env.warnf("Attach one with: sshstate edit %s --key <key>\n", host.Alias)
	}
	env.printf("\nConfig regenerated at %s\n", env.Layout.Config())
	return nil
}

func runInstall(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "install")
	withService := fs.Bool("service", false, "also register the daemon with launchd or systemd so it starts on demand")
	importTrust := fs.Bool("import-trust", false, "import matching entries from ~/.ssh/known_hosts without asking")
	skipTrust := fs.Bool("skip-trust", false, "activate the Include without importing existing host-key trust")
	if err := fs.Parse(args); err != nil {
		return err
	}
	registered := false
	if *withService {
		if err := installService(env); err != nil {
			return err
		}
		registered = true
	}
	if _, err := env.Client().Generate(ctx); err != nil {
		if registered && isLocked(err) {
			env.printf("\nThe service is registered, but the vault it starts is locked, so the\n")
			env.printf("configuration was not generated. Finish with:\n")
			env.printf("  sshstate unlock\n  sshstate install\n")
			return errors.New("installation is incomplete")
		}
		return env.hint(err)
	}
	if err := env.resolveTrust(ctx, *importTrust, *skipTrust); err != nil {
		return err
	}
	res, err := sshconfig.Install(env.Layout)
	var symlink *sshconfig.SymlinkError
	if errors.As(err, &symlink) {
		return fmt.Errorf("%w\nadd these lines at the top of %s yourself, then run this again:\n\n%s",
			err, symlink.Target, sshconfig.ManagedBlock(env.Layout))
	}
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
	env.printf("\nManaged hosts now resolve through OpenSSH. Check with: sshstate doctor\n")
	return nil
}

func runUninstall(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "uninstall")
	purge := fs.Bool("purge", false, "also delete vault data (requires a recent export)")
	yes := fs.Bool("yes", false, "answer yes to every confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *purge {
		if err := env.purgeVault(ctx, *yes); err != nil {
			return err
		}
	}
	if !*yes && !*purge {
		ok, err := env.confirm("Remove the sshstate Include from ~/.ssh/config? Vault data is preserved.")
		if err != nil {
			return withBypass(err, "--yes")
		}
		if !ok {
			env.printf("Nothing changed.\n")
			return nil
		}
	}
	if !*purge {
		env.OfferDeregistration(ctx, *yes)
	}
	if mgr := env.services(); mgr != nil {
		if installed, err := mgr.Installed(env.Layout); err == nil && installed {
			if err := mgr.Uninstall(env.Layout); err != nil {
				return err
			}
			env.printf("Unregistered the %s service.\n", mgr.Name())
		}
	}
	res, err := sshconfig.Uninstall(env.Layout)
	var symlink *sshconfig.SymlinkError
	if errors.As(err, &symlink) {
		return fmt.Errorf("%w\nremove the block between the sshstate managed include markers from %s yourself, then run this again",
			err, symlink.Target)
	}
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
	reactivated, err := sshconfig.ReactivateBlocks(env.Layout)
	if errors.As(err, &symlink) {
		env.warnf("\nThe Host blocks sshstate commented out are still commented in %s; "+
			"uncomment the blocks marked \"superseded by sshstate\" there yourself.\n", symlink.Target)
		err = nil
	}
	if err != nil {
		return fmt.Errorf("the Include is gone, but the Host blocks sshstate commented out are still commented: %w", err)
	}
	if len(reactivated.Aliases) > 0 {
		env.printf("Reactivated the Host blocks sshstate had commented out: %s\n", strings.Join(reactivated.Aliases, ", "))
		env.printf("They are your definitions from before sshstate managed them; later edits in sshstate are not in them.\n")
	}
	if *purge {
		env.printf("\nDeleted: the encrypted vault at %s\n", env.Layout.Database())
	} else {
		env.printf("\nPreserved: the encrypted vault at %s\n", env.Layout.Database())
	}
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
		return env.hint(err)
	}
	problems, warnings := 0, 0
	for _, f := range report.Findings {
		marker := "ok  "
		switch f.Severity {
		case "warn":
			marker = "warn"
			warnings++
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
	if warnings > 0 {
		env.printf("\nNo problems, but %s above.\n", count(warnings, "warning", "warnings"))
		return nil
	}
	env.printf("\nNo problems found.\n")
	return nil
}

const serviceStartWait = 10 * time.Second

func (e *Env) awaitDaemon(ctx context.Context, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		_, err := e.Client().Status(ctx)
		if !errors.Is(err, control.ErrDaemonUnavailable) {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func installService(env *Env) error {
	mgr := env.services()
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
	if err := env.awaitDaemon(context.Background(), serviceStartWait); err != nil {
		return fmt.Errorf("registered with %s, but the daemon did not answer within %s: %w\ncheck it with: sshstate doctor",
			mgr.Name(), serviceStartWait, err)
	}
	env.printf("Registered with %s: %s\n", mgr.Name(), mgr.DefinitionPath())
	env.printf("The daemon now starts on demand when SSH or the CLI connects.\n")
	env.printf("It starts locked; run sshstate unlock after login.\n")
	return nil
}
