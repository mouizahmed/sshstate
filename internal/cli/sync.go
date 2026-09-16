// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relayclient"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func runConnect(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "connect")
	secretPath := fs.String("bootstrap-secret", "", "path to the relay's one-time bootstrap secret file")
	positional, err := fs.parsePositional(args, 1)
	if err != nil {
		return err
	}
	url := positional[0]
	req := control.ConnectRequest{URL: strings.TrimSuffix(url, "/")}
	if *secretPath != "" {
		raw, err := os.ReadFile(*secretPath)
		if err != nil {
			return fmt.Errorf("read the bootstrap secret: %w", err)
		}
		if _, err := protocol.DecodeBootstrapSecret(string(raw)); err != nil {
			return fmt.Errorf("%s: %w", *secretPath, err)
		}
		req.BootstrapSecret = strings.TrimSpace(string(raw))
	}

	out, err := env.Client().Connect(ctx, req)
	if err != nil {
		return env.hint(err)
	}
	if out.Bootstrap {
		env.printf("Connected to %s and created the vault there.\n", out.URL)
		env.printf("The bootstrap secret is now spent; the relay will not accept another vault.\n")
	} else {
		env.printf("Connected to %s.\n", out.URL)
	}
	env.printf("Published %s.\n", count(out.Uploaded, "record", "records"))
	env.printf("\nOn another machine, enrol it with: sshstate pair\n")
	return nil
}

func runSync(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "sync")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := env.Client().Status(ctx)
	if err != nil {
		return env.hint(err)
	}
	if st.Relay == "" {
		env.printf("This vault is on this machine only, so there is nothing to sync.\n")
		env.printf("To use it on more than one machine: sshstate connect <relay-url>\n")
		return nil
	}
	out, err := env.Client().Sync(ctx)
	if err != nil {
		return env.hint(err)
	}
	switch {
	case out.Pushed == 0 && out.Applied == 0 && out.Preserved == 0:
		env.printf("Already up to date.\n")
	default:
		if out.Pushed > 0 {
			env.printf("Published %s.\n", count(out.Pushed, "change", "changes"))
		}
		if out.Applied > 0 {
			env.printf("Applied %s.\n", count(out.Applied, "change", "changes"))
		}
	}
	if out.Preserved > 0 {
		env.printf("\nKept %s that lost a race with another device.\n",
			count(out.Preserved, "edit", "edits"))
		env.printf("Review them with: sshstate conflicts\n")
	}
	if !out.Complete {
		env.warnf("\nThe relay had more changes than this run could take.\n")
		env.warnf("Generated configuration is unchanged; run sync again.\n")
	}
	return nil
}

func runDevices(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "devices")
	if err := fs.Parse(args); err != nil {
		return err
	}
	out, err := env.Client().Devices(ctx)
	if err != nil {
		return env.hint(err)
	}
	if len(out.Devices) == 0 {
		env.printf("No devices.\n")
		return nil
	}
	for _, d := range out.Devices {
		marker := "  "
		if d.ThisDevice {
			marker = "* "
		}
		env.printf("%s%s  %-8s enrolled %s\n", marker, d.DeviceID, d.Status, d.EnrolledAt)
		if d.Status == "revoked" {
			env.printf("    revoked %s\n", d.RevokedAt)
		}
	}
	env.printf("\nThis listing is the signed membership chain, not the relay's device table.\n")
	return nil
}

func runRevoke(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "revoke")
	yes := fs.Bool("yes", false, "confirm revoking the device you are using")
	positional, err := fs.parsePositional(args, 1)
	if err != nil {
		return err
	}
	devices, err := env.Client().Devices(ctx)
	if err != nil {
		return env.hint(err)
	}
	ids := make([]string, 0, len(devices.Devices))
	for _, d := range devices.Devices {
		ids = append(ids, d.DeviceID)
	}
	deviceID, err := resolveRecordID(ids, positional[0], "device")
	if err != nil {
		return fmt.Errorf("%w; see: sshstate devices", err)
	}
	out, err := env.Client().Revoke(ctx, control.RevokeRequest{
		DeviceID: deviceID,
		Confirm:  *yes,
	})
	if err != nil {
		return env.hint(err)
	}
	env.printf("Revoked %s.\n", out.DeviceID)
	if out.ThisDevice {
		env.printf("\nThis device can no longer write to the vault.\n")
		env.printf("Remove what is left on this machine with: sshstate uninstall\n")
	}
	env.printf("\nThat device can no longer write, and an honest relay will refuse its\n")
	env.printf("requests. It does not erase the vault keys or the SSH keys it already\n")
	env.printf("holds. Replace any SSH credentials that device could use.\n")
	return nil
}

func runExport(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "export")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("export")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; choose another path", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, err := env.Client().Export(ctx, path)
	if err != nil {
		return env.hint(err)
	}
	env.printf("Wrote %s (%d bytes, %s, %s).\n", out.Path, out.Bytes,
		count(out.Records, "record", "records"),
		count(out.Conflicts, "conflict", "conflicts"))
	env.printf("\nIt is encrypted to your recovery kit and to nothing else, so the kit is\n")
	env.printf("what opens it. Store them apart from each other.\n")
	env.printf("\nThis restores access to what it contains. It is not a backup of the\n")
	env.printf("relay: storage that is gone is gone.\n")
	return nil
}

func runConflicts(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "conflicts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	out, err := env.Client().Conflicts(ctx)
	if err != nil {
		return env.hint(err)
	}
	if len(out.Conflicts) == 0 {
		env.printf("No conflicts.\n")
		return nil
	}
	env.printf("%s preserved because another device's edit was accepted first:\n\n",
		count(len(out.Conflicts), "edit", "edits"))
	for _, c := range out.Conflicts {
		env.printf("  %s\n", c.RecordID)
		env.printf("    %s %s, kept %s\n", c.SourceRecordType, c.SourceRecordID, c.PreservedAt)
	}
	env.printf("\nNothing was lost. Acceptance order decided which version is current;\n")
	env.printf("it is not a claim about which edit was made later.\n")
	return nil
}

func runRestore(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "restore")
	kitPath := fs.String("kit", "", "path to the recovery kit")
	label := fs.String("label", defaultDeviceLabel(), "label for this device")
	positional, err := fs.parsePositional(args, 1)
	if err != nil {
		return err
	}
	if *kitPath == "" {
		return usageError("restore")
	}
	archivePath := positional[0]

	archive, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("read the export: %w", err)
	}
	kitBody, err := os.ReadFile(*kitPath)
	if err != nil {
		return fmt.Errorf("read the recovery kit: %w", err)
	}
	kit, err := vault.ParseKit(string(kitBody))
	if err != nil {
		return fmt.Errorf("%s: %w", *kitPath, err)
	}

	store, err := vault.OpenStore(env.Layout.Database())
	if err != nil {
		return err
	}
	defer store.Close()
	if initialized, err := store.Initialized(); err != nil {
		return err
	} else if initialized {
		return fmt.Errorf("a vault already exists at %s; restore onto a machine that has none",
			env.Layout.Database())
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

	mgr, res, err := vault.Restore(store, vault.RestoreOptions{
		Archive:     archive,
		Kit:         kit,
		Password:    password,
		DeviceLabel: *label,
	})
	if err != nil {
		return err
	}
	env.printf("Restored vault %s as new device %s.\n", res.VaultID, res.DeviceID)
	env.printf("Installed %s, accepted through seq %s.\n",
		count(res.Records, "record", "records"), res.Seq)
	env.printf("\nThis device was authorized by the recovery kit, so it can write.\n")
	env.printf("The kit still opens this vault: treat it as you did before.\n")
	env.printf("\nNext: sshstate daemon, then sshstate install\n")
	if _, err := mgr.RelayURL(); err == nil {
		env.printf("Point it at a relay with: sshstate connect <url>\n")
	}
	return nil
}

func (e *Env) deregister(ctx context.Context, st *control.StatusResponse) (done bool, why string) {
	if st.Relay == "" {
		return true, ""
	}
	if !st.Unlocked {
		return false, "the vault is locked"
	}
	if _, err := e.Client().Revoke(ctx, control.RevokeRequest{
		DeviceID: st.DeviceID,
		Confirm:  true,
	}); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func (e *Env) OfferDeregistration(ctx context.Context, yes bool) {
	st, err := e.Client().Status(ctx)
	if err != nil {
		e.warnf("\nThe daemon is not reachable, so this device was not deregistered.\n")
		e.warnf("If this vault is connected to a relay, revoke it from another device.\n")
		return
	}
	if st.Relay == "" {
		return
	}
	if !yes {
		ok, err := e.confirm(fmt.Sprintf(
			"Also deregister this device from %s, so it is no longer an authorized writer?", st.Relay))
		if err != nil || !ok {
			e.printf("Left registered. This device remains an authorized writer on %s.\n", st.Relay)
			e.printf("Revoke it later with: sshstate revoke %s\n", st.DeviceID)
			return
		}
	}
	done, why := e.deregister(ctx, st)
	if done {
		e.printf("Deregistered this device from %s.\n", st.Relay)
		return
	}
	e.warnf("\nDeregistration did not complete: %s.\n", why)
	e.warnf("This device remains an authorized writer on %s.\n", st.Relay)
	e.warnf("Revoke it from another device with: sshstate revoke %s\n", st.DeviceID)
}

func (e *Env) purgeVault(ctx context.Context, yes bool) error {
	st, err := e.Client().Status(ctx)
	if err != nil {
		return fmt.Errorf("--purge needs the daemon running so it can deregister first: %w.\n"+
			"Start it with: sshstate daemon\nNothing was deleted", err)
	}
	if st.LastExportPath == "" {
		return errors.New("--purge needs a backup first.\n" +
			"Run: sshstate export <path>\n" +
			"Check you can open it, then try again. Nothing was deleted.")
	}
	if _, err := os.Stat(st.LastExportPath); err != nil {
		return fmt.Errorf("the last export (%s) is not there any more.\n"+
			"Take a new one with: sshstate export <path>\nNothing was deleted", st.LastExportPath)
	}
	if !yes {
		e.printf("This deletes the vault at %s.\n", e.Layout.Database())
		e.printf("Your most recent backup is %s (%s).\n", st.LastExportPath, st.LastExportAt)
		e.printf("Without that file and your recovery kit, the contents are gone.\n\n")
		answer, err := e.ReadLine(fmt.Sprintf("Type the vault id (%s) to delete it: ", st.VaultID))
		if err != nil {
			return err
		}
		if strings.TrimSpace(answer) != st.VaultID {
			return errors.New("that is not this vault's id; nothing was deleted")
		}
	}

	done, why := e.deregister(ctx, st)
	switch {
	case done && st.Relay != "":
		e.printf("Deregistered this device from %s.\n", st.Relay)
	case !done:
		e.warnf("Deregistration did not complete: %s.\n", why)
		e.warnf("This device remains an authorized writer on %s.\n", st.Relay)
		e.warnf("Revoke it from another device with: sshstate revoke %s\n\n", st.DeviceID)
	}

	if err := e.Client().Shutdown(ctx); err != nil && !errors.Is(err, control.ErrDaemonUnavailable) {
		return fmt.Errorf("stop the daemon before deleting its database: %w", err)
	}
	if err := os.RemoveAll(e.Layout.Data); err != nil {
		return fmt.Errorf("delete the vault: %w", err)
	}
	return nil
}

func runResolve(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "resolve")
	resurrect := fs.Bool("resurrect", false, "apply the edit even though the record has since been deleted")
	positional, err := fs.parsePositional(args, 1)
	if err != nil {
		return err
	}
	listed, err := env.Client().Conflicts(ctx)
	if err != nil {
		return env.hint(err)
	}
	ids := make([]string, 0, len(listed.Conflicts))
	for _, c := range listed.Conflicts {
		ids = append(ids, c.RecordID)
	}
	recordID, err := resolveRecordID(ids, positional[0], "conflict")
	if err != nil {
		return fmt.Errorf("%w; see: sshstate conflicts", err)
	}
	out, err := env.Client().Resolve(ctx, control.ResolveRequest{
		RecordID:  recordID,
		Resurrect: *resurrect,
	})
	if err != nil {
		if strings.Contains(err.Error(), "has been deleted") {
			return fmt.Errorf("%w\nThat record was deleted on another device.\n"+
				"To apply this edit anyway and bring it back: sshstate resolve %s --resurrect",
				env.hint(err), recordID)
		}
		return env.hint(err)
	}
	env.printf("Applied the preserved edit to record %s.\n", out.SourceRecordID)
	env.printf("\nIt went in as an ordinary change against the current version, so if\n")
	env.printf("another device edited the same record just now, this becomes a new\n")
	env.printf("conflict rather than overwriting it. Publish with: sshstate sync\n")
	return nil
}

func runRecover(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "recover")
	kitPath := fs.String("kit", "", "path to the recovery kit")
	label := fs.String("label", defaultDeviceLabel(), "label for this device")
	positional, err := fs.parsePositional(args, 2)
	if err != nil {
		return err
	}
	if *kitPath == "" {
		return usageError("recover")
	}
	relayURL, vaultID := strings.TrimSuffix(positional[0], "/"), protocol.ID(positional[1])
	if !vaultID.Valid() {
		return fmt.Errorf("%q is not a vault id", positional[1])
	}

	kitBody, err := os.ReadFile(*kitPath)
	if err != nil {
		return fmt.Errorf("read the recovery kit: %w", err)
	}
	kit, err := vault.ParseKit(string(kitBody))
	if err != nil {
		return fmt.Errorf("%s: %w", *kitPath, err)
	}
	if kit.VaultID != vaultID {
		return fmt.Errorf("that kit is for vault %s, not %s", kit.VaultID, vaultID)
	}

	store, err := vault.OpenStore(env.Layout.Database())
	if err != nil {
		return err
	}
	defer store.Close()
	if initialized, err := store.Initialized(); err != nil {
		return err
	} else if initialized {
		return fmt.Errorf("a vault already exists at %s; recover onto a machine that has none",
			env.Layout.Database())
	}

	client, err := relayclient.New(relayclient.Options{BaseURL: relayURL})
	if err != nil {
		return err
	}
	challenge, err := client.RecoveryChallenge(ctx, vaultID)
	if err != nil {
		return env.hint(err)
	}
	if len(challenge.RecoveryEnvelope) == 0 {
		return errors.New("that relay holds no recovery material for this vault")
	}
	digest, err := challenge.Genesis.Digest()
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, kit.GenesisDigest) {
		return errors.New("the relay returned a different vault than this kit is for")
	}
	recoverySigning, err := crypto.SigningKeyFromSeed(kit.SigningSeed)
	if err != nil {
		return err
	}

	password, err := env.ReadSecret("New device unlock password for this machine: ")
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

	mgr, res, err := vault.Restore(store, vault.RestoreOptions{
		Archive:     challenge.RecoveryEnvelope,
		Kit:         kit,
		Password:    password,
		DeviceLabel: *label,
		Publish: func(ev protocol.SignedMembershipEvent) error {
			admission := protocol.RecoveryAdmission{
				Domain:          protocol.RecoveryAdmitDomain,
				FormatVersion:   protocol.RecoveryAdmitFormatVersion,
				VaultID:         vaultID,
				GenesisDigest:   digest,
				Nonce:           challenge.Nonce,
				DeviceID:        ev.Event.DeviceID,
				DeviceVerifyKey: ev.Event.DeviceVerifyKey,
				DeviceRecipient: *ev.Event.DeviceRecipient,
				CreatedAt:       time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
			}
			msg, err := admission.SigningInput()
			if err != nil {
				return err
			}
			sig, err := recoverySigning.Sign(protocol.RecoveryAdmitDomain, msg)
			if err != nil {
				return err
			}
			_, err = client.RecoveryComplete(ctx, protocol.RecoveryCompleteRequest{
				Admission:       admission,
				Signature:       sig,
				MembershipEvent: ev,
			})
			return err
		},
	})
	if err != nil {
		return err
	}
	if err := mgr.SetRelayURL(relayURL); err != nil {
		return err
	}

	env.printf("Recovered vault %s as new device %s.\n", res.VaultID, res.DeviceID)
	env.printf("Installed %s from the relay's recovery material.\n",
		count(res.Records, "record", "records"))
	env.printf("\nThe kit authorized this device, so it can write. Any device you have\n")
	env.printf("lost is still authorized: revoke it with sshstate revoke <device-id>.\n")
	env.printf("\nNext: sshstate daemon, then sshstate sync\n")
	return nil
}
