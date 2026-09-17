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
		raw, err := readUserFile("bootstrap secret", *secretPath)
		if err != nil {
			return err
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
	case out.Pushed == 0 && out.Applied == 0 && out.Preserved == 0 && out.Learned == 0:
		env.printf("Already up to date.\n")
	default:
		if out.Learned > 0 {
			env.printf("Learned %s. See them with: sshstate devices\n", count(out.Learned, "device change", "device changes"))
		}
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
	env.printIssues(out.Issues)
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
	yes := fs.Bool("yes", false, "answer yes when the device to revoke is this one")
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
		subject := c.Subject
		if subject == "" {
			subject = c.SourceRecordID
		}
		env.printf("  %s\n", c.RecordID)
		env.printf("    %s %s, kept %s\n", strings.ReplaceAll(c.SourceRecordType, "_", " "), subject, c.PreservedAt)
		for _, change := range c.Changes {
			env.printf("      %s\n", change)
		}
		if len(c.Changes) == 0 && !c.SourceRemoved {
			env.printf("      no difference from the current version; resolving it changes nothing\n")
		}
		resolve := "sshstate resolve " + c.RecordID
		if c.SourceRemoved {
			resolve += " --resurrect"
		}
		env.printf("      keep it with: %s\n", resolve)
		env.printf("      or drop it:   sshstate resolve %s --discard\n", c.RecordID)
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

	archive, err := readUserFile("export", archivePath)
	if err != nil {
		return err
	}
	kitBody, err := readUserFile("recovery kit", *kitPath)
	if err != nil {
		return err
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

	_, res, err := vault.Restore(store, vault.RestoreOptions{
		Archive:     archive,
		Kit:         kit,
		Password:    password,
		DeviceLabel: *label,
	})
	if err != nil {
		return err
	}
	env.printf("Restored vault %s as new device %s.\n", res.VaultID, res.DeviceID)
	env.printf("Installed %s from the export.\n", count(res.Records, "record", "records"))
	env.printf("\nThis device was authorized by the recovery kit, so it can write.\n")
	env.printf("The kit still opens this vault: treat it as you did before.\n")
	env.printf("\nFinish setting up this machine with: sshstate setup\n")
	env.printf("\nThe restored vault lives on this machine only. A restored vault cannot start a new relay;\n")
	env.printf("to use the original relay again, recover from it on a fresh machine: sshstate recover\n")
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
		relay := e.storedRelay()
		if relay == "" {
			return
		}
		e.warnf("\nThe daemon is not reachable, so this device was not deregistered from %s.\n", relay)
		e.warnf("Revoke it from another device with: sshstate revoke <device-id>\n")
		return
	}
	if st.Relay == "" {
		return
	}
	if e.onlyDevice(ctx, st) {
		e.printf("This is the vault's only device, so it stays registered on %s.\n", st.Relay)
		e.printf("To remove it there, pair another machine first and revoke it from that one.\n")
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

func (e *Env) onlyDevice(ctx context.Context, st *control.StatusResponse) bool {
	listed, err := e.Client().Devices(ctx)
	if err != nil {
		return false
	}
	for _, d := range listed.Devices {
		if d.Status == "active" && d.DeviceID != st.DeviceID {
			return false
		}
	}
	return true
}

func (e *Env) storedRelay() string {
	meta, ok := e.storedMeta(vault.MetaRelayURL)
	if !ok {
		return "its relay"
	}
	return meta[vault.MetaRelayURL]
}

func (e *Env) storedMeta(keys ...string) (map[string]string, bool) {
	out := map[string]string{}
	if !e.vaultExists() {
		return out, true
	}
	store, err := vault.OpenStore(e.Layout.Database())
	if err != nil {
		return out, false
	}
	defer store.Close()
	for _, k := range keys {
		v, err := store.Meta(k)
		switch {
		case errors.Is(err, vault.ErrNotFound):
		case err != nil:
			return out, false
		default:
			out[k] = v
		}
	}
	return out, true
}

func (e *Env) purgeVault(ctx context.Context, yes bool) error {
	st, err := e.Client().Status(ctx)
	if err != nil {
		return fmt.Errorf("--purge needs the daemon running so it can deregister first: %w\nNothing was deleted", e.hint(err))
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

	only := st.Relay != "" && e.onlyDevice(ctx, st)
	done, why := false, ""
	if !only {
		done, why = e.deregister(ctx, st)
	}
	switch {
	case only:
		e.printf("This was the vault's only device, so it stays registered on %s.\n", st.Relay)
		e.printf("The recovery kit can still restore the vault from there.\n\n")
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
	discard := fs.Bool("discard", false, "drop the kept edit and keep the current version")
	positional, err := fs.parsePositional(args, 1)
	if err != nil {
		return err
	}
	if *discard && *resurrect {
		return errors.New("give --discard or --resurrect, not both")
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
		Discard:   *discard,
	})
	if err != nil {
		if strings.Contains(err.Error(), "has been deleted") {
			return fmt.Errorf("%w\nThat record was deleted on another device.\n"+
				"To apply this edit anyway and bring it back: sshstate resolve %s --resurrect",
				env.hint(err), recordID)
		}
		return env.hint(err)
	}
	if *discard {
		env.printf("Discarded the kept edit; record %s stays as it is.\n", out.SourceRecordID)
		env.printf("Publish with: sshstate sync\n")
		return nil
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

	kitBody, err := readUserFile("recovery kit", *kitPath)
	if err != nil {
		return err
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
	env.printf("\nFinish setting up this machine with: sshstate setup\n")
	return nil
}
