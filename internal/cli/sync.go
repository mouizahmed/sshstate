// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

func runConnect(ctx context.Context, env *Env, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	secretPath := fs.String("bootstrap-secret", "", "path to the relay's one-time bootstrap secret file")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: sshstate connect <relay-url> [--bootstrap-secret <file>]")
	}
	url := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: sshstate connect <relay-url> [--bootstrap-secret <file>]")
	}
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
		return hint(err)
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
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	out, err := env.Client().Sync(ctx)
	if err != nil {
		return hint(err)
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
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	out, err := env.Client().Devices(ctx)
	if err != nil {
		return hint(err)
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
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	yes := fs.Bool("yes", false, "confirm revoking the device you are using")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: sshstate revoke <device-id> [--yes]")
	}
	deviceID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: sshstate revoke <device-id> [--yes]")
	}
	out, err := env.Client().Revoke(ctx, control.RevokeRequest{
		DeviceID: deviceID,
		Confirm:  *yes,
	})
	if err != nil {
		return hint(err)
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
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: sshstate export <path>")
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
		return hint(err)
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
	fs := flag.NewFlagSet("conflicts", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	out, err := env.Client().Conflicts(ctx)
	if err != nil {
		return hint(err)
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
