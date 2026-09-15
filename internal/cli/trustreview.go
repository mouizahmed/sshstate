// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"strings"

	"github.com/mouizahmed/sshstate/internal/control"
)

func runTrust(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "trust")
	approve := fs.String("approve", "", "comma-separated observation record ids to approve")
	approveAll := fs.Bool("approve-all", false, "approve every pending observation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: sshstate trust [--approve id,...] [--approve-all]")
	}

	if *approve != "" || *approveAll {
		req := control.TrustApproveRequest{All: *approveAll}
		for _, id := range strings.Split(*approve, ",") {
			if id = strings.TrimSpace(id); id != "" {
				req.RecordIDs = append(req.RecordIDs, id)
			}
		}
		res, err := env.Client().TrustApprove(ctx, req)
		if err != nil {
			return hint(err)
		}
		env.printf("Approved %s.\n", count(res.Approved, "observation", "observations"))
		env.printf("Regenerated %s\n", env.Layout.KnownHosts())
		return nil
	}

	res, err := env.Client().TrustList(ctx)
	if err != nil {
		return hint(err)
	}
	if len(res.Entries) == 0 {
		env.printf("No host-key observations yet.\n")
		return nil
	}
	var pending int
	for _, e := range res.Entries {
		marker := e.Marker
		if marker != "" {
			marker += " "
		}
		env.printf("%-8s %s  %s%s\n", e.Status, e.RecordID, marker, e.Fingerprint)
		env.printf("         %s\n", trustDestination(e.Line))
		if e.Status == "pending" {
			pending++
		}
	}
	if pending > 0 {
		env.printf("\n%s pending review, and not trusted until approved.\n",
			count(pending, "observation is", "observations are"))
		env.printf("Approve with: sshstate trust --approve <record-id>\n")
	}
	return nil
}

func trustDestination(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return line
	}
	if strings.HasPrefix(fields[0], "@") && len(fields) > 1 {
		return fields[1]
	}
	return fields[0]
}
