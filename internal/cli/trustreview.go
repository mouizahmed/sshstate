// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/control"
)

func runTrust(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "trust")
	approveAll := fs.Bool("all", false, "approve every pending observation")
	subjects, rest := splitPositional(args, len(args))
	if err := fs.Parse(rest); err != nil {
		return err
	}
	subjects = append(subjects, fs.Args()...)
	if len(subjects) > 0 && *approveAll {
		return errors.New("give record ids or --all, not both")
	}

	if len(subjects) > 0 || *approveAll {
		req := control.TrustApproveRequest{All: *approveAll}
		if len(subjects) > 0 {
			listed, err := env.Client().TrustList(ctx)
			if err != nil {
				return env.hint(err)
			}
			ids := make([]string, 0, len(listed.Entries))
			for _, e := range listed.Entries {
				ids = append(ids, e.RecordID)
			}
			for _, want := range subjects {
				id, err := resolveRecordID(ids, want, "observation")
				if err != nil {
					return fmt.Errorf("%w; see: sshstate trust", err)
				}
				req.RecordIDs = append(req.RecordIDs, id)
			}
		}
		res, err := env.Client().TrustApprove(ctx, req)
		if err != nil {
			return env.hint(err)
		}
		env.printf("Approved %s.\n", count(res.Approved, "observation", "observations"))
		env.printf("Regenerated %s\n", env.Layout.KnownHosts())
		return nil
	}

	res, err := env.Client().TrustList(ctx)
	if err != nil {
		return env.hint(err)
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
		env.printf("Approve with: sshstate trust <record-id>, or: sshstate trust --all\n")
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
