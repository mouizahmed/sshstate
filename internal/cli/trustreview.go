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
	revoke := fs.Bool("revoke", false, "stop trusting these observations: OpenSSH refuses their keys on every machine")
	subjects, rest := splitPositional(args, len(args))
	if err := fs.Parse(rest); err != nil {
		return err
	}
	subjects = append(subjects, fs.Args()...)
	if len(subjects) > 0 && *approveAll {
		return errors.New("give record ids or --all, not both")
	}
	if *revoke && (*approveAll || len(subjects) == 0) {
		return errors.New("--revoke needs the record ids to revoke; see: sshstate trust")
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
		if *revoke {
			res, err := env.Client().TrustRevoke(ctx, control.TrustRevokeRequest{RecordIDs: req.RecordIDs})
			if err != nil {
				return env.hint(err)
			}
			env.printf("Revoked %s. OpenSSH now refuses those keys, here and on every machine after it syncs.\n",
				count(res.Revoked, "observation", "observations"))
			env.printf("Regenerated %s\n", env.Layout.KnownHosts())
			return nil
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
	var pending, withheld int
	for _, e := range res.Entries {
		status, marker := e.Status, e.Marker
		if marker == "@revoked" {
			status, marker = "revoked", ""
		}
		if marker != "" {
			marker += " "
		}
		env.printf("%-8s %s  %s%s\n", status, e.RecordID, marker, e.Fingerprint)
		destination := trustDestination(e.Line)
		if strings.HasPrefix(destination, "|1|") {
			destination = "hashed host name"
		}
		if len(e.Hosts) > 0 {
			env.printf("         %s (%s)\n", strings.Join(e.Hosts, ", "), destination)
		} else {
			env.printf("         %s\n", destination)
		}
		if e.Withheld {
			withheld++
			env.warnf("         disagrees with another approved key for this host, so it is not shared with other machines\n")
		}
		if e.Status == "pending" {
			pending++
		}
	}
	if withheld > 0 {
		env.warnf("\nCheck the server's real fingerprint out of band, then revoke the wrong key: sshstate trust <record-id> --revoke\n")
	}
	if pending > 0 {
		env.printf("\n%s pending review. Other machines do not trust a pending key until it is approved,\n",
			count(pending, "observation is", "observations are"))
		env.printf("but OpenSSH on the machine that saw it already accepted it when you answered yes.\n")
		env.printf("Approve with: sshstate trust <record-id>, or: sshstate trust --all\n")
		env.printf("If a key should not be trusted, refuse it everywhere with: sshstate trust --revoke <record-id>\n")
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
