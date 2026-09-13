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

var errInstallCancelled = errors.New("cancelled; ~/.ssh/config was not changed")

func (e *Env) resolveTrust(ctx context.Context, doImport, doSkip bool) error {
	if doImport && doSkip {
		return errors.New("--import-trust and --skip-trust contradict each other")
	}
	preview, err := e.Client().TrustPreview(ctx)
	if err != nil {
		return hint(err)
	}
	importable := importableDigests(preview)
	e.printTrustPreview(preview, len(importable))

	if len(importable) == 0 {
		if preview.Opaque > 0 || preview.Unrelated > 0 {
			e.warnf("\nManaged hosts will use only the trust in the vault, so you may be\n")
			e.warnf("prompted to accept a host key you have accepted before.\n")
		}
		return nil
	}

	choice := ""
	switch {
	case doImport:
		choice = "import"
	case doSkip:
		choice = "skip"
	case !e.Interactive:
		return errors.New("this install needs an explicit decision about existing host-key trust\n" +
			"pass --import-trust to import the entries listed above, or --skip-trust to continue without them")
	default:
		choice, err = e.askTrustChoice()
		if err != nil {
			return err
		}
	}

	switch choice {
	case "cancel":
		return errInstallCancelled
	case "skip":
		e.printf("\nContinuing without importing trust.\n")
		e.warnf("Managed hosts read the generated known_hosts, not your own, so you may be\n")
		e.warnf("prompted to accept host keys you have already accepted. Your own\n")
		e.warnf("known_hosts file is unchanged.\n")
		return nil
	}

	res, err := e.Client().TrustImport(ctx, importable)
	if err != nil {
		return fmt.Errorf("importing trust failed, so the Include was not activated: %w", hint(err))
	}
	e.printf("\nImported %d entr%s into %s\n", res.Imported, plural(res.Imported, "y", "ies"), res.KnownHostsPath)
	if res.Pending > 0 {
		e.printf("%d of them are held as pending candidates and are not yet trusted.\n", res.Pending)
	}
	if res.Skipped > 0 {
		e.printf("%d were already in the vault.\n", res.Skipped)
	}
	e.printf("Your own %s was not modified.\n", preview.SourcePath)
	return nil
}

func (e *Env) askTrustChoice() (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		answer, err := e.ReadLine("\nImport this trust? [i]mport / [s]kip / [c]ancel: ")
		if err != nil {
			return "", err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "i", "import":
			return "import", nil
		case "s", "skip":
			return "skip", nil
		case "c", "cancel", "":
			return "cancel", nil
		}
		e.warnf("Answer i, s, or c.\n")
	}
	return "cancel", nil
}

func importableDigests(p *control.TrustPreviewResponse) []string {
	var out []string
	for _, c := range p.Candidates {
		if c.Status != control.TrustStatusImported {
			out = append(out, c.Digest)
		}
	}
	return out
}

func (e *Env) printTrustPreview(p *control.TrustPreviewResponse, importable int) {
	if len(p.Candidates) == 0 && p.Opaque == 0 && p.Unrelated == 0 && len(p.Problems) == 0 {
		e.printf("\nNo existing host-key trust was found in %s\n", p.SourcePath)
		return
	}
	e.printf("\nExisting host-key trust in %s\n", p.SourcePath)
	if len(p.Candidates) > 0 {
		e.printf("\n%d entr%s match%s hosts this vault manages:\n\n",
			len(p.Candidates), plural(len(p.Candidates), "y", "ies"), plural(len(p.Candidates), "es", ""))
	}
	for _, c := range p.Candidates {
		marker := ""
		if c.Marker != "" {
			marker = " " + c.Marker
		}
		e.printf("  %-12s %-18s %-12s %s%s  [%s]\n",
			strings.Join(c.Aliases, ","), strings.Join(c.Destinations, ","),
			c.KeyType, c.Fingerprint, marker, c.Status)
		if note := c.Note; note != "" {
			e.printf("      %s\n", note)
		}
	}
	if p.Opaque > 0 {
		e.printf("\n  %d hashed entr%s could not be matched to a managed host. A hash cannot\n",
			p.Opaque, plural(p.Opaque, "y", "ies"))
		e.printf("  be read back, so these can be neither imported nor ruled out.\n")
	}
	if p.Unrelated > 0 {
		e.printf("\n  %d entr%s for hosts this vault does not manage, left where they are.\n",
			p.Unrelated, plural(p.Unrelated, "y", "ies"))
	}
	for _, problem := range p.Problems {
		e.warnf("\n  could not parse %s\n", problem)
	}
	if importable == 0 && len(p.Candidates) > 0 {
		e.printf("\nEvery matching entry is already in the vault.\n")
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func count(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, plural(n, one, many))
}
