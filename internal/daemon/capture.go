// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"os"
	"strings"

	"github.com/mouizahmed/sshstate/internal/knownhosts"
	"github.com/mouizahmed/sshstate/internal/vault"
)

type CaptureResult struct {
	Approved int
	Pending  int
	Skipped  int
	Ignored  int
}

func (d *Daemon) reconcileCapture() (CaptureResult, error) {
	var result CaptureResult
	if st, err := d.mgr.Status(); err != nil || !st.Unlocked {
		return result, err
	}
	raw, err := os.ReadFile(d.layout.CaptureFile())
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	text := string(raw)
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = text[:i+1]
	} else {
		return result, nil
	}

	entries, problems := knownhosts.Parse(text)
	result.Ignored = len(problems)

	hosts, err := d.mgr.Hosts()
	if err != nil {
		return result, err
	}
	destinations := make([]string, 0, len(hosts))
	for _, h := range hosts {
		destinations = append(destinations, knownhosts.Destination(h.HostName, h.Port))
	}

	stored, err := d.mgr.KnownHosts()
	if err != nil {
		return result, err
	}
	seen := make(map[string]bool, len(stored))
	approvedFor := map[string][]vault.KnownHostView{}
	for _, s := range stored {
		seen[string(s.LineDigest)] = true
		if s.Status == vault.TrustApproved {
			approvedFor[s.KeyType] = append(approvedFor[s.KeyType], s)
		}
	}

	var specs []vault.KnownHostSpec
	for _, e := range entries {
		matched := ""
		for _, dest := range destinations {
			if e.Matches(dest) {
				matched = dest
				break
			}
		}
		if matched == "" {
			result.Ignored++
			continue
		}
		digest := e.Digest
		if seen[string(digest[:])] {
			result.Skipped++
			continue
		}
		status := vault.TrustApproved
		if disagreesWithApproved(e, matched, approvedFor[e.KeyType]) {
			status = vault.TrustPending
		}
		if status == vault.TrustApproved {
			result.Approved++
			approvedFor[e.KeyType] = append(approvedFor[e.KeyType], vault.KnownHostView{
				Line:        e.Line,
				KeyType:     e.KeyType,
				Fingerprint: e.Fingerprint,
				Marker:      e.Marker,
				Status:      vault.TrustApproved,
			})
		} else {
			result.Pending++
		}
		seen[string(digest[:])] = true
		specs = append(specs, vault.KnownHostSpec{
			Line:        e.Line,
			KeyType:     e.KeyType,
			Fingerprint: e.Fingerprint,
			Marker:      e.Marker,
			Status:      status,
			LineDigest:  digest[:],
		})
	}
	if len(specs) == 0 {
		return result, nil
	}
	if _, _, err := d.mgr.AddKnownHosts(specs); err != nil {
		return CaptureResult{}, err
	}
	return result, nil
}

func disagreesWithApproved(e knownhosts.Entry, dest string, approved []vault.KnownHostView) bool {
	for _, a := range approved {
		if a.Fingerprint == e.Fingerprint {
			return false
		}
	}
	for _, a := range approved {
		prior, err := knownhosts.ParseLine(a.Line)
		if err != nil {
			continue
		}
		if prior.Marker != e.Marker {
			continue
		}
		if prior.Matches(dest) {
			return true
		}
	}
	return false
}
