// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mouizahmed/sshstate/internal/control"
)

func runHosts(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "hosts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("hosts")
	}
	hosts, err := env.Client().Hosts(ctx)
	if err != nil {
		return env.hint(err)
	}
	if len(hosts) == 0 {
		env.printf("No managed hosts. Add one with: sshstate add <alias> --hostname <host>\n")
		return nil
	}
	keys, err := env.Client().Keys(ctx)
	if err != nil {
		return env.hint(err)
	}
	fingerprints := map[string]string{}
	for _, k := range keys {
		fingerprints[k.RecordID] = k.Fingerprint
	}
	for _, h := range hosts {
		env.printf("%s\n", h.Alias)
		env.printf("  %s@%s:%d\n", h.User, h.HostName, h.Port)
		if h.ProxyJump != nil {
			env.printf("  jump    %s\n", *h.ProxyJump)
		}
		for i, id := range h.KeyIDs {
			env.printf("  key %d   %s  %s\n", i+1, shortID(id), fingerprints[id])
		}
		if len(h.KeyIDs) == 0 {
			env.warnf("  no keys; the agent offers nothing for this host\n")
		}
		env.printf("  record  %s\n", h.RecordID)
		for _, issue := range h.Issues {
			env.warnf("  ! %s\n    %s\n", issue.Problem, issue.Remedy)
		}
	}
	env.printf("\n%s\n", count(len(hosts), "host", "hosts"))
	return nil
}

func runKeys(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("keys")
	}
	keys, err := env.Client().Keys(ctx)
	if err != nil {
		return env.hint(err)
	}
	if len(keys) == 0 {
		env.printf("No keys in the vault. Import one with: sshstate add-key /path/to/private_key\n")
		return nil
	}
	hosts, err := env.Client().Hosts(ctx)
	if err != nil {
		return env.hint(err)
	}
	used := map[string][]string{}
	for _, h := range hosts {
		for _, id := range h.KeyIDs {
			used[id] = append(used[id], h.Alias)
		}
	}
	for _, k := range keys {
		env.printf("%s  %s\n", shortID(k.RecordID), k.Fingerprint)
		env.printf("  %s", k.Algorithm)
		if k.Comment != "" {
			env.printf("  %s", k.Comment)
		}
		env.printf("\n")
		if aliases := used[k.RecordID]; len(aliases) > 0 {
			sort.Strings(aliases)
			env.printf("  offered to %s\n", strings.Join(aliases, ", "))
		} else {
			env.printf("  offered to nothing\n")
		}
		env.printf("  record  %s\n", k.RecordID)
	}
	env.printf("\n%s\n", count(len(keys), "key", "keys"))
	return nil
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func resolveKeyID(keys []control.KeyResponse, want string) (string, error) {
	want = strings.TrimSpace(want)
	if want == "" {
		return "", errors.New("no key given")
	}
	var matches []control.KeyResponse
	for _, k := range keys {
		if k.RecordID == want || k.Fingerprint == want {
			return k.RecordID, nil
		}
	}
	for _, k := range keys {
		switch {
		case strings.HasPrefix(k.RecordID, strings.ToLower(want)),
			strings.HasSuffix(k.Fingerprint, want),
			k.Comment != "" && strings.EqualFold(k.Comment, want):
			matches = append(matches, k)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].RecordID, nil
	case 0:
		return "", fmt.Errorf("no key matches %q; see: sshstate keys", want)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%q matches %d keys:", want, len(matches))
	for _, k := range matches {
		fmt.Fprintf(&b, "\n  %s  %s  %s", shortID(k.RecordID), k.Fingerprint, k.Comment)
	}
	return "", errors.New(b.String())
}

func resolveHost(hosts []control.HostResponse, subject string) (*control.HostResponse, error) {
	var named []int
	for i, h := range hosts {
		if h.Alias == subject {
			named = append(named, i)
		}
	}
	switch len(named) {
	case 1:
		return &hosts[named[0]], nil
	case 0:
	default:
		ids := make([]string, 0, len(named))
		for _, i := range named {
			ids = append(ids, hosts[i].RecordID)
		}
		return nil, fmt.Errorf("%d hosts are named %q; name one by its record id: %s", len(named), subject, strings.Join(ids, ", "))
	}
	ids := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ids = append(ids, h.RecordID)
	}
	id, err := resolveRecordID(ids, subject, "host")
	if err != nil {
		return nil, fmt.Errorf("no host named %q; see: sshstate hosts", subject)
	}
	for i := range hosts {
		if hosts[i].RecordID == id {
			return &hosts[i], nil
		}
	}
	return nil, fmt.Errorf("no host named %q; see: sshstate hosts", subject)
}

func (e *Env) printIssues(issues []control.HostIssue) {
	if len(issues) == 0 {
		return
	}
	e.warnf("\n%s:\n", count(len(issues), "host problem needs attention", "host problems need attention"))
	for _, issue := range issues {
		omitted := ""
		if issue.Omitted {
			omitted = " (left out of the SSH config until fixed)"
		}
		e.warnf("  %s %s%s\n", issue.Alias, issue.Problem, omitted)
		e.warnf("    %s\n", issue.Remedy)
	}
}

func resolveRecordID(candidates []string, want, kind string) (string, error) {
	want = strings.TrimSpace(strings.ToLower(want))
	if want == "" {
		return "", fmt.Errorf("no %s given", kind)
	}
	var matches []string
	for _, id := range candidates {
		if id == want {
			return id, nil
		}
		if strings.HasPrefix(id, want) {
			matches = append(matches, id)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no %s matches %q", kind, want)
	}
	return "", fmt.Errorf("%q matches %d %ss; give more characters", want, len(matches), kind)
}

func resolveKeyList(ctx context.Context, env *Env, spec string) ([]string, error) {
	keys, err := env.Client().Keys(ctx)
	if err != nil {
		return nil, env.hint(err)
	}
	ids := []string{}
	for _, want := range strings.Split(spec, ",") {
		if want = strings.TrimSpace(want); want == "" {
			continue
		}
		id, err := resolveKeyID(keys, want)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
