// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package sshconfig

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mouizahmed/sshstate/internal/paths"
)

type CommentResult struct {
	BackupPath string
	Aliases    []string
	Lines      int
}

const supersededMarker = "# superseded by sshstate: "

func CommentOutBlocks(l paths.Layout, blocks []ImportedHost) (CommentResult, error) {
	var res CommentResult
	if len(blocks) == 0 {
		return res, nil
	}
	path := l.UserSSHConfig
	body, existed, err := readUserConfig(path)
	if err != nil {
		return res, err
	}
	if !existed {
		return res, fmt.Errorf("%s does not exist", path)
	}
	lines := strings.Split(string(body), "\n")

	sort.SliceStable(blocks, func(i, j int) bool { return blocks[i].Line < blocks[j].Line })
	commented := map[int]bool{}
	for _, b := range blocks {
		if b.Line < 1 || b.EndLine > len(lines) || b.EndLine < b.Line {
			return res, fmt.Errorf("host %q spans lines %d-%d, which %s does not have", b.Alias, b.Line, b.EndLine, path)
		}
		for n := b.Line; n <= b.EndLine; n++ {
			commented[n] = true
		}
		res.Aliases = append(res.Aliases, b.Alias)
	}

	out := make([]string, 0, len(lines)+len(blocks))
	for i, text := range lines {
		n := i + 1
		if !commented[n] {
			out = append(out, text)
			continue
		}
		if commented[n] && !commented[n-1] {
			out = append(out, supersededMarker+"the vault defines this host")
		}
		out = append(out, "# "+text)
		res.Lines++
	}
	next := []byte(strings.Join(out, "\n"))

	backup, err := backupUserConfig(path, body)
	if err != nil {
		return res, err
	}
	res.BackupPath = backup
	if err := replaceUserConfig(path, body, next, existed); err != nil {
		return res, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, fi.Mode().Perm()&^0o077)
	}
	return res, nil
}
