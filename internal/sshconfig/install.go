// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package sshconfig

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/paths"
)

const (
	MarkerBegin = "# BEGIN sshstate managed include - do not edit this block"
	MarkerEnd   = "# END sshstate managed include"
)

var ErrConcurrentChange = errors.New("~/.ssh/config changed while sshstate was editing it")

type InstallResult struct {
	Changed    bool
	BackupPath string
	Created    bool
}

func managedBlock(l paths.Layout) string {
	return fmt.Sprintf("%s\nInclude %s\n%s\n", MarkerBegin, l.Config(), MarkerEnd)
}

func Install(l paths.Layout) (InstallResult, error) {
	var res InstallResult
	original, existed, err := readUserConfig(l.UserSSHConfig)
	if err != nil {
		return res, err
	}
	if _, _, found := findBlock(original); found {
		return res, nil
	}
	if err := refuseSymlink(l.UserSSHConfig); err != nil {
		return res, err
	}

	if existed {
		backup, err := backupUserConfig(l.UserSSHConfig, original)
		if err != nil {
			return res, err
		}
		res.BackupPath = backup
	}
	res.Created = !existed

	next := []byte(managedBlock(l))
	if len(original) > 0 {
		next = append(next, '\n')
		next = append(next, original...)
	}
	if err := replaceUserConfig(l.UserSSHConfig, original, next, existed); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

func Uninstall(l paths.Layout) (InstallResult, error) {
	var res InstallResult
	original, existed, err := readUserConfig(l.UserSSHConfig)
	if err != nil || !existed {
		return res, err
	}
	start, end, found := findBlock(original)
	if !found {
		return res, nil
	}
	if err := refuseSymlink(l.UserSSHConfig); err != nil {
		return res, err
	}
	backup, err := backupUserConfig(l.UserSSHConfig, original)
	if err != nil {
		return res, err
	}
	res.BackupPath = backup

	next := make([]byte, 0, len(original))
	next = append(next, original[:start]...)
	rest := original[end:]
	rest = bytes.TrimPrefix(rest, []byte("\n"))
	next = append(next, rest...)

	if err := replaceUserConfig(l.UserSSHConfig, original, next, true); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

func IsInstalled(l paths.Layout) (bool, error) {
	body, existed, err := readUserConfig(l.UserSSHConfig)
	if err != nil || !existed {
		return false, err
	}
	_, _, found := findBlock(body)
	return found, nil
}

func findBlock(body []byte) (start, end int, found bool) {
	begin := bytes.Index(body, []byte(MarkerBegin))
	if begin < 0 {
		return 0, 0, false
	}
	closer := bytes.Index(body[begin:], []byte(MarkerEnd))
	if closer < 0 {
		return 0, 0, false
	}
	end = begin + closer + len(MarkerEnd)
	if end < len(body) && body[end] == '\n' {
		end++
	}
	return begin, end, true
}

type SymlinkError struct {
	Path   string
	Target string
}

func (e *SymlinkError) Error() string {
	return fmt.Sprintf("%s is a symlink to %s, and sshstate does not edit files through symlinks", e.Path, e.Target)
}

func refuseSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		target, _ = os.Readlink(path)
	}
	return &SymlinkError{Path: path, Target: target}
}

func ManagedBlock(l paths.Layout) string { return managedBlock(l) }

func readUserConfig(path string) (body []byte, existed bool, err error) {
	fi, err := os.Stat(path)
	switch {
	case os.IsNotExist(err):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	body, err = os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return body, true, nil
}

const maxBackupsPerSecond = 100

func backupUserConfig(path string, body []byte) (string, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	backup := fmt.Sprintf("%s.sshstate-backup-%s", path, stamp)
	for n := 2; ; n++ {
		err := atomicCreate(backup, body, 0o600)
		if err == nil {
			return backup, nil
		}
		if !errors.Is(err, os.ErrExist) || n > maxBackupsPerSecond {
			return "", fmt.Errorf("write backup %s: %w", filepath.Base(backup), err)
		}
		backup = fmt.Sprintf("%s.sshstate-backup-%s-%d", path, stamp, n)
	}
}

func replaceUserConfig(path string, original, next []byte, existed bool) error {
	if existed {
		current, stillThere, err := readUserConfig(path)
		if err != nil {
			return err
		}
		if !stillThere || sha256.Sum256(current) != sha256.Sum256(original) {
			return ErrConcurrentChange
		}
	}
	perm := os.FileMode(0o600)
	if existed {
		if fi, err := os.Stat(path); err == nil {
			perm = fi.Mode().Perm()
		}
	}
	return atomicWrite(path, next, perm)
}

func DescribeInclude(l paths.Layout) string {
	return strings.TrimSpace("Include " + l.Config())
}
