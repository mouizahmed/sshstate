// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package service

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOwnDirectoryCreatesAMissingDirectoryForTheUser(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home", ".ssh", "sshstate")
	if err := ownDirectory(dir, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the directory was not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("created with mode %o, want 700", perm)
	}
	if uid := int(info.Sys().(*syscall.Stat_t).Uid); uid != os.Getuid() {
		t.Fatalf("created owned by uid %d, want %d", uid, os.Getuid())
	}
}

func TestOwnDirectoryRefusesADirectorySomeoneElseOwns(t *testing.T) {
	dir := t.TempDir()
	err := ownDirectory(dir, os.Getuid()+1)
	if err == nil || !strings.Contains(err.Error(), "sudo rm -rf "+dir) {
		t.Fatalf("a directory owned by another user was accepted: %v", err)
	}
}
