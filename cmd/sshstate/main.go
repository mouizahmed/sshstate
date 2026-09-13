// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mouizahmed/sshstate/internal/buildinfo"
	"github.com/mouizahmed/sshstate/internal/cli"
	"github.com/mouizahmed/sshstate/internal/crypto"
)

var laterMilestones = map[string]string{
	"import":            "strict SSH config import arrives with the known-host milestone",
	"tui":               "the focused TUI ships after the CLI operations it wraps",
	"recover":           "recovery through a relay ships with rotation; `restore` works offline today",
	"rotate-master-key": "master key rotation ships before stable v1",
	"rotation":          "rotation status and resume ship with rotation",
}

func usage(env *cli.Env) string {
	var b strings.Builder
	b.WriteString("sshstate - synchronize an SSH environment across machines\n\n")
	b.WriteString("usage: sshstate <command> [flags]\n\n")
	b.WriteString("commands:\n")
	for _, c := range cli.Commands() {
		fmt.Fprintf(&b, "  %-11s %s\n", c.Name, c.Summary)
	}
	fmt.Fprintf(&b, "  %-11s %s\n", "version", "print version and the adopted cryptographic suite")

	b.WriteString("\nnot yet implemented:\n")
	names := make([]string, 0, len(laterMilestones))
	for name := range laterMilestones {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "  %-11s %s\n", name, laterMilestones[name])
	}
	return b.String()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sshstate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	env, err := cli.DefaultEnv()
	if err != nil {
		return err
	}
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage(env))
		os.Exit(2)
	}

	name, rest := args[0], args[1:]
	switch name {
	case "version":
		fmt.Printf("sshstate %s\n", buildinfo.String())
		fmt.Printf("suite   %s (ML-DSA-65, ML-KEM-768+X25519)\n", crypto.SuiteID)
		fmt.Println()
		fmt.Println(buildinfo.Notice())
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage(env))
		return nil
	}

	for _, c := range cli.Commands() {
		if c.Name == name {
			return c.Run(context.Background(), env, rest)
		}
	}
	if reason, ok := laterMilestones[name]; ok {
		return fmt.Errorf("%q is not implemented yet: %s", name, reason)
	}
	fmt.Fprintf(os.Stderr, "sshstate: unknown command %q\n\n%s", name, usage(env))
	os.Exit(2)
	return errors.New("unreachable")
}
