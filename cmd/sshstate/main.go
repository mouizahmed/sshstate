// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mouizahmed/sshstate/internal/buildinfo"
	"github.com/mouizahmed/sshstate/internal/cli"
	"github.com/mouizahmed/sshstate/internal/crypto"
)

var unimplementedVerbs = map[string]string{
	"rotate-master-key": "master key rotation is not implemented",
	"rotation-status":   "master key rotation status is not implemented",
	"rotation-resume":   "master key rotation resume is not implemented",
}

var withdrawn = map[string]string{
	"tui": "withdrawn from v1 scope; the CLI is the interface",
}

func usage(env *cli.Env) string {
	var b strings.Builder
	b.WriteString("sshstate - synchronize an SSH environment across machines\n\n")
	b.WriteString("usage: sshstate <command> [flags]\n")
	for _, group := range cli.Groups() {
		fmt.Fprintf(&b, "\n%s:\n", group)
		for _, c := range cli.Commands() {
			if c.Group == group {
				fmt.Fprintf(&b, "  %-18s %s\n", c.Name, c.Summary)
			}
		}
		if group == cli.GroupAdvanced {
			fmt.Fprintf(&b, "  %-18s %s\n", "version", "print version and the adopted cryptographic suite")
		}
	}

	b.WriteString("\nNot yet implemented:\n")
	names := make([]string, 0, len(unimplementedVerbs))
	for name := range unimplementedVerbs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "  %-18s %s\n", name, unimplementedVerbs[name])
	}
	b.WriteString("\nNew here? Run: sshstate setup\n")
	b.WriteString("Help for one command: sshstate <command> --help\n")
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

	return dispatch(env, args[0], args[1:])
}

func dispatch(env *cli.Env, name string, rest []string) error {
	switch name {
	case "version":
		fmt.Printf("sshstate %s\n", buildinfo.String())
		fmt.Printf("suite   %s (ML-DSA-65, ML-KEM-768+X25519)\n", crypto.SuiteID)
		fmt.Println()
		fmt.Println(buildinfo.Notice())
		return nil
	case "help", "-h", "--help":
		if name == "help" && len(rest) > 0 {
			name, rest = rest[0], []string{"--help"}
			break
		}
		fmt.Print(usage(env))
		return nil
	}

	for _, c := range cli.Commands() {
		if c.Name == name {
			err := c.Run(context.Background(), env, rest)
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
	}
	if reason, ok := unimplementedVerbs[name]; ok {
		return fmt.Errorf("%q is not implemented yet: %s", name, reason)
	}
	if reason, ok := withdrawn[name]; ok {
		return fmt.Errorf("%q will not ship: %s", name, reason)
	}
	fmt.Fprintf(os.Stderr, "sshstate: unknown command %q\n\n%s", name, usage(env))
	os.Exit(2)
	return errors.New("unreachable")
}
