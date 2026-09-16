// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	GroupStart    = "Getting started"
	GroupHosts    = "Hosts and keys"
	GroupMachines = "Several machines"
	GroupBackup   = "Backup and recovery"
	GroupAdvanced = "Advanced"
)

func Groups() []string {
	return []string{GroupStart, GroupHosts, GroupMachines, GroupBackup, GroupAdvanced}
}

type flagSet struct {
	*flag.FlagSet
	env  *Env
	name string
}

func newFlagSet(env *Env, name string) *flagSet {
	fs := flag.NewFlagSet("sshstate "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return &flagSet{FlagSet: fs, env: env, name: name}
}

func (fs *flagSet) Parse(args []string) error {
	err := fs.FlagSet.Parse(args)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, flag.ErrHelp):
		fs.printHelp(fs.env.Stdout)
		return flag.ErrHelp
	default:
		message := strings.Replace(err.Error(), ": -", ": --", 1)
		return fmt.Errorf("%s\n%v\nmore: sshstate %s --help", message, usageError(fs.name), fs.name)
	}
}

func (fs *flagSet) parsePositional(args []string, n int) ([]string, error) {
	positional, rest := splitPositional(args, n)
	if err := fs.Parse(rest); err != nil {
		return nil, err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != n {
		return nil, usageError(fs.name)
	}
	return positional, nil
}

func (fs *flagSet) printHelp(w io.Writer) {
	c, _ := lookup(fs.name)
	fmt.Fprintf(w, "usage: %s\n\n%s\n", usageLine(fs.name), sentence(c.Summary))
	if !hasFlags(fs.FlagSet) {
		return
	}
	fmt.Fprintf(w, "\nflags:\n")
	fs.VisitAll(func(f *flag.Flag) {
		kind, usage := flag.UnquoteUsage(f)
		dashes := "--"
		if len(f.Name) == 1 {
			dashes = "-"
		}
		fmt.Fprintf(w, "  %s%s", dashes, f.Name)
		if kind != "" {
			fmt.Fprintf(w, " %s", kind)
		}
		fmt.Fprintf(w, "\n      %s", usage)
		if shownDefault(f.DefValue) {
			fmt.Fprintf(w, " (default %s)", f.DefValue)
		}
		fmt.Fprintln(w)
	})
}

func hasFlags(fs *flag.FlagSet) bool {
	any := false
	fs.VisitAll(func(*flag.Flag) { any = true })
	return any
}

func shownDefault(value string) bool {
	switch value {
	case "", "false", "0", "-1":
		return false
	}
	return true
}

func sentence(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:] + "."
}

func lookup(name string) (Command, bool) {
	for _, c := range Commands() {
		if c.Name == name {
			return c, true
		}
	}
	return Command{}, false
}

func usageLine(name string) string {
	c, _ := lookup(name)
	return strings.TrimSpace("sshstate " + name + " " + c.Args)
}

func usageError(name string) error {
	return errors.New("usage: " + usageLine(name))
}
