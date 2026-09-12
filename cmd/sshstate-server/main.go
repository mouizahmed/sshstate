// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mouizahmed/sshstate/internal/buildinfo"
)

const usage = `sshstate-server - sshstate sync relay

usage: sshstate-server <command> [flags]

available now:
  version    print version

not yet implemented:
  serve      HTTP relay (project brief §5.5, Milestone 2)
`

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch cmd := flag.Arg(0); cmd {
	case "version":
		fmt.Printf("sshstate-server %s\n", buildinfo.String())
		fmt.Println()
		fmt.Println(buildinfo.Notice())
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "sshstate-server: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}
