// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mouizahmed/sshstate/internal/buildinfo"
	"github.com/mouizahmed/sshstate/internal/crypto"
)

const usage = `sshstate - synchronize an SSH environment across machines

usage: sshstate <command> [flags]

available now:
  version    print version and the adopted cryptographic suite

not yet implemented (project brief §3.1):
  init, unlock, lock, add, add-key, import, install, status, doctor,
  devices, revoke, sync, pair, conflicts, resolve, export, restore,
  recover, rotate-master-key, uninstall
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
		fmt.Printf("sshstate %s\n", buildinfo.String())
		fmt.Printf("suite   %s (ML-DSA-65, ML-KEM-768+X25519)\n", crypto.SuiteID)
		fmt.Println()
		fmt.Println(buildinfo.Notice())
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "sshstate: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}
