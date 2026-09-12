// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package activation

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const listenFDsStart = 3

func listenerFiles(name string) ([]*os.File, error) {
	if pid := os.Getenv("LISTEN_PID"); pid != "" {
		want, err := strconv.Atoi(pid)
		if err != nil || want != os.Getpid() {
			return nil, nil
		}
	}
	countStr := os.Getenv("LISTEN_FDS")
	if countStr == "" {
		return nil, nil
	}
	count, err := strconv.Atoi(countStr)
	if err != nil || count <= 0 {
		return nil, nil
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != count {
		return nil, fmt.Errorf("LISTEN_FDNAMES lists %d names for %d descriptors; sshstate requires named sockets", len(names), count)
	}

	var out []*os.File
	for i := 0; i < count; i++ {
		if names[i] != name {
			continue
		}
		fd := listenFDsStart + i
		unix.CloseOnExec(fd)
		out = append(out, os.NewFile(uintptr(fd), "systemd-"+name))
	}
	return out, nil
}

func available() bool { return os.Getenv("LISTEN_FDS") != "" }
