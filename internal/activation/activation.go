// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package activation

import (
	"fmt"
	"net"
	"os"
)

const (
	NameControl = "control"
	NameAgent   = "agent"
)

var ErrNotActivated = fmt.Errorf("no activated socket")

func Listener(name string) (net.Listener, error) {
	files, err := listenerFiles(name)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, ErrNotActivated
	}
	if len(files) > 1 {
		for _, f := range files {
			f.Close()
		}
		return nil, fmt.Errorf("service manager passed %d sockets named %q, expected 1", len(files), name)
	}
	ln, err := net.FileListener(files[0])
	closeErr := files[0].Close()
	if err != nil {
		return nil, fmt.Errorf("adopt activated socket %q: %w", name, err)
	}
	if closeErr != nil {
		ln.Close()
		return nil, fmt.Errorf("adopt activated socket %q: %w", name, closeErr)
	}
	return ln, nil
}

func Available() bool { return available() }

var _ = os.Getenv
