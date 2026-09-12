// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package peercred

import (
	"errors"
	"net"
)

func peerUID(*net.UnixConn) (int, error) {
	return 0, errors.New("peer credential checks are not implemented on this platform")
}
