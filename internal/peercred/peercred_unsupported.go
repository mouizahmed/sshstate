//go:build !darwin && !linux

package peercred

import (
	"errors"
	"net"
)

func peerUID(*net.UnixConn) (int, error) {
	return 0, errors.New("peer credential checks are not implemented on this platform")
}
