package peercred

import (
	"fmt"
	"net"
	"os"
)

func Check(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is %T, not a Unix socket", conn)
	}
	uid, err := peerUID(uc)
	if err != nil {
		return err
	}
	if self := os.Getuid(); uid != self {
		return fmt.Errorf("peer runs as uid %d, this daemon serves uid %d", uid, self)
	}
	return nil
}
