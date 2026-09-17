//go:build darwin && !cgo

package activation

import (
	"errors"
	"os"
)

func listenerFiles(string) ([]*os.File, error) {
	if _, ok := os.LookupEnv("XPC_SERVICE_NAME"); ok {
		return nil, errors.New("this binary was built without cgo and cannot adopt launchd sockets; rebuild with CGO_ENABLED=1")
	}
	return nil, nil
}

func available() bool { return false }
