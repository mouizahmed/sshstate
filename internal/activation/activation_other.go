//go:build !darwin && !linux

package activation

import "os"

func listenerFiles(string) ([]*os.File, error) { return nil, nil }

func available() bool { return false }
