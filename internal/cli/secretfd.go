package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const maxSecretBytes = 1024

func secretFromFD(fd int) (func(string) ([]byte, error), error) {
	if fd < 0 {
		return nil, fmt.Errorf("%d is not a file descriptor", fd)
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("file descriptor %d is not open: %w", fd, err)
	}
	unix.CloseOnExec(dup)
	f := os.NewFile(uintptr(dup), fmt.Sprintf("fd %d", fd))
	if f == nil {
		_ = unix.Close(dup)
		return nil, fmt.Errorf("file descriptor %d could not be adopted", fd)
	}
	r := bufio.NewReader(io.LimitReader(f, maxSecretBytes+1))
	return func(string) ([]byte, error) {
		line, err := r.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read the secret from fd %d: %w", fd, err)
		}
		if len(line) > maxSecretBytes {
			return nil, fmt.Errorf("the secret on fd %d is longer than %d bytes", fd, maxSecretBytes)
		}
		line = bytes.TrimRight(line, "\n")
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			return nil, fmt.Errorf("fd %d supplied an empty secret", fd)
		}
		return line, nil
	}, nil
}

func applySecretFD(env *Env, fd int) error {
	if fd < 0 {
		return nil
	}
	read, err := secretFromFD(fd)
	if err != nil {
		return err
	}
	env.ReadSecret = read
	return nil
}
