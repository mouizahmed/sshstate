package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func readSecret(prompt string) ([]byte, error) { return readSecretFrom(ttyPath, prompt) }

const ttyPath = "/dev/tty"

func readSecretFrom(path, prompt string) ([]byte, error) {
	tty, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", errNoTerminal, err)
	}
	defer tty.Close()

	restore, err := hush(int(tty.Fd()))
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", errNoTerminal, err)
	}
	defer restore()

	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return nil, err
	}
	secret, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return secret, nil
}

func hush(fd int) (func(), error) {
	state, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	quiet := *state
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, ioctlFlushTermios, &quiet); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlFlushTermios, state) }, nil
}

var errNoAnswer = errors.New("this needs an answer, and standard input is not a terminal")

var errNoTerminal = errors.New("no terminal available to read a password")

func readLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr)
			return "", errNoAnswer
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
