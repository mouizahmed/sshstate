package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fdWith(t *testing.T, body string) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if _, err := w.WriteString(body); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return int(r.Fd())
}

func TestUnlockReadsThePasswordFromAFileDescriptor(t *testing.T) {
	s, _ := newUnlocked(t)
	if _, err := s.Env.Client().Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.secrets = nil

	fd := fdWith(t, password+"\n")
	s.mustRun(t, "unlock", "--password-fd", itoa(fd))

	st, err := s.Env.Client().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unlocked {
		t.Fatal("the vault is still locked")
	}
}

func TestAWrongPasswordOnTheDescriptorIsRefused(t *testing.T) {
	s, _ := newUnlocked(t)
	if _, err := s.Env.Client().Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.secrets = nil

	fd := fdWith(t, "not the password\n")
	if err := s.run(t, "unlock", "--password-fd", itoa(fd)); err == nil {
		t.Fatal("a wrong password on the descriptor unlocked the vault")
	}
	st, err := s.Env.Client().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Unlocked {
		t.Fatal("the vault unlocked anyway")
	}
}

func TestSecretFromFDRejectsWhatItShould(t *testing.T) {
	if _, err := secretFromFD(-1); err == nil {
		t.Fatal("a negative descriptor was accepted")
	}
	if _, err := secretFromFD(9999); err == nil {
		t.Fatal("a descriptor nothing has open was accepted")
	}

	read, err := secretFromFD(fdWith(t, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := read(""); err == nil {
		t.Fatal("an empty line was accepted as a password")
	}

	read, err = secretFromFD(fdWith(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := read(""); err == nil {
		t.Fatal("an empty descriptor was accepted as a password")
	}

	read, err = secretFromFD(fdWith(t, strings.Repeat("x", maxSecretBytes+10)+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := read(""); err == nil {
		t.Fatal("an unbounded secret was accepted")
	}
}

func TestSecretFromFDStripsOnlyTheTerminator(t *testing.T) {
	read, err := secretFromFD(fdWith(t, "  pass word  \r\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := read("")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "  pass word  " {
		t.Fatalf("read %q; leading and trailing spaces are part of a password", got)
	}
}

func TestSecretFromFDTakesOneLineNotTheWholeStream(t *testing.T) {
	read, err := secretFromFD(fdWith(t, "first\nsecond\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := read("")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Fatalf("read %q, expected only the first line", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestReadSecretNeedsATerminalAndNotStdin(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tty")
	if _, err := readSecretFrom(missing, "prompt: "); err == nil {
		t.Fatal("a path that is not a terminal was accepted")
	} else if !strings.Contains(err.Error(), "no terminal available") {
		t.Fatalf("unhelpful error: %v", err)
	}

	regular := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(regular, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSecretFrom(regular, "prompt: "); err == nil {
		t.Fatalf("a regular file supplied the password %q; only a terminal may", got)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("hunter2\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	if _, err := readSecretFrom(missing, "prompt: "); err == nil {
		t.Fatal("a piped stdin satisfied a password prompt")
	}
}

func TestSecretFromFDDoesNotCloseTheCallersDescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := w.WriteString("first\nsecond\n"); err != nil {
		t.Fatal(err)
	}

	read, err := secretFromFD(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := read(""); err != nil || string(got) != "first" {
		t.Fatalf("read %q, %v", got, err)
	}

	read = nil
	for i := 0; i < 5; i++ {
		runtime.GC()
		runtime.Gosched()
	}

	if _, err := r.Stat(); err != nil {
		t.Fatalf("the caller's descriptor was closed underneath it: %v", err)
	}
	if _, err := w.WriteString("third\n"); err != nil {
		t.Fatalf("the pipe was broken by the secret reader: %v", err)
	}
}

func TestReadLineNamesAClosedStdinInsteadOfEOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })

	_, err = readLine("question: ")
	if !errors.Is(err, errNoAnswer) {
		t.Fatalf("a closed stdin produced %v", err)
	}
	if strings.Contains(err.Error(), "EOF") {
		t.Fatalf("the error still says EOF: %v", err)
	}
}

func TestPromptsWithABypassNameIt(t *testing.T) {
	s, firstID, _ := listReady(t)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", firstID)
	s.answer = func(string) (string, error) { return "", errNoAnswer }

	err := s.run(t, "remove", "prod")
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("remove with no terminal did not say to pass --yes: %v", err)
	}
	err = s.run(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("uninstall with no terminal did not say to pass --yes: %v", err)
	}
}

func TestUnlockWithNoTerminalNamesPasswordFD(t *testing.T) {
	s, _ := newUnlocked(t)
	s.mustRun(t, "lock")
	s.Env.ReadSecret = func(string) ([]byte, error) {
		return nil, fmt.Errorf("%w (open /dev/tty: device not configured)", errNoTerminal)
	}
	err := s.run(t, "unlock")
	if err == nil || !strings.Contains(err.Error(), "--password-fd") {
		t.Fatalf("unlock with no terminal did not say to pass --password-fd: %v", err)
	}
}

func TestAMissingFileIsNamedTheSameWayEverywhere(t *testing.T) {
	s := newScripted(t)
	missing := filepath.Join(t.TempDir(), "absent")
	for _, args := range [][]string{
		{"import", missing},
		{"add-key", missing},
		{"confirm-recovery", "--kit", missing},
	} {
		err := s.run(t, args[0], args[1:]...)
		if err == nil || !strings.HasSuffix(err.Error(), " not found: "+missing) || strings.Count(err.Error(), missing) != 1 {
			t.Fatalf("%s: a missing file was not reported plainly: %v", args[0], err)
		}
	}
}
