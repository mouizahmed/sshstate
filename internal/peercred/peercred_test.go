package peercred

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func listenFor(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sshstate-peercred")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	return ln, path
}

func TestSameUserIsAccepted(t *testing.T) {
	ln, path := listenFor(t)

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- Check(conn)
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a connection from this user was refused: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never answered")
	}
}

func TestPeerUIDIsTheActualUID(t *testing.T) {
	ln, path := listenFor(t)

	type result struct {
		uid int
		err error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer conn.Close()
		uid, err := peerUID(conn.(*net.UnixConn))
		done <- result{uid: uid, err: err}
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("reading peer credentials failed: %v", got.err)
		}
		if got.uid != os.Getuid() {
			t.Fatalf("peer uid is %d, this process is %d", got.uid, os.Getuid())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never answered")
	}
}

func TestNonUnixConnectionIsRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- Check(conn)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a TCP connection passed a check that reads Unix peer credentials")
		}
		if !strings.Contains(err.Error(), "not a Unix socket") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never answered")
	}
}

func TestCrossUserConnectionIsRefused(t *testing.T) {
	peer := os.Getenv("SSHSTATE_PEER_TEST_USER")
	if peer == "" {
		t.Skip("set SSHSTATE_PEER_TEST_USER to a second account, with passwordless `sudo -u`, to run this")
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo is not available")
	}
	ln, path := listenFor(t)

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- Check(conn)
	}()

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(filepath.Dir(path), "helper")
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, body, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sudo", "-n", "-u", peer, "env", "SSHSTATE_PEER_SOCKET="+path,
		helper, "-test.run", "^TestConnectAsPeerHelper$", "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("could not run the test binary as %q (%v):\n%s", peer, err, out)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a connection from another user was accepted")
		}
		if !strings.Contains(err.Error(), "peer runs as uid") {
			t.Fatalf("unexpected refusal: %v", err)
		}
		self := strconv.Itoa(os.Getuid())
		if !strings.Contains(err.Error(), self) {
			t.Fatalf("the refusal does not say which uid this daemon serves: %v", err)
		}
		t.Logf("refused, as it must be: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the listener never answered")
	}
}

func TestConnectAsPeerHelper(t *testing.T) {
	path := os.Getenv("SSHSTATE_PEER_SOCKET")
	if path == "" {
		t.Skip("helper; driven by TestCrossUserConnectionIsRefused")
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("could not reach %s as uid %d: %v", path, os.Getuid(), err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Logf("write after connect: %v", err)
	}
}
