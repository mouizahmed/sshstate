package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/vault"
)

func TestNativeSSHLogin(t *testing.T) {
	if os.Getenv("SSHSTATE_SSHD_TEST") != "1" {
		t.Skip("set SSHSTATE_SSHD_TEST=1 to start a real sshd")
	}
	sshdBin := findSSHD(t)
	for _, bin := range []string{"ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not on PATH", bin)
		}
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	dir, err := os.MkdirTemp("/tmp", "sshd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	clientKey := filepath.Join(dir, "client")
	keygen(t, clientKey)
	hostKey := filepath.Join(dir, "host")
	keygen(t, hostKey)

	clientPub, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, clientPub, 0o600); err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	config := filepath.Join(dir, "sshd_config")
	body := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
AuthorizedKeysFile %s
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
LogLevel VERBOSE
`, port, hostKey, filepath.Join(dir, "sshd.pid"), authorized)
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	log := &syncBuffer{}
	sshd := exec.Command(sshdBin, "-D", "-e", "-f", config)
	sshd.Stdout, sshd.Stderr = log, log
	if err := sshd.Start(); err != nil {
		t.Fatalf("start sshd: %v", err)
	}
	t.Cleanup(func() {
		_ = sshd.Process.Kill()
		_, _ = sshd.Process.Wait()
	})
	waitForPort(t, port, log)

	s := newScripted(t)
	kitPath := filepath.Join(dir, "kit.txt")
	s.secrets = []string{password, password}
	s.answer = func(string) (string, error) { return kitChecksum(t, kitPath), nil }
	s.mustRun(t, "init", "--kit", kitPath)
	s.answer = nil
	s.startDaemon(t)
	s.secrets = []string{password}
	s.mustRun(t, "unlock")

	s.out.Reset()
	s.mustRun(t, "add-key", clientKey)
	recordID := recordIDFrom(t, s.out.String())
	s.mustRun(t, "add", "demo",
		"--hostname", "127.0.0.1", "--port", fmt.Sprint(port),
		"--user", me.Username, "--key", recordID)

	hostPub, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(hostPub))
	if len(fields) < 2 {
		t.Fatalf("unreadable host public key: %s", hostPub)
	}
	entry := fmt.Sprintf("[127.0.0.1]:%d %s %s\n", port, fields[0], fields[1])
	if err := os.MkdirAll(filepath.Dir(s.Layout.UserKnownHosts()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Layout.UserKnownHosts(), []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}
	s.mustRun(t, "install", "--import-trust")

	login := func() (string, error) {
		cmd := exec.Command("ssh", "-F", s.Layout.UserSSHConfig,
			"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
			"demo", "echo", "logged-in")
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=", "SSH_AGENT_PID=")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := login()
	if err != nil {
		t.Fatalf("native ssh login failed: %v\nssh:\n%s\nsshd:\n%s", err, out, log)
	}
	if !strings.Contains(out, "logged-in") {
		t.Fatalf("the command did not run on the server:\n%s", out)
	}

	walkNoPrivateKey(t, s.Layout.Data, clientKey)
	walkNoPrivateKey(t, s.Layout.SSH, clientKey)

	s.mustRun(t, "lock")
	if out, err := login(); err == nil {
		t.Fatalf("ssh logged in with a locked vault:\n%s", out)
	}
	s.secrets = []string{password}
	s.mustRun(t, "unlock")
	if out, err := login(); err != nil {
		t.Fatalf("ssh did not work again after unlocking: %v\nssh:\n%s\nsshd:\n%s", err, out, log)
	}
}

func findSSHD(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/sshd", "/usr/libexec/sshd", "/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("sshd was not found")
	return ""
}

func keygen(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", filepath.Base(path), "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen %s: %v: %s", path, err, out)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int, log *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sshd never listened on %d:\n%s", port, log)
}

var recordLine = regexp.MustCompile(`(?m)^record ([0-9a-zA-Z_-]+)$`)

func recordIDFrom(t *testing.T, out string) string {
	t.Helper()
	m := recordLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add-key printed no record id:\n%s", out)
	}
	return m[1]
}

func kitChecksum(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kit, err := vault.ParseKit(string(body))
	if err != nil {
		t.Fatal(err)
	}
	return kit.Checksum()
}

func walkNoPrivateKey(t *testing.T, root, keyPath string) {
	t.Helper()
	secret, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	needle := strings.TrimSpace(string(secret))
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.Contains(string(body), needle) {
			t.Errorf("the private key was written to %s", path)
		}
		return nil
	})
}
