package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mouizahmed/sshstate/internal/control"
)

func TestNativeSSHLogin(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh binary available")
	}

	h := start(t)
	ctx := context.Background()
	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "login@test")
	if err != nil {
		t.Fatal(err)
	}
	added, err := h.client.AddKey(ctx, control.AddKeyRequest{
		PrivateKey: string(pemEncode(t, block)),
		Comment:    "login@test",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorized, _, _, _, err := ssh.ParseAuthorizedKey([]byte(added.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	srv := startSSHServer(t, authorized)
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}

	if _, err := h.client.AddHost(ctx, control.AddHostRequest{
		Alias:    "testhost",
		HostName: host,
		User:     "tester",
		Port:     port,
		KeyIDs:   []string{added.RecordID},
	}); err != nil {
		t.Fatal(err)
	}

	line := fmt.Sprintf("[%s]:%d %s\n", host, port,
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.hostKey.PublicKey()))))
	if err := os.MkdirAll(filepath.Dir(h.layout.CaptureFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.CaptureFile(), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, sshBin,
		"-F", h.layout.Config(),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"testhost", "whoami")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh login failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "authenticated as tester") {
		t.Fatalf("unexpected session output: %q", out)
	}

	if _, err := h.client.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	locked := exec.CommandContext(runCtx, sshBin,
		"-F", h.layout.Config(),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"testhost", "whoami")
	locked.Env = cmd.Env
	if out, err := locked.CombinedOutput(); err == nil {
		t.Fatalf("ssh authenticated while the vault was locked:\n%s", out)
	}
}

func pemEncode(t *testing.T, block *pem.Block) []byte {
	t.Helper()
	return pem.EncodeToMemory(block)
}

type sshServer struct {
	addr    string
	hostKey ssh.Signer
}

func startSSHServer(t *testing.T, authorized ssh.PublicKey) *sshServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() != "tester" {
				return nil, fmt.Errorf("unexpected user %q", conn.User())
			}
			if string(key.Marshal()) != string(authorized.Marshal()) {
				return nil, fmt.Errorf("unauthorized key")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOne(conn, cfg)
		}
	}()
	return &sshServer{addr: ln.Addr().String(), hostKey: hostKey}
}

func serveOne(nConn net.Conn, cfg *ssh.ServerConfig) {
	defer nConn.Close()
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			return
		}
		go func(ch ssh.Channel, requests <-chan *ssh.Request) {
			defer ch.Close()
			for req := range requests {
				switch req.Type {
				case "exec", "shell":
					req.Reply(true, nil)
					io.WriteString(ch, "authenticated as "+conn.User()+"\n")
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					req.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}
