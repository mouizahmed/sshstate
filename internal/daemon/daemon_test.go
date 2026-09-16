// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/paths"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const testPassword = "correct horse battery staple"

type harness struct {
	layout paths.Layout
	daemon *Daemon
	client *control.Client
	mgr    *vault.Manager
}

func start(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	layout := paths.Layout{
		Data:          filepath.Join(root, "data"),
		SSH:           filepath.Join(root, "ssh", "sshstate"),
		UserSSHConfig: filepath.Join(root, "ssh", "config"),
		Runtime:       shortRuntimeDir(t),
	}

	store, err := vault.OpenStore(layout.Database())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	mgr, kit, err := vault.Init(store, vault.InitOptions{
		Password: []byte(testPassword), DeviceLabel: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.ConfirmRecoveryKit(kit.Checksum(), kit); err != nil {
		t.Fatal(err)
	}
	mgr.Lock()

	d := New(mgr, layout, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon exited with %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("daemon did not shut down")
		}
	})

	client := control.NewClient(layout.ControlSocket())
	waitForSocket(t, layout.ControlSocket())
	waitForSocket(t, layout.AgentSocket())
	return &harness{layout: layout, daemon: d, client: client, mgr: mgr}
}

func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", path); err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s never became available", path)
}

func testKeyPEM(t *testing.T, comment string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestSocketsAreRestrictive(t *testing.T) {
	h := start(t)
	for _, path := range []string{h.layout.ControlSocket(), h.layout.AgentSocket()} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != socketPerm {
			t.Errorf("%s is mode %04o, want %04o", filepath.Base(path), got, socketPerm)
		}
	}
	if h.layout.ControlSocket() == h.layout.AgentSocket() {
		t.Fatal("control and agent share one socket")
	}
}

func TestDaemonStartsLockedAndRefusesWork(t *testing.T) {
	h := start(t)
	ctx := context.Background()

	st, err := h.client.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unlocked {
		t.Fatal("daemon came up unlocked")
	}
	if _, err := h.client.Keys(ctx); err == nil {
		t.Fatal("locked daemon answered a key listing")
	} else {
		var api *control.APIError
		if !errors.As(err, &api) || api.Code != control.CodeLocked {
			t.Fatalf("wrong error for a locked vault: %v", err)
		}
	}
}

func TestUnlockWrongPasswordRejected(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	if _, err := h.client.Unlock(ctx, "not the password"); err == nil {
		t.Fatal("unlocked with the wrong password")
	}
	st, err := h.client.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unlocked {
		t.Fatal("a failed unlock left the vault open")
	}
}

func TestEndToEndKeyHostAndGeneratedConfig(t *testing.T) {
	h := start(t)
	ctx := context.Background()

	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	key, err := h.client.AddKey(ctx, control.AddKeyRequest{
		PrivateKey: string(testKeyPEM(t, "me@laptop")),
		Comment:    "me@laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	host, err := h.client.AddHost(ctx, control.AddHostRequest{
		Alias: "prod", HostName: "10.0.0.5", User: "ubuntu", KeyIDs: []string{key.RecordID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if host.Port != 22 {
		t.Fatalf("omitted port became %d", host.Port)
	}

	body, err := os.ReadFile(h.layout.Config())
	if err != nil {
		t.Fatalf("config was not generated: %v", err)
	}
	got := string(body)
	for _, want := range []string{
		"Host prod", "HostName 10.0.0.5", "User ubuntu", "Port 22",
		"IdentityAgent " + h.layout.AgentSocket(),
		"IdentitiesOnly yes", "ForwardAgent no", "UpdateHostKeys no",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated config is missing %q", want)
		}
	}
	if err := filepath.WalkDir(h.layout.SSH, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), "PRIVATE KEY") {
			t.Errorf("%s contains private key material", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pubs, err := filepath.Glob(filepath.Join(h.layout.PublicDir(), "prod-01-*.pub"))
	if err != nil || len(pubs) != 1 {
		t.Fatalf("expected one generated public key file, found %v", pubs)
	}
}

func TestAgentListsAndSignsOnlyWhileUnlocked(t *testing.T) {
	h := start(t)
	ctx := context.Background()

	conn, err := net.Dial("unix", h.layout.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("locked agent offered %d identities", len(keys))
	}

	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	added, err := h.client.AddKey(ctx, control.AddKeyRequest{
		PrivateKey: string(testKeyPEM(t, "agent@test")),
		Comment:    "agent@test",
	})
	if err != nil {
		t.Fatal(err)
	}

	keys, err = client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("unlocked agent offered %d identities", len(keys))
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(added.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if string(keys[0].Blob) != string(pub.Marshal()) {
		t.Fatal("the agent offered a different key than the one added")
	}

	data := []byte("session identifier and exchange hash")
	sig, err := client.Sign(pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("the agent produced a signature that does not verify: %v", err)
	}

	if _, err := h.client.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	keys, err = client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("locked agent still offers %d identities", len(keys))
	}
	if _, err := client.Sign(pub, data); err == nil {
		t.Fatal("the agent signed after the vault was locked")
	}
}

func TestAgentRefusesKeyManagement(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	added, err := h.client.AddKey(ctx, control.AddKeyRequest{PrivateKey: string(testKeyPEM(t, "k"))})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(added.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("unix", h.layout.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)

	_, intruder, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: intruder, Comment: "intruder"}); err == nil {
		t.Error("the agent accepted a new key over the agent protocol")
	}
	if err := client.Remove(pub); err == nil {
		t.Error("the agent removed a key over the agent protocol")
	}
	if err := client.RemoveAll(); err == nil {
		t.Error("the agent accepted RemoveAll")
	}
	if err := client.Lock([]byte("pw")); err == nil {
		t.Error("the agent accepted a protocol-level lock")
	}
	if err := client.Unlock([]byte("pw")); err == nil {
		t.Error("the agent accepted a protocol-level unlock")
	}

	keys, err := h.client.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].RecordID != added.RecordID {
		t.Fatalf("the vault holds %d keys after refused mutations", len(keys))
	}
}

func TestAgentHonoursRSASignatureFlags(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(rsaKey, "rsa@test")
	if err != nil {
		t.Fatal(err)
	}
	added, err := h.client.AddKey(ctx, control.AddKeyRequest{PrivateKey: string(pem.EncodeToMemory(block))})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(added.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("unix", h.layout.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)

	data := []byte("exchange hash")
	for flags, want := range map[agent.SignatureFlags]string{
		agent.SignatureFlagRsaSha256: ssh.KeyAlgoRSASHA256,
		agent.SignatureFlagRsaSha512: ssh.KeyAlgoRSASHA512,
	} {
		sig, err := client.SignWithFlags(pub, data, flags)
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		if sig.Format != want {
			t.Errorf("flags %d produced %s, want %s", flags, sig.Format, want)
		}
		if err := pub.Verify(data, sig); err != nil {
			t.Errorf("%s signature does not verify: %v", want, err)
		}
	}
}

func TestSecondDaemonRefusesToStart(t *testing.T) {
	h := start(t)
	store, err := vault.OpenStore(h.layout.Database())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr, err := vault.NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	second := New(mgr, h.layout, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := second.Run(ctx); err == nil {
		t.Fatal("a second daemon started for the same vault")
	} else if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("unexpected failure: %v", err)
	}
}

func TestInstallUninstallThroughCLIPaths(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Generate(ctx); err != nil {
		t.Fatal(err)
	}
	existing := "Host legacy\n    HostName old.example.com\n"
	if err := os.MkdirAll(filepath.Dir(h.layout.UserSSHConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.UserSSHConfig, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sshconfig.Install(h.layout); err != nil {
		t.Fatal(err)
	}
	st, err := h.client.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ConfigInstalled {
		t.Fatal("status does not report the installed Include")
	}
	if _, err := sshconfig.Uninstall(h.layout); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.layout.Database()); err != nil {
		t.Fatalf("uninstall removed the vault database: %v", err)
	}
	body, err := os.ReadFile(h.layout.UserSSHConfig)
	if err != nil || string(body) != existing {
		t.Fatalf("uninstall did not restore the user's config exactly: %q", body)
	}
}

func TestAgentSignsAndListsThroughTheExportedAgent(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.AddKey(ctx, control.AddKeyRequest{
		PrivateKey: string(testKeyPEM(t, "agent-direct")),
	}); err != nil {
		t.Fatal(err)
	}

	a := h.daemon.Agent()
	if a == nil {
		t.Fatal("the daemon exposes no agent")
	}
	signers, err := a.Signers()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 {
		t.Fatalf("Signers returned %d signers", len(signers))
	}

	data := []byte("the message to sign")
	sig, err := a.Sign(signers[0].PublicKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := signers[0].PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}

	if _, err := h.client.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Signers(); err == nil {
		t.Fatal("Signers answered while locked")
	}
	if _, err := a.Sign(signers[0].PublicKey(), data); err == nil {
		t.Fatal("Sign answered while locked")
	}
}

func TestALongSocketPathIsExplained(t *testing.T) {
	long := "/tmp/" + strings.Repeat("x", 200) + "/control.sock"
	_, err := listenUnix(long)
	if err == nil {
		t.Fatal("a socket path longer than the system allows was accepted")
	}
	for _, want := range []string{"bytes", "at most", "--runtime"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("the error is still the bare kernel message: %v", err)
	}
}

func TestTheDaemonAnnouncesOnlyAfterItIsListening(t *testing.T) {
	root := t.TempDir()
	layout := paths.Layout{
		Data:          filepath.Join(root, "data"),
		SSH:           filepath.Join(root, "ssh"),
		UserSSHConfig: filepath.Join(root, "ssh", "config"),
		Runtime:       "/tmp/" + strings.Repeat("y", 200),
	}
	store, err := vault.OpenStore(layout.Database())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr, kit, err := vault.Init(store, vault.InitOptions{Password: []byte(testPassword), DeviceLabel: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.ConfirmRecoveryKit(kit.Checksum(), kit); err != nil {
		t.Fatal(err)
	}
	d := New(mgr, layout, nil)
	announced := false
	d.OnListening(func() { announced = true })

	if err := d.Run(context.Background()); err == nil {
		t.Fatal("the daemon ran with a socket path it cannot bind")
	}
	if announced {
		t.Fatal("the daemon announced it was running before it could listen")
	}
}
