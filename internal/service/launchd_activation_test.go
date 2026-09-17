//go:build darwin

package service_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/paths"
	"github.com/mouizahmed/sshstate/internal/service"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func TestLaunchdSocketActivation(t *testing.T) {
	if os.Getenv("SSHSTATE_LAUNCHD_TEST") != "1" {
		t.Skip("set SSHSTATE_LAUNCHD_TEST=1 to register a real launchd job")
	}

	root, err := os.MkdirTemp("/tmp", "sssl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	layout := paths.Layout{
		Data:          root + "/data",
		SSH:           root + "/ssh",
		UserSSHConfig: root + "/ssh/config",
		Runtime:       root,
	}

	store, err := vault.OpenStore(layout.Database())
	if err != nil {
		t.Fatal(err)
	}
	mgr, kit, err := vault.Init(store, vault.InitOptions{Password: []byte("pw"), DeviceLabel: "launchd-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.ConfirmRecoveryKit(kit.Checksum(), kit); err != nil {
		t.Fatal(err)
	}
	vaultID := string(mgr.VaultID())
	store.Close()

	binary := root + "/sshstate"
	build := exec.Command("go", "build", "-o", binary, "github.com/mouizahmed/sshstate/cmd/sshstate")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build the daemon binary: %v", err)
	}

	body, err := service.RenderPlist(binary, layout, nil)
	if err != nil {
		t.Fatal(err)
	}
	label := service.Label + ".test"
	body = strings.ReplaceAll(body, service.Label, label)
	plistPath := root + "/agent.plist"
	if err := os.WriteFile(plistPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	domain := fmt.Sprintf("gui/%d", os.Getuid())
	_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
	t.Cleanup(func() { _ = exec.Command("launchctl", "bootout", domain+"/"+label).Run() })

	if out, err := exec.Command("launchctl", "bootstrap", domain, plistPath).CombinedOutput(); err != nil {
		t.Fatalf("launchctl bootstrap: %v: %s", err, out)
	}

	var before os.FileInfo
	socketDeadline := time.Now().Add(30 * time.Second)
	for {
		before, err = os.Stat(layout.ControlSocket())
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			t.Fatalf("stat launchd control socket: %v", err)
		}
		if time.Now().After(socketDeadline) {
			t.Fatalf("launchd did not create the control socket: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	client := control.NewClient(layout.ControlSocket())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var st *control.StatusResponse
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err = client.Status(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the activated daemon never answered: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if out, err := exec.Command("pgrep", "-f", binary).Output(); err != nil || len(out) == 0 {
		t.Fatal("status succeeded but no daemon process exists")
	}
	after, err := os.Stat(layout.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("the daemon replaced launchd's socket instead of adopting it")
	}
	if st.VaultID != vaultID {
		t.Fatalf("the activated daemon serves vault %s, expected %s", st.VaultID, vaultID)
	}
	if st.Unlocked {
		t.Fatal("the activated daemon came up unlocked")
	}
	if _, err := client.Unlock(ctx, "pw"); err != nil {
		t.Fatalf("unlock through the activated daemon: %v", err)
	}
	if _, err := client.Lock(ctx); err != nil {
		t.Fatal(err)
	}
}
