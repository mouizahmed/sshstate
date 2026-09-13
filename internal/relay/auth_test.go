// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

func emptyStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func newVault(t *testing.T) (*protocol.Genesis, protocol.SignedMembershipEvent) {
	t.Helper()
	first := newDevice(t)
	recovery := newDevice(t)
	g := &protocol.Genesis{
		Domain:               protocol.GenesisDomain,
		FormatVersion:        protocol.GenesisFormatVersion,
		Suite:                crypto.SuiteID,
		VaultID:              protocol.MustNewID(),
		CreatedAt:            stamp,
		FirstDeviceID:        first.id,
		FirstDeviceVerifyKey: first.signing.Verifier().Bytes(),
		FirstDeviceRecipient: first.enc.Recipient().String(),
		RecoveryVerifyKey:    recovery.signing.Verifier().Bytes(),
		RecoveryRecipient:    recovery.enc.Recipient().String(),
	}
	root, err := membership.Root(g, first.signing, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return g, root
}

func secret(b byte) []byte { return bytes.Repeat([]byte{b}, BootstrapSecretBytes) }

func TestBootstrapCreatesTheVaultOnce(t *testing.T) {
	store := emptyStore(t)
	g, root := newVault(t)

	if err := store.Bootstrap(secret(1), g, root); err == nil {
		t.Fatal("bootstrap succeeded with no configured secret")
	} else {
		mustCode(t, err, protocol.CodeNotAuthorized)
	}

	if err := store.SetBootstrapSecret(secret(1)); err != nil {
		t.Fatal(err)
	}
	if consumed, err := store.BootstrapConsumed(); err != nil || consumed {
		t.Fatalf("bootstrap reported consumed before use (%v, %v)", consumed, err)
	}
	mustCode(t, store.Bootstrap(secret(2), g, root), protocol.CodeNotAuthorized)

	if err := store.Bootstrap(secret(1), g, root); err != nil {
		t.Fatal(err)
	}
	if consumed, err := store.BootstrapConsumed(); err != nil || !consumed {
		t.Fatalf("bootstrap did not record consumption (%v, %v)", consumed, err)
	}

	other, otherRoot := newVault(t)
	mustCode(t, store.Bootstrap(secret(1), other, otherRoot), protocol.CodeBootstrapConsumed)
}

func TestFailedBootstrapLeavesNoVault(t *testing.T) {
	store := emptyStore(t)
	if err := store.SetBootstrapSecret(secret(1)); err != nil {
		t.Fatal(err)
	}
	g, root := newVault(t)
	mustCode(t, store.Bootstrap(secret(9), g, root), protocol.CodeNotAuthorized)

	if _, err := store.VaultID(); err == nil {
		t.Fatal("a rejected bootstrap created a vault")
	}
	if consumed, err := store.BootstrapConsumed(); err != nil || consumed {
		t.Fatal("a rejected bootstrap consumed the secret")
	}
	if err := store.Bootstrap(secret(1), g, root); err != nil {
		t.Fatalf("the correct secret was refused afterwards: %v", err)
	}
}

func TestBootstrapRejectsAnInvalidVaultWithoutConsuming(t *testing.T) {
	store := emptyStore(t)
	if err := store.SetBootstrapSecret(secret(1)); err != nil {
		t.Fatal(err)
	}
	g, root := newVault(t)
	broken := *g
	broken.RecoveryRecipient = ""
	mustCode(t, store.Bootstrap(secret(1), &broken, root), protocol.CodeInvalidRequest)
	if consumed, err := store.BootstrapConsumed(); err != nil || consumed {
		t.Fatal("an invalid genesis consumed the bootstrap secret")
	}
	if err := store.Bootstrap(secret(1), g, root); err != nil {
		t.Fatal(err)
	}
}

func TestSettingTheSecretIsIdempotentAndCannotReopenRegistration(t *testing.T) {
	store := emptyStore(t)
	if err := store.SetBootstrapSecret(secret(1)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetBootstrapSecret(secret(1)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetBootstrapSecret(secret(2)); err != nil {
		t.Fatal(err)
	}
	g, root := newVault(t)
	if err := store.Bootstrap(secret(2), g, root); err != nil {
		t.Fatal(err)
	}
	mustCode(t, store.SetBootstrapSecret(secret(3)), protocol.CodeBootstrapConsumed)
	if err := store.SetBootstrapSecret(secret(2)); err != nil {
		t.Fatalf("restating the consumed secret failed: %v", err)
	}
}

func TestReadBootstrapSecret(t *testing.T) {
	dir := t.TempDir()
	want := secret(7)
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte(EncodeBootstrapSecret(want)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBootstrapSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read %x", got)
	}

	padded := base64.StdEncoding.EncodeToString(want)
	standard, err := DecodeBootstrapSecret(padded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(standard, want) {
		t.Fatal("padded standard base64 decoded to a different secret")
	}

	for name, body := range map[string]string{
		"empty":      "   \n",
		"not base64": "!!!!",
		"too short":  base64.RawURLEncoding.EncodeToString([]byte("short")),
	} {
		if _, err := DecodeBootstrapSecret(body); err == nil {
			t.Errorf("a %s secret was accepted", name)
		}
	}
	if _, err := ReadBootstrapSecret(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing secret file was accepted")
	}
}

func TestNonceStoreRejectsReplay(t *testing.T) {
	store := emptyStore(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return now }
	device := protocol.MustNewID()
	until := now.Add(6 * time.Minute)

	fresh, err := store.Use(device, "nonce-a", until)
	if err != nil || !fresh {
		t.Fatalf("first use reported (%v, %v)", fresh, err)
	}
	fresh, err = store.Use(device, "nonce-a", until)
	if err != nil || fresh {
		t.Fatalf("a replay reported (%v, %v)", fresh, err)
	}

	fresh, err = store.Use(protocol.MustNewID(), "nonce-a", until)
	if err != nil || !fresh {
		t.Fatalf("another device's identical nonce reported (%v, %v)", fresh, err)
	}
}

func TestNonceStoreSweepsExpiredEntries(t *testing.T) {
	store := emptyStore(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return now }
	device := protocol.MustNewID()

	if _, err := store.Use(device, "old", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := store.Use(device, "new", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := store.db.QueryRow(`SELECT count(*) FROM request_nonce`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d nonces remain, want 1", n)
	}
}

func TestNonceStoreIsAtomicUnderConcurrency(t *testing.T) {
	store := emptyStore(t)
	device := protocol.MustNewID()
	until := time.Now().Add(6 * time.Minute)

	const attempts = 16
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first int
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh, err := store.Use(device, "contested", until)
			if err != nil {
				t.Error(err)
				return
			}
			if fresh {
				mu.Lock()
				first++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if first != 1 {
		t.Fatalf("%d of %d concurrent uses were told they were the first", first, attempts)
	}
}
