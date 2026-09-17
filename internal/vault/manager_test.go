package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/sshkeys"
)

const testPassword = "correct horse battery staple"

func newVault(t *testing.T) (*Manager, *Kit, *Store) {
	t.Helper()
	s := newStore(t)
	m, kit, err := Init(s, InitOptions{Password: []byte(testPassword), DeviceLabel: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryKit(kit.Checksum(), kit); err != nil {
		t.Fatal(err)
	}
	return m, kit, s
}

func testKey(t *testing.T, comment string) *sshkeys.Key {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatal(err)
	}
	k, err := sshkeys.Import(pem.EncodeToMemory(block), nil, comment)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestInitCreatesPinnedVault(t *testing.T) {
	m, kit, s := newVault(t)

	g := m.Genesis()
	if g.Suite != crypto.SuiteID {
		t.Fatalf("genesis pins suite %q, not the implemented one", g.Suite)
	}
	if g.VaultID != m.VaultID() || g.FirstDeviceID != m.DeviceID() {
		t.Fatal("genesis does not describe this vault and device")
	}
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if string(kit.GenesisDigest) != string(digest) {
		t.Fatal("recovery kit does not pin this genesis")
	}

	wrappers, err := s.Wrappers()
	if err != nil {
		t.Fatal(err)
	}
	for purpose, w := range wrappers {
		secret, err := w.Unwrap([]byte(testPassword), m.VaultID(), m.DeviceID(), purpose)
		if err != nil {
			t.Fatalf("%s: %v", purpose, err)
		}
		if strings.Contains(string(secret), kit.EncryptionIdentity) {
			t.Fatalf("%s wrapper retains the recovery identity", purpose)
		}
		if string(secret) == string(kit.SigningSeed) {
			t.Fatalf("%s wrapper retains the recovery signing seed", purpose)
		}
	}
	for _, key := range []string{MetaVaultID, MetaDeviceID, MetaDeviceLabel, MetaKeyEpoch, MetaRecoveryConfirmed} {
		v, _ := s.Meta(key)
		if v == "" {
			continue
		}
		if strings.Contains(v, kit.EncryptionIdentity) || strings.Contains(v, kit.Checksum()) {
			t.Fatalf("meta %q leaks recovery material", key)
		}
	}
}

func TestInitRefusesToReplaceAnExistingVault(t *testing.T) {
	m, _, s := newVault(t)
	_ = m
	if _, _, err := Init(s, InitOptions{Password: []byte("another")}); err == nil {
		t.Fatal("a second init overwrote an existing vault")
	}
}

func TestInitRequiresPassword(t *testing.T) {
	s := newStore(t)
	if _, _, err := Init(s, InitOptions{}); err == nil {
		t.Fatal("initialized without a password")
	}
}

func TestUnlockLockCycle(t *testing.T) {
	m, _, s := newVault(t)
	key := testKey(t, "one")
	if _, err := m.AddKey(key); err != nil {
		t.Fatal(err)
	}

	m.Lock()
	if _, err := m.Keys(); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked vault answered a read: %v", err)
	}
	if _, err := m.AddKey(testKey(t, "two")); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked vault accepted a write: %v", err)
	}

	if err := m.Unlock([]byte("wrong password")); err == nil {
		t.Fatal("unlocked with the wrong password")
	}
	if _, err := m.Keys(); !errors.Is(err, ErrLocked) {
		t.Fatal("a failed unlock left the vault usable")
	}

	if err := m.Unlock([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	keys, err := m.Keys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("after unlock: %d keys, %v", len(keys), err)
	}
	if keys[0].Fingerprint != key.Fingerprint {
		t.Fatal("key did not survive the lock cycle")
	}
	_ = s
}

func TestReopenStartsLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	m, kit, err := Init(s, InitOptions{Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecoveryKit(kit.Checksum(), kit); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddKey(testKey(t, "k")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	m2, err := NewManager(s2)
	if err != nil {
		t.Fatal(err)
	}
	st, err := m2.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Unlocked {
		t.Fatal("reopened vault came back unlocked")
	}
	if st.VaultID != m.VaultID() {
		t.Fatal("reopened a different vault")
	}
	if _, err := m2.Keys(); !errors.Is(err, ErrLocked) {
		t.Fatalf("reopened vault answered a read: %v", err)
	}
	if err := m2.Unlock([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	keys, _ := m2.Keys()
	if len(keys) != 1 {
		t.Fatalf("after reopen and unlock: %d keys", len(keys))
	}
}

func TestIdleAndHardExpiry(t *testing.T) {
	m, _, _ := newVault(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	if err := m.Unlock([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}

	now = now.Add(IdleTimeout - time.Second)
	if _, err := m.AddKey(testKey(t, "a")); err != nil {
		t.Fatalf("expired early: %v", err)
	}
	now = now.Add(IdleTimeout - time.Second)
	if _, err := m.AddKey(testKey(t, "b")); err != nil {
		t.Fatalf("mutation did not refresh idle expiry: %v", err)
	}

	now = now.Add(IdleTimeout - time.Second)
	if _, err := m.Status(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := m.AddKey(testKey(t, "c")); !errors.Is(err, ErrLocked) {
		t.Fatalf("idle expiry did not fire, or Status refreshed it: %v", err)
	}
}

func TestHardExpiryIsNotRefreshable(t *testing.T) {
	m, _, _ := newVault(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	if err := m.Unlock([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	for elapsed := time.Duration(0); elapsed < HardTimeout; elapsed += IdleTimeout / 2 {
		now = now.Add(IdleTimeout / 2)
		if _, err := m.Status(); err != nil {
			t.Fatal(err)
		}
		if _, err := m.AddKey(testKey(t, "k")); err != nil {
			t.Fatalf("expired before the hard deadline at %s: %v", elapsed, err)
		}
	}
	now = now.Add(IdleTimeout)
	if _, err := m.AddKey(testKey(t, "late")); !errors.Is(err, ErrLocked) {
		t.Fatalf("hard expiry never fired: %v", err)
	}
}

func TestMutationsBlockedUntilRecoveryConfirmed(t *testing.T) {
	s := newStore(t)
	m, kit, err := Init(s, InitOptions{Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddKey(testKey(t, "k")); !errors.Is(err, ErrRecoveryUnconfirmed) {
		t.Fatalf("wrote before the recovery kit was confirmed: %v", err)
	}
	if err := m.ConfirmRecoveryKit("WRONGCHECK", kit); err == nil {
		t.Fatal("accepted a wrong checksum")
	}
	if err := m.ConfirmRecoveryKit(kit.Checksum(), kit); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddKey(testKey(t, "k")); err != nil {
		t.Fatal(err)
	}
}

func TestAddKeyDeduplicatesByFingerprint(t *testing.T) {
	m, _, _ := newVault(t)
	k := testKey(t, "first")
	id, err := m.AddKey(k)
	if err != nil {
		t.Fatal(err)
	}
	again := *k
	again.Comment = "second"
	if _, err := m.AddKey(&again); err == nil {
		t.Fatal("added the same key twice")
	}
	keys, _ := m.Keys()
	if len(keys) != 1 || keys[0].RecordID != id {
		t.Fatalf("vault holds %d keys", len(keys))
	}
}

func TestAddHostValidation(t *testing.T) {
	m, _, _ := newVault(t)
	keyID, err := m.AddKey(testKey(t, "k"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.AddHost(HostSpec{
		Alias: "prod", HostName: "10.0.0.5", User: "ubuntu", KeyIDs: []protocol.ID{keyID},
	}); err != nil {
		t.Fatal(err)
	}
	hosts, _ := m.Hosts()
	if len(hosts) != 1 || hosts[0].Port != DefaultPort {
		t.Fatalf("omitted port was not resolved to %d: %+v", DefaultPort, hosts)
	}

	if _, err := m.AddHost(HostSpec{Alias: "prod", HostName: "x", User: "y"}); err == nil {
		t.Fatal("added a duplicate alias")
	}
	if _, err := m.AddHost(HostSpec{
		Alias: "other", HostName: "x", User: "y", KeyIDs: []protocol.ID{protocol.MustNewID()},
	}); err == nil {
		t.Fatal("added a host referencing a key that is not in the vault")
	}
	missing := "nowhere"
	if _, err := m.AddHost(HostSpec{Alias: "jumped", HostName: "x", User: "y", ProxyJump: &missing}); err == nil {
		t.Fatal("added a host whose ProxyJump names no known alias")
	}
	jump := "prod"
	if _, err := m.AddHost(HostSpec{Alias: "behind", HostName: "10.0.0.9", User: "y", ProxyJump: &jump}); err != nil {
		t.Fatalf("rejected a valid ProxyJump: %v", err)
	}
}

func TestKeyViewsCarryNoPrivateMaterial(t *testing.T) {
	m, _, _ := newVault(t)
	k := testKey(t, "k")
	id, err := m.AddKey(k)
	if err != nil {
		t.Fatal(err)
	}
	views, err := m.Keys()
	if err != nil {
		t.Fatal(err)
	}
	rendered := sprintf("%+v", views)
	if strings.Contains(rendered, "PRIVATE KEY") || strings.Contains(rendered, k.PrivateKey) {
		t.Fatal("a key listing carried private key material")
	}
	priv, err := m.PrivateKey(id)
	if err != nil || priv != k.PrivateKey {
		t.Fatalf("agent path cannot load the key: %v", err)
	}
	m.Lock()
	if _, err := m.PrivateKey(id); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked vault released a private key: %v", err)
	}
}

func TestDatabaseHoldsNoPlaintextSecrets(t *testing.T) {
	m, _, s := newVault(t)
	k := testKey(t, "leak-probe")
	if _, err := m.AddKey(k); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddHost(HostSpec{Alias: "prod", HostName: "10.9.9.9", User: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	m.Lock()
	s.Close()

	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := s.Path() + suffix
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for name, needle := range map[string]string{
			"private key":     "PRIVATE KEY",
			"key comment":     "leak-probe",
			"hostname":        "10.9.9.9",
			"user":            "ubuntu",
			"unlock password": testPassword,
		} {
			if strings.Contains(string(body), needle) {
				t.Errorf("%s contains plaintext %s", filepath.Base(path), name)
			}
		}
	}
}

func TestAnAcceptedSnapshotRefusesAnUnsyncedEditToAnExistingHost(t *testing.T) {
	m, _, s := newVault(t)
	id, err := m.AddHost(HostSpec{Alias: "prod", HostName: "10.0.0.5", User: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := m.Snapshot(true)
	if err != nil {
		t.Fatalf("an unsynced new host blocked the snapshot: %v", err)
	}
	if len(snapshot.Records) != 0 {
		t.Fatalf("an unsynced new host was included: %d records", len(snapshot.Records))
	}

	pending, err := s.Outbox()
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range pending {
		if err := s.AcceptOutbox(env, 1); err != nil {
			t.Fatal(err)
		}
	}
	port := 2201
	if err := m.EditHost(id, HostEdit{Port: &port}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Snapshot(true); !errors.Is(err, ErrUnsyncedEdit) {
		t.Fatalf("want ErrUnsyncedEdit for an unsynced edit, got %v", err)
	}
	if _, err := m.Snapshot(false); err != nil {
		t.Fatalf("an export snapshot refused an unsynced edit: %v", err)
	}
}

func TestLocalEditsCannotCreateAJumpLoop(t *testing.T) {
	m, _, _ := newVault(t)
	a, err := m.AddHost(HostSpec{Alias: "a", HostName: "10.0.0.1", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	jumpA := "a"
	b, err := m.AddHost(HostSpec{Alias: "b", HostName: "10.0.0.2", User: "u", ProxyJump: &jumpA})
	if err != nil {
		t.Fatal(err)
	}
	jumpB := "b"
	if err := m.EditHost(a, HostEdit{ProxyJump: &jumpB}); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("an edit that closes a ProxyJump loop was accepted: %v", err)
	}
	self := "b"
	if err := m.EditHost(b, HostEdit{ProxyJump: &self}); err == nil {
		t.Fatalf("a host was allowed to jump through itself: %v", err)
	}
	port := 2222
	if err := m.EditHost(b, HostEdit{Port: &port}); err != nil {
		t.Fatalf("an edit that does not touch the jump was refused: %v", err)
	}
}
