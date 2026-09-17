package sshkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func marshal(t *testing.T, key any, comment string) []byte {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestImportEd25519(t *testing.T) {
	raw := marshal(t, ed25519Key(t), "me@laptop")
	k, err := Import(raw, nil, "me@laptop")
	if err != nil {
		t.Fatal(err)
	}
	if k.Algorithm != "ssh-ed25519" {
		t.Fatalf("algorithm is %q", k.Algorithm)
	}
	if !strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint is %q", k.Fingerprint)
	}
	if !strings.HasPrefix(k.PublicKey, "ssh-ed25519 ") || !strings.HasSuffix(k.PublicKey, " me@laptop") {
		t.Fatalf("public line is %q", k.PublicKey)
	}
	if !strings.Contains(k.PrivateKey, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatal("private key was not normalized to OpenSSH format")
	}
	if _, err := Signer(k.PrivateKey); err != nil {
		t.Fatalf("stored key does not load: %v", err)
	}
}

func TestSameKeyGivesSameFingerprint(t *testing.T) {
	key := ed25519Key(t)
	a, err := Import(marshal(t, key, "one"), nil, "one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Import(marshal(t, key, "two"), nil, "two")
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("comment changed the fingerprint: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
}

func TestImportRSAStrengthPolicy(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(marshal(t, weak, ""), nil, ""); err == nil {
		t.Fatal("accepted a 1024-bit RSA key")
	} else if !strings.Contains(err.Error(), "2048") {
		t.Fatalf("unhelpful message: %v", err)
	}

	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := Import(marshal(t, strong, ""), nil, "")
	if err != nil {
		t.Fatalf("rejected a 2048-bit RSA key: %v", err)
	}
	if k.Algorithm != "ssh-rsa" {
		t.Fatalf("algorithm is %q", k.Algorithm)
	}
}

func TestImportECDSANISTCurves(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Import(marshal(t, key, ""), nil, ""); err != nil {
			t.Errorf("rejected %s: %v", curve.Params().Name, err)
		}
	}
}

func TestEncryptedSourceKeyFlow(t *testing.T) {
	raw := marshal(t, ed25519Key(t), "")
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(ed25519Key(t), "", []byte("source pass"))
	if err != nil {
		t.Fatal(err)
	}
	encPEM := pem.EncodeToMemory(encrypted)

	if _, err := Import(encPEM, nil, ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("want ErrPassphraseRequired, got %v", err)
	}
	if _, err := Import(encPEM, []byte("wrong"), ""); err == nil {
		t.Fatal("accepted the wrong passphrase")
	} else if !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Fatalf("unhelpful message: %v", err)
	}
	k, err := Import(encPEM, []byte("source pass"), "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(k.PrivateKey, "bcrypt") || strings.Contains(k.PrivateKey, "aes") {
		t.Fatal("stored key is still passphrase encrypted")
	}
	if _, err := Signer(k.PrivateKey); err != nil {
		t.Fatalf("decrypted key does not load: %v", err)
	}
	_ = raw
}

func TestPublicKeyDigestIsPathSafe(t *testing.T) {
	k, err := Import(marshal(t, ed25519Key(t), ""), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PublicKeyDigest(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatalf("digest is %d characters, want 64 hex", len(digest))
	}
	if strings.ContainsAny(digest, "/+= :") {
		t.Fatalf("digest %q is not path safe", digest)
	}
}

func TestRejectsGarbageAndUnsupportedTypes(t *testing.T) {
	if _, err := Import([]byte("not a key"), nil, ""); err == nil {
		t.Fatal("accepted a non-key file")
	}
	if _, err := Import(nil, nil, ""); err == nil {
		t.Fatal("accepted an empty file")
	}
}
