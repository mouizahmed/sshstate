package crypto

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"filippo.io/age"
)

const testDomain = "sshstate.record.v1"

func TestSignVerifyRoundTrip(t *testing.T) {
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("canonical signing input")
	sig, err := k.Sign(testDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(k.Verifier(), testDomain, msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestDomainSeparation(t *testing.T) {
	k, _ := GenerateSigningKey()
	msg := []byte("canonical signing input")
	sig, err := k.Sign(testDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(k.Verifier(), "sshstate.membership.v1", msg, sig); err == nil {
		t.Fatal("signature verified under a different domain")
	}
}

func TestEmptyDomainRejected(t *testing.T) {
	k, _ := GenerateSigningKey()
	if _, err := k.Sign("", []byte("x")); err == nil {
		t.Fatal("empty signing domain accepted")
	}
}

func TestOversizedDomainRejected(t *testing.T) {
	k, _ := GenerateSigningKey()
	if _, err := k.Sign(strings.Repeat("d", maxDomainLen+1), []byte("x")); err == nil {
		t.Fatal("oversized signing domain accepted")
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	k, _ := GenerateSigningKey()
	msg := []byte("canonical signing input")
	sig, _ := k.Sign(testDomain, msg)
	for _, i := range []int{0, len(sig) / 2, len(sig) - 1} {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 0x01
		if err := Verify(k.Verifier(), testDomain, msg, bad); err == nil {
			t.Fatalf("tampered signature accepted (byte %d)", i)
		}
	}
}

func TestTamperedMessageRejected(t *testing.T) {
	k, _ := GenerateSigningKey()
	sig, _ := k.Sign(testDomain, []byte("original"))
	if err := Verify(k.Verifier(), testDomain, []byte("modified"), sig); err == nil {
		t.Fatal("signature accepted over a different message")
	}
}

func TestWrongSignerRejected(t *testing.T) {
	a, _ := GenerateSigningKey()
	b, _ := GenerateSigningKey()
	msg := []byte("canonical signing input")
	sig, _ := a.Sign(testDomain, msg)
	if err := Verify(b.Verifier(), testDomain, msg, sig); err == nil {
		t.Fatal("signature verified under an unrelated key")
	}
}

func TestSigningKeySeedRoundTrip(t *testing.T) {
	k, _ := GenerateSigningKey()
	seed := k.Seed()
	if len(seed) != SeedSize {
		t.Fatalf("seed is %d bytes, want %d", len(seed), SeedSize)
	}
	restored, err := SigningKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("canonical signing input")
	sig, _ := restored.Sign(testDomain, msg)
	if err := Verify(k.Verifier(), testDomain, msg, sig); err != nil {
		t.Fatalf("key restored from seed produced an unverifiable signature: %v", err)
	}
}

func TestMalformedKeyMaterialRejected(t *testing.T) {
	if _, err := SigningKeyFromSeed(make([]byte, SeedSize-1)); err == nil {
		t.Fatal("short seed accepted")
	}
	if _, err := VerifyKeyFromBytes([]byte{1, 2, 3}); err == nil {
		t.Fatal("short verify key accepted")
	}
	if _, err := ParseEncryptionKey("not-an-age-key"); err == nil {
		t.Fatal("malformed encryption key accepted")
	}
}

func TestVerifyKeyBytesRoundTrip(t *testing.T) {
	k, _ := GenerateSigningKey()
	b := k.Verifier().Bytes()
	vk, err := VerifyKeyFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("canonical signing input")
	sig, _ := k.Sign(testDomain, msg)
	if err := Verify(vk, testDomain, msg, sig); err != nil {
		t.Fatalf("re-parsed verify key rejected a valid signature: %v", err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("vault key bundle")
	ct, err := Seal(payload, k.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(k, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round-tripped payload differs")
	}
}

func TestEncryptionKeyStringRoundTrip(t *testing.T) {
	k, _ := GenerateEncryptionKey()
	restored, err := ParseEncryptionKey(k.ExportSecret())
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := Seal([]byte("bundle"), k.Recipient())
	if _, err := Open(restored, ct); err != nil {
		t.Fatalf("key restored from its encoding could not open its own envelope: %v", err)
	}
	if restored.Recipient().String() != k.Recipient().String() {
		t.Fatal("recipient derived from restored key differs")
	}
}

func TestRecoveryKitSecretStaysShort(t *testing.T) {
	k, _ := GenerateEncryptionKey()
	if got := len(k.ExportSecret()); got > 128 {
		t.Fatalf("secret encoding is %d chars; recovery kit assumes it stays short", got)
	}
	if got := len(k.Recipient().String()); got < 1000 {
		t.Logf("recipient encoding is %d chars (expected ~1959)", got)
	}
}

func TestWrongIdentityCannotOpen(t *testing.T) {
	a, _ := GenerateEncryptionKey()
	b, _ := GenerateEncryptionKey()
	ct, _ := Seal([]byte("bundle"), a.Recipient())
	if _, err := Open(b, ct); err == nil {
		t.Fatal("unrelated identity opened the envelope")
	}
}

func TestMultipleRecipients(t *testing.T) {
	a, _ := GenerateEncryptionKey()
	b, _ := GenerateEncryptionKey()
	payload := []byte("bundle for two devices")
	ct, err := Seal(payload, a.Recipient(), b.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]*EncryptionKey{"a": a, "b": b} {
		got, err := Open(k, ct)
		if err != nil {
			t.Fatalf("recipient %s could not open: %v", name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("recipient %s got wrong plaintext", name)
		}
	}
}

func TestSealRequiresRecipient(t *testing.T) {
	if _, err := Seal([]byte("x")); err == nil {
		t.Fatal("seal with no recipients accepted")
	}
}

func TestClassicalRecipientCannotRideAlong(t *testing.T) {
	hybrid, _ := GenerateEncryptionKey()
	classical, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, err = age.Encrypt(&buf, hybrid.Recipient().r, classical.Recipient())
	if err == nil {
		t.Fatal("age accepted a mixed post-quantum and classical recipient set")
	}
	if !strings.Contains(err.Error(), "post-quantum") {
		t.Fatalf("mixing rejected for an unexpected reason: %v", err)
	}
}

func TestParseRecipientRejectsClassical(t *testing.T) {
	classical, _ := age.GenerateX25519Identity()
	if _, err := ParseRecipient(classical.Recipient().String()); err == nil {
		t.Fatal("classical age recipient accepted as a suite recipient")
	}
}

func TestOversizedEnvelopeRejected(t *testing.T) {
	k, _ := GenerateEncryptionKey()
	if _, err := Open(k, make([]byte, maxEnvelope+1)); err == nil {
		t.Fatal("oversized envelope accepted")
	}
}

func TestSigningKeyFormattingRedactsSeed(t *testing.T) {
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	seed := strings.Trim(fmt.Sprintf("%v", k.Seed()), "[]")
	for _, value := range []any{k, *k} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			got := fmt.Sprintf(format, value)
			if strings.Contains(got, seed) || !strings.Contains(got, "redacted") {
				t.Errorf("%s did not redact signing key", format)
			}
		}
	}
}

func TestEncryptionKeyFormattingRedactsSecret(t *testing.T) {
	k, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{k, *k} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			got := fmt.Sprintf(format, value)
			if strings.Contains(got, k.ExportSecret()) || !strings.Contains(got, "redacted") {
				t.Errorf("%s did not redact encryption key", format)
			}
		}
	}
}

func TestEnvelopeSizeBoundary(t *testing.T) {
	k, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), maxEnvelope-4096)
	ct, err := Seal(payload, k.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(k, ct)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("near-limit round trip failed: %v", err)
	}
	for _, size := range []int{maxEnvelope, maxEnvelope + 1} {
		ct, err := Seal(bytes.Repeat([]byte("x"), size), k.Recipient())
		if err == nil || ct != nil {
			t.Fatalf("Seal accepted oversized envelope for %d plaintext bytes", size)
		}
	}
	recipients := make([]*Recipient, 8)
	for i := range recipients {
		recipients[i] = k.Recipient()
	}
	if ct, err := Seal(payload, recipients...); err == nil || ct != nil {
		t.Fatal("recipient overhead bypassed envelope size limit")
	}
}

func TestSuiteIDPresent(t *testing.T) {
	if SuiteID == "" {
		t.Fatal("SuiteID must be set; it is bound into genesis and envelope context")
	}
}
