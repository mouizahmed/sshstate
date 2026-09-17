package crypto

import (
	"bytes"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

const SuiteID = "sshstate.suite.v1"

const SeedSize = mldsa.PrivateKeySize

const maxDomainLen = 255

func params() mldsa.Parameters { return mldsa.MLDSA65() }

type SigningKey struct{ sk *mldsa.PrivateKey }

type VerifyKey struct{ pk *mldsa.PublicKey }

func GenerateSigningKey() (*SigningKey, error) {
	sk, err := mldsa.GenerateKey(params())
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &SigningKey{sk: sk}, nil
}

func SigningKeyFromSeed(seed []byte) (*SigningKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("signing seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	sk, err := mldsa.NewPrivateKey(params(), seed)
	if err != nil {
		return nil, fmt.Errorf("parse signing seed: %w", err)
	}
	return &SigningKey{sk: sk}, nil
}

func (k *SigningKey) Seed() []byte { return k.sk.Bytes() }

func (k SigningKey) String() string { return "[redacted signing key]" }

func (k SigningKey) GoString() string { return k.String() }

func (k *SigningKey) Verifier() *VerifyKey { return &VerifyKey{pk: k.sk.PublicKey()} }

func (k *SigningKey) Sign(domain string, msg []byte) ([]byte, error) {
	opts, err := signOpts(domain)
	if err != nil {
		return nil, err
	}
	sig, err := k.sk.Sign(nil, msg, opts)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return sig, nil
}

func (v *VerifyKey) Bytes() []byte { return v.pk.Bytes() }

func VerifyKeyFromBytes(b []byte) (*VerifyKey, error) {
	if want := params().PublicKeySize(); len(b) != want {
		return nil, fmt.Errorf("verify key must be %d bytes, got %d", want, len(b))
	}
	pk, err := mldsa.NewPublicKey(params(), b)
	if err != nil {
		return nil, fmt.Errorf("parse verify key: %w", err)
	}
	return &VerifyKey{pk: pk}, nil
}

func Verify(v *VerifyKey, domain string, msg, sig []byte) error {
	opts, err := signOpts(domain)
	if err != nil {
		return err
	}
	if want := params().SignatureSize(); len(sig) != want {
		return fmt.Errorf("signature must be %d bytes, got %d", want, len(sig))
	}
	return mldsa.Verify(v.pk, msg, sig, opts)
}

func signOpts(domain string) (*mldsa.Options, error) {
	if domain == "" {
		return nil, errors.New("signing domain must not be empty")
	}
	if len(domain) > maxDomainLen {
		return nil, fmt.Errorf("signing domain must be at most %d bytes, got %d", maxDomainLen, len(domain))
	}
	return &mldsa.Options{Context: domain}, nil
}

type EncryptionKey struct{ id *age.HybridIdentity }

type Recipient struct{ r *age.HybridRecipient }

func GenerateEncryptionKey() (*EncryptionKey, error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}
	return &EncryptionKey{id: id}, nil
}

func ParseEncryptionKey(s string) (*EncryptionKey, error) {
	id, err := age.ParseHybridIdentity(s)
	if err != nil {
		return nil, fmt.Errorf("parse encryption key: %w", err)
	}
	return &EncryptionKey{id: id}, nil
}

func (k *EncryptionKey) ExportSecret() string { return k.id.String() }

func (k EncryptionKey) String() string { return "[redacted encryption key]" }

func (k EncryptionKey) GoString() string { return k.String() }

func (k *EncryptionKey) Recipient() *Recipient { return &Recipient{r: k.id.Recipient()} }

func (r *Recipient) String() string { return r.r.String() }

func ParseRecipient(s string) (*Recipient, error) {
	r, err := age.ParseHybridRecipient(s)
	if err != nil {
		return nil, fmt.Errorf("parse recipient: %w", err)
	}
	return &Recipient{r: r}, nil
}

func Seal(plaintext []byte, recipients ...*Recipient) ([]byte, error) {
	if len(plaintext) > maxEnvelope {
		return nil, fmt.Errorf("seal: plaintext exceeds %d bytes", maxEnvelope)
	}
	if len(recipients) == 0 {
		return nil, errors.New("seal: at least one recipient required")
	}
	rs := make([]age.Recipient, 0, len(recipients))
	for _, r := range recipients {
		if r == nil || r.r == nil {
			return nil, errors.New("seal: nil recipient")
		}
		rs = append(rs, r.r)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(envelopeWriter{&buf}, rs...)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return buf.Bytes(), nil
}

const maxEnvelope = 1 << 20

type envelopeWriter struct{ buf *bytes.Buffer }

func (w envelopeWriter) Write(p []byte) (int, error) {
	if len(p) > maxEnvelope-w.buf.Len() {
		return 0, fmt.Errorf("envelope exceeds %d bytes", maxEnvelope)
	}
	return w.buf.Write(p)
}

const MaxStreamBytes = 256 << 20

func SealBounded(plaintext []byte, max int, recipients ...*Recipient) ([]byte, error) {
	if max <= 0 || max > MaxStreamBytes {
		max = MaxStreamBytes
	}
	if len(plaintext) > max {
		return nil, fmt.Errorf("seal: payload is %d bytes, the limit is %d", len(plaintext), max)
	}
	if len(recipients) == 0 {
		return nil, errors.New("seal: at least one recipient required")
	}
	rs := make([]age.Recipient, 0, len(recipients))
	for _, r := range recipients {
		if r == nil || r.r == nil {
			return nil, errors.New("seal: nil recipient")
		}
		rs = append(rs, r.r)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return buf.Bytes(), nil
}

func OpenBounded(k *EncryptionKey, ciphertext []byte, max int) ([]byte, error) {
	if k == nil || k.id == nil {
		return nil, errors.New("open: nil encryption key")
	}
	if max <= 0 || max > MaxStreamBytes {
		max = MaxStreamBytes
	}
	if len(ciphertext) > max+(1<<20) {
		return nil, fmt.Errorf("open: ciphertext exceeds %d bytes", max)
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), k.id)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	if len(out) > max {
		return nil, fmt.Errorf("open: plaintext exceeds %d bytes", max)
	}
	return out, nil
}

func Open(k *EncryptionKey, ciphertext []byte) ([]byte, error) {
	if k == nil || k.id == nil {
		return nil, errors.New("open: nil encryption key")
	}
	if len(ciphertext) > maxEnvelope {
		return nil, fmt.Errorf("open: envelope exceeds %d bytes", maxEnvelope)
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), k.id)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	out, err := io.ReadAll(io.LimitReader(r, maxEnvelope))
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return out, nil
}
