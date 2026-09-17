package enroll

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const MaxSnapshotBytes = crypto.MaxStreamBytes

func SealBundle(b *protocol.Bundle, signer *crypto.SigningKey, recipient *crypto.Recipient) ([]byte, error) {
	if err := b.Validate(crypto.SuiteID); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if recipient == nil {
		return nil, errors.New("bundle: no recipient")
	}
	if recipient.String() != b.Recipient {
		return nil, errors.New("bundle: the recipient it names is not the one it is sealed to")
	}
	msg, err := b.SigningInput()
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(protocol.BundleSignatureDomain, msg)
	if err != nil {
		return nil, err
	}
	body, err := protocol.Canonical(&protocol.SignedBundle{Bundle: *b, Signature: sig})
	if err != nil {
		return nil, err
	}
	return crypto.Seal(body, recipient)
}

func SealSignedBundle(sb *protocol.SignedBundle, recipient *crypto.Recipient) ([]byte, error) {
	if sb == nil || len(sb.Signature) == 0 {
		return nil, errors.New("bundle: unsigned")
	}
	if recipient == nil {
		return nil, errors.New("bundle: no recipient")
	}
	if recipient.String() != sb.Bundle.Recipient {
		return nil, errors.New("bundle: the recipient it names is not the one it is sealed to")
	}
	if err := sb.Bundle.Validate(crypto.SuiteID); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	body, err := protocol.Canonical(sb)
	if err != nil {
		return nil, err
	}
	return crypto.Seal(body, recipient)
}

func OpenBundle(sealed []byte, identity *crypto.EncryptionKey, expectSender *crypto.VerifyKey) (*protocol.Bundle, error) {
	raw, err := crypto.Open(identity, sealed)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	var signed protocol.SignedBundle
	if err := protocol.StrictUnmarshal(raw, &signed); err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	if err := signed.Bundle.Validate(crypto.SuiteID); err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	msg, err := signed.Bundle.SigningInput()
	if err != nil {
		return nil, err
	}
	if err := crypto.Verify(expectSender, protocol.BundleSignatureDomain, msg, signed.Signature); err != nil {
		return nil, errors.New("open bundle: the bundle is not signed by the device that should have sent it")
	}
	if identity.Recipient().String() != signed.Bundle.Recipient {
		return nil, errors.New("open bundle: the bundle was addressed to a different recipient")
	}
	return &signed.Bundle, nil
}

func BuildSnapshot(envs []*protocol.Envelope) ([]byte, error) {
	sorted := append([]*protocol.Envelope(nil), envs...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].Context.RecordID < sorted[j-1].Context.RecordID; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var b bytes.Buffer
	for _, env := range sorted {
		line, err := protocol.Canonical(env)
		if err != nil {
			return nil, err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if b.Len() > MaxSnapshotBytes {
		return nil, fmt.Errorf("snapshot is %d bytes, the limit is %d", b.Len(), MaxSnapshotBytes)
	}
	return b.Bytes(), nil
}

func ParseSnapshot(raw []byte) ([]*protocol.Envelope, error) {
	if len(raw) > MaxSnapshotBytes {
		return nil, fmt.Errorf("snapshot is %d bytes, the limit is %d", len(raw), MaxSnapshotBytes)
	}
	var out []*protocol.Envelope
	for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var env protocol.Envelope
		if err := protocol.StrictUnmarshal([]byte(line), &env); err != nil {
			return nil, fmt.Errorf("snapshot line %d: %w", i+1, err)
		}
		out = append(out, &env)
	}
	return out, nil
}

func SealSnapshot(snapshot []byte, recipient *crypto.Recipient) (sealed []byte, digest []byte, length protocol.Counter, err error) {
	sealed, err = crypto.SealBounded(snapshot, MaxSnapshotBytes, recipient)
	if err != nil {
		return nil, nil, 0, err
	}
	sum := sha256.Sum256(snapshot)
	return sealed, sum[:], protocol.Counter(len(snapshot)), nil
}

func OpenSnapshot(sealed []byte, identity *crypto.EncryptionKey, digest []byte, length protocol.Counter) ([]*protocol.Envelope, error) {
	raw, err := crypto.OpenBounded(identity, sealed, MaxSnapshotBytes)
	if err != nil {
		return nil, fmt.Errorf("open snapshot: %w", err)
	}
	if protocol.Counter(len(raw)) != length {
		return nil, fmt.Errorf("open snapshot: %d bytes, the bundle says %s", len(raw), length)
	}
	sum := sha256.Sum256(raw)
	if !bytes.Equal(sum[:], digest) {
		return nil, errors.New("open snapshot: the snapshot does not match the digest the bundle binds")
	}
	return ParseSnapshot(raw)
}
