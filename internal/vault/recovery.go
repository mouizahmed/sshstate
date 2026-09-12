// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"bufio"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const KitFormatVersion = 1

const kitChecksumDomain = "sshstate.recovery-kit-checksum.v1"

const KitChecksumChars = 10

var kitBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type Kit struct {
	FormatVersion      int
	VaultID            protocol.ID
	GenesisDigest      []byte
	SigningSeed        []byte
	EncryptionIdentity string
}

func NewKit(vaultID protocol.ID) (*Kit, *crypto.SigningKey, *crypto.EncryptionKey, error) {
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("recovery signing key: %w", err)
	}
	ek, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("recovery encryption key: %w", err)
	}
	return &Kit{
		FormatVersion:      KitFormatVersion,
		VaultID:            vaultID,
		SigningSeed:        sk.Seed(),
		EncryptionIdentity: ek.ExportSecret(),
	}, sk, ek, nil
}

func (k *Kit) Checksum() string {
	h := sha256.New()
	h.Write([]byte(kitChecksumDomain))
	h.Write([]byte(k.VaultID))
	h.Write(k.GenesisDigest)
	h.Write(k.SigningSeed)
	h.Write([]byte(k.EncryptionIdentity))
	return kitBase32.EncodeToString(h.Sum(nil))[:KitChecksumChars]
}

func (k *Kit) Marshal() string {
	var b strings.Builder
	b.WriteString("# sshstate recovery kit\n")
	b.WriteString("#\n")
	b.WriteString("# Anyone holding this file can read this vault and authorize a new device.\n")
	b.WriteString("# Store it offline. It is not a backup: it recovers access to data the\n")
	b.WriteString("# relay still holds, and cannot restore data that no longer exists.\n")
	b.WriteString("#\n")
	fmt.Fprintf(&b, "format_version: %d\n", k.FormatVersion)
	fmt.Fprintf(&b, "vault_id: %s\n", k.VaultID)
	fmt.Fprintf(&b, "genesis_digest: %s\n", hex.EncodeToString(k.GenesisDigest))
	fmt.Fprintf(&b, "signing_seed: %s\n", base64.RawURLEncoding.EncodeToString(k.SigningSeed))
	fmt.Fprintf(&b, "encryption_identity: %s\n", k.EncryptionIdentity)
	fmt.Fprintf(&b, "checksum: %s\n", k.Checksum())
	return b.String()
}

func ParseKit(text string) (*Kit, error) {
	fields := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("recovery kit line is not name: value: %q", line)
		}
		name = strings.TrimSpace(name)
		if _, dup := fields[name]; dup {
			return nil, fmt.Errorf("recovery kit names %q twice", name)
		}
		fields[name] = strings.TrimSpace(value)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read recovery kit: %w", err)
	}

	var version int
	if _, err := fmt.Sscanf(fields["format_version"], "%d", &version); err != nil {
		return nil, errors.New("recovery kit has no format_version")
	}
	if version != KitFormatVersion {
		return nil, fmt.Errorf("unsupported recovery kit format version %d", version)
	}
	k := &Kit{
		FormatVersion:      version,
		VaultID:            protocol.ID(fields["vault_id"]),
		EncryptionIdentity: fields["encryption_identity"],
	}
	if !k.VaultID.Valid() {
		return nil, errors.New("recovery kit has no valid vault_id")
	}
	digest, err := hex.DecodeString(fields["genesis_digest"])
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("recovery kit genesis_digest is malformed")
	}
	k.GenesisDigest = digest
	seed, err := base64.RawURLEncoding.DecodeString(fields["signing_seed"])
	if err != nil || len(seed) != crypto.SeedSize {
		return nil, errors.New("recovery kit signing_seed is malformed")
	}
	k.SigningSeed = seed
	if k.EncryptionIdentity == "" {
		return nil, errors.New("recovery kit has no encryption_identity")
	}
	if got := fields["checksum"]; got != k.Checksum() {
		return nil, fmt.Errorf("recovery kit checksum is %q but its contents produce %q; the file is damaged or edited", got, k.Checksum())
	}
	return k, nil
}

func (k *Kit) Keys() (*crypto.SigningKey, *crypto.EncryptionKey, error) {
	sk, err := crypto.SigningKeyFromSeed(k.SigningSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("recovery signing key: %w", err)
	}
	ek, err := crypto.ParseEncryptionKey(k.EncryptionIdentity)
	if err != nil {
		return nil, nil, fmt.Errorf("recovery encryption key: %w", err)
	}
	return sk, ek, nil
}

func (k Kit) String() string {
	return fmt.Sprintf("vault.Kit{vault:%s, secrets:[redacted]}", k.VaultID)
}

func (k Kit) GoString() string { return k.String() }
