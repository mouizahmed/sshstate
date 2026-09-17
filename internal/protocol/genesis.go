package protocol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const (
	GenesisDomain        = "sshstate.genesis.v1"
	GenesisFormatVersion = 1
)

type Genesis struct {
	Domain        string `json:"domain"`
	FormatVersion int    `json:"format_version"`
	Suite         string `json:"suite"`
	VaultID       ID     `json:"vault_id"`
	CreatedAt     string `json:"created_at"`

	FirstDeviceID        ID     `json:"first_device_id"`
	FirstDeviceVerifyKey Bytes  `json:"first_device_verify_key"`
	FirstDeviceRecipient string `json:"first_device_recipient"`

	RecoveryVerifyKey Bytes  `json:"recovery_verify_key"`
	RecoveryRecipient string `json:"recovery_recipient"`
}

func (g *Genesis) Validate(expectSuite string) error {
	if g == nil {
		return errors.New("genesis is missing")
	}
	if g.Domain != GenesisDomain {
		return fmt.Errorf("genesis domain %q is not %q", g.Domain, GenesisDomain)
	}
	if g.FormatVersion != GenesisFormatVersion {
		return fmt.Errorf("unsupported genesis format version %d", g.FormatVersion)
	}
	if g.Suite != expectSuite {
		return fmt.Errorf("vault uses suite %q, this build implements %q", g.Suite, expectSuite)
	}
	if err := g.VaultID.check("vault_id"); err != nil {
		return err
	}
	if err := g.FirstDeviceID.check("first_device_id"); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, g.CreatedAt); err != nil {
		return fmt.Errorf("genesis created_at is not RFC 3339: %w", err)
	}
	if len(g.FirstDeviceVerifyKey) == 0 || g.FirstDeviceRecipient == "" {
		return errors.New("genesis is missing the first device's public keys")
	}
	if len(g.RecoveryVerifyKey) == 0 || g.RecoveryRecipient == "" {
		return errors.New("genesis is missing the recovery kit's public keys")
	}
	return nil
}

func (g *Genesis) Digest() ([]byte, error) {
	canon, err := Canonical(g)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}
