package vault

import (
	"errors"
	"fmt"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type Keys struct {
	Epoch    protocol.Counter
	Metadata *crypto.SymmetricKey
	Secret   *crypto.SymmetricKey
}

func NewKeys() (*Keys, error) {
	metadata, err := crypto.NewSymmetricKey()
	if err != nil {
		return nil, fmt.Errorf("vault metadata key: %w", err)
	}
	secret, err := crypto.NewSymmetricKey()
	if err != nil {
		metadata.Wipe()
		return nil, fmt.Errorf("vault secret key: %w", err)
	}
	return &Keys{Epoch: 1, Metadata: metadata, Secret: secret}, nil
}

func (k *Keys) For(t protocol.RecordType) (*crypto.SymmetricKey, error) {
	if k == nil || k.Metadata == nil || k.Secret == nil {
		return nil, errors.New("vault is locked")
	}
	if t.SecretScoped() {
		return k.Secret, nil
	}
	return k.Metadata, nil
}

func (k *Keys) Wipe() {
	if k == nil {
		return
	}
	k.Metadata.Wipe()
	k.Secret.Wipe()
	k.Metadata = nil
	k.Secret = nil
}

func (k Keys) String() string { return fmt.Sprintf("vault.Keys{epoch:%s, keys:[redacted]}", k.Epoch) }

func (k Keys) GoString() string { return k.String() }
