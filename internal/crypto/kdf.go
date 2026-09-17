package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	KDFAlgorithm  = "argon2id"
	KDFSaltSize   = 16
	KDFMemoryKiB  = 64 * 1024
	KDFIterations = 3
	KDFLanes      = 4
)

const (
	maxKDFMemoryKiB  = 1 << 20
	maxKDFIterations = 10
	maxKDFLanes      = 16
)

const WrapperDomain = "sshstate.local-wrapper.v1"

const WrapperFormatVersion = 1

type KDFParams struct {
	Algorithm  string         `json:"algorithm"`
	Version    int            `json:"version"`
	MemoryKiB  uint32         `json:"memory_kib"`
	Iterations uint32         `json:"iterations"`
	Lanes      uint8          `json:"lanes"`
	Salt       protocol.Bytes `json:"salt"`
}

func DefaultKDFParams() (KDFParams, error) {
	salt := make([]byte, KDFSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, fmt.Errorf("kdf salt: %w", err)
	}
	return KDFParams{
		Algorithm:  KDFAlgorithm,
		Version:    argon2.Version,
		MemoryKiB:  KDFMemoryKiB,
		Iterations: KDFIterations,
		Lanes:      KDFLanes,
		Salt:       salt,
	}, nil
}

func (p KDFParams) Validate() error {
	if p.Algorithm != KDFAlgorithm {
		return fmt.Errorf("unsupported local KDF %q", p.Algorithm)
	}
	if p.Version != argon2.Version {
		return fmt.Errorf("unsupported argon2 version %d", p.Version)
	}
	if len(p.Salt) != KDFSaltSize {
		return fmt.Errorf("kdf salt must be %d bytes, got %d", KDFSaltSize, len(p.Salt))
	}
	if p.MemoryKiB == 0 || p.MemoryKiB > maxKDFMemoryKiB {
		return fmt.Errorf("kdf memory %d KiB outside 1..%d", p.MemoryKiB, maxKDFMemoryKiB)
	}
	if p.Iterations == 0 || p.Iterations > maxKDFIterations {
		return fmt.Errorf("kdf iterations %d outside 1..%d", p.Iterations, maxKDFIterations)
	}
	if p.Lanes == 0 || p.Lanes > maxKDFLanes {
		return fmt.Errorf("kdf lanes %d outside 1..%d", p.Lanes, maxKDFLanes)
	}
	return nil
}

func (p KDFParams) DeriveKEK(password []byte) (*SymmetricKey, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, errors.New("unlock password is empty")
	}
	out := argon2.IDKey(password, p.Salt, p.Iterations, p.MemoryKiB, p.Lanes, SymmetricKeySize)
	key, err := SymmetricKeyFromBytes(out)
	clear(out)
	return key, err
}

type WrapperContext struct {
	Domain        string      `json:"domain"`
	FormatVersion int         `json:"format_version"`
	VaultID       protocol.ID `json:"vault_id"`
	DeviceID      protocol.ID `json:"device_id"`
	Purpose       string      `json:"purpose"`
	KDF           KDFParams   `json:"kdf"`
}

const (
	PurposeDeviceSigningKey    = "device-signing-key"
	PurposeDeviceEncryptionKey = "device-encryption-key"
	PurposeVaultMetadataKey    = "vault-metadata-key"
	PurposeVaultSecretKey      = "vault-secret-key"
)

type Wrapper struct {
	FormatVersion int            `json:"format_version"`
	KDF           KDFParams      `json:"kdf"`
	Nonce         protocol.Bytes `json:"nonce"`
	Ciphertext    protocol.Bytes `json:"ciphertext"`
}

func Wrap(password []byte, vaultID, deviceID protocol.ID, purpose string, secret []byte) (*Wrapper, error) {
	params, err := DefaultKDFParams()
	if err != nil {
		return nil, err
	}
	return wrapWith(password, params, vaultID, deviceID, purpose, secret)
}

func wrapWith(password []byte, params KDFParams, vaultID, deviceID protocol.ID, purpose string, secret []byte) (*Wrapper, error) {
	if purpose == "" {
		return nil, errors.New("wrap: purpose is required")
	}
	if len(secret) == 0 {
		return nil, errors.New("wrap: secret is empty")
	}
	kek, err := params.DeriveKEK(password)
	if err != nil {
		return nil, err
	}
	defer kek.Wipe()

	aad, err := wrapperAAD(params, vaultID, deviceID, purpose)
	if err != nil {
		return nil, err
	}
	nonce, ct, err := SealAEAD(kek, secret, aad)
	if err != nil {
		return nil, err
	}
	return &Wrapper{
		FormatVersion: WrapperFormatVersion,
		KDF:           params,
		Nonce:         nonce,
		Ciphertext:    ct,
	}, nil
}

func (w *Wrapper) Unwrap(password []byte, vaultID, deviceID protocol.ID, purpose string) ([]byte, error) {
	if w == nil {
		return nil, errors.New("unwrap: nil wrapper")
	}
	if w.FormatVersion != WrapperFormatVersion {
		return nil, fmt.Errorf("unsupported wrapper format version %d", w.FormatVersion)
	}
	kek, err := w.KDF.DeriveKEK(password)
	if err != nil {
		return nil, err
	}
	defer kek.Wipe()

	aad, err := wrapperAAD(w.KDF, vaultID, deviceID, purpose)
	if err != nil {
		return nil, err
	}
	pt, err := OpenAEAD(kek, w.Nonce, w.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("unwrap: wrong password or wrapper does not belong to this device")
	}
	return pt, nil
}

func Rewrap(newPassword []byte, vaultID, deviceID protocol.ID, purpose string, secret []byte) (*Wrapper, error) {
	return Wrap(newPassword, vaultID, deviceID, purpose, secret)
}

func wrapperAAD(params KDFParams, vaultID, deviceID protocol.ID, purpose string) ([]byte, error) {
	if !vaultID.Valid() || !deviceID.Valid() {
		return nil, errors.New("wrapper context needs valid vault and device ids")
	}
	return protocol.Canonical(WrapperContext{
		Domain:        WrapperDomain,
		FormatVersion: WrapperFormatVersion,
		VaultID:       vaultID,
		DeviceID:      deviceID,
		Purpose:       purpose,
		KDF:           params,
	})
}
