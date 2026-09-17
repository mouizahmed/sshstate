package vault

import (
	"errors"
	"fmt"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/export"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type RestoreOptions struct {
	Archive     []byte
	Kit         *Kit
	Password    []byte
	DeviceLabel string
	Publish     func(protocol.SignedMembershipEvent) error
}

type RestoreResult struct {
	VaultID  protocol.ID
	DeviceID protocol.ID
	Records  int
	Seq      protocol.Counter
}

func Restore(store *Store, opts RestoreOptions) (*Manager, *RestoreResult, error) {
	if opts.Kit == nil {
		return nil, nil, errors.New("restore: a recovery kit is required")
	}
	if len(opts.Password) == 0 {
		return nil, nil, errors.New("restore: a new device unlock password is required")
	}
	initialized, err := store.Initialized()
	if err != nil {
		return nil, nil, err
	}
	if initialized {
		return nil, nil, errors.New("a vault already exists here; restore into a machine that has none")
	}

	identity, err := crypto.ParseEncryptionKey(opts.Kit.EncryptionIdentity)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: recovery kit: %w", err)
	}
	archive, err := export.Open(opts.Archive, identity, opts.Kit.GenesisDigest)
	if err != nil {
		return nil, nil, err
	}
	genesis := archive.Contents.Genesis
	if genesis.VaultID != opts.Kit.VaultID {
		return nil, nil, errors.New("restore: this kit belongs to a different vault")
	}
	bundle := archive.Contents.Bundle.Bundle
	metadata, err := crypto.SymmetricKeyFromBytes(bundle.MetadataKey)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: metadata key: %w", err)
	}
	secret, err := crypto.SymmetricKeyFromBytes(bundle.SecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: secret key: %w", err)
	}
	keys := &Keys{Epoch: bundle.KeyEpoch, Metadata: metadata, Secret: secret}

	deviceID, err := protocol.NewID()
	if err != nil {
		return nil, nil, err
	}
	deviceSigning, err := crypto.GenerateSigningKey()
	if err != nil {
		return nil, nil, fmt.Errorf("restore: device signing key: %w", err)
	}
	deviceEncryption, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("restore: device encryption key: %w", err)
	}
	recoverySigning, err := crypto.SigningKeyFromSeed(opts.Kit.SigningSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: recovery signing key: %w", err)
	}

	chain, err := membership.Validate(genesis, archive.Contents.Membership)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: membership chain: %w", err)
	}
	now := time.Now()
	enrol, err := chain.RecoveryEnroll(recoverySigning, membership.DeviceKeys{
		ID:        deviceID,
		VerifyKey: deviceSigning.Verifier().Bytes(),
		Recipient: deviceEncryption.Recipient().String(),
	}, now)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: authorize the replacement device: %w", err)
	}
	chain, err = chain.Append(enrol)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: %w", err)
	}
	records := append(append([]*protocol.Envelope{}, archive.Contents.Records...),
		archive.Contents.Conflicts...)
	inst, err := installation(genesis, chain, deviceID, opts.Password, map[string][]byte{
		crypto.PurposeDeviceSigningKey:    deviceSigning.Seed(),
		crypto.PurposeDeviceEncryptionKey: []byte(deviceEncryption.ExportSecret()),
		crypto.PurposeVaultMetadataKey:    metadata[:],
		crypto.PurposeVaultSecretKey:      secret[:],
	})
	if err != nil {
		return nil, nil, fmt.Errorf("restore: %w", err)
	}
	inst.Heads = records
	inst.Cursor = archive.Manifest.Checkpoint.Seq.String()
	inst.Meta = map[string]string{
		MetaVaultID:           string(genesis.VaultID),
		MetaDeviceID:          string(deviceID),
		MetaKeyEpoch:          bundle.KeyEpoch.String(),
		MetaDeviceLabel:       opts.DeviceLabel,
		MetaRecoveryConfirmed: "true",
	}
	var announce func() error
	if opts.Publish != nil {
		announce = func() error {
			if err := opts.Publish(enrol); err != nil {
				return fmt.Errorf("announce the replacement device: %w", err)
			}
			return nil
		}
	}
	if err := store.Install(inst, announce); err != nil {
		return nil, nil, fmt.Errorf("restore: %w", err)
	}

	m := &Manager{store: store, genesis: genesis, vaultID: genesis.VaultID, deviceID: deviceID}
	m.current = m.newSession(keys, deviceSigning, deviceEncryption)
	return m, &RestoreResult{
		VaultID:  genesis.VaultID,
		DeviceID: deviceID,
		Records:  LiveCount(records),
		Seq:      archive.Manifest.Checkpoint.Seq,
	}, nil
}

type JoinOptions struct {
	Genesis     *protocol.Genesis
	Bundle      *protocol.Bundle
	Membership  []protocol.SignedMembershipEvent
	Records     []*protocol.Envelope
	DeviceID    protocol.ID
	Signing     *crypto.SigningKey
	Encryption  *crypto.EncryptionKey
	Password    []byte
	DeviceLabel string
}

func Join(store *Store, opts JoinOptions) (*Manager, error) {
	if opts.Genesis == nil || opts.Bundle == nil {
		return nil, errors.New("join: incomplete enrollment")
	}
	if len(opts.Password) == 0 {
		return nil, errors.New("join: a device unlock password is required")
	}
	initialized, err := store.Initialized()
	if err != nil {
		return nil, err
	}
	if initialized {
		return nil, errors.New("a vault already exists here; refusing to replace it")
	}

	metadata, err := crypto.SymmetricKeyFromBytes(opts.Bundle.MetadataKey)
	if err != nil {
		return nil, fmt.Errorf("join: metadata key: %w", err)
	}
	secret, err := crypto.SymmetricKeyFromBytes(opts.Bundle.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("join: secret key: %w", err)
	}
	keys := &Keys{Epoch: opts.Bundle.KeyEpoch, Metadata: metadata, Secret: secret}

	chain, err := membership.Validate(opts.Genesis, opts.Membership)
	if err != nil {
		return nil, fmt.Errorf("join: membership chain: %w", err)
	}
	if !chain.Authorized(opts.DeviceID) {
		return nil, errors.New("join: the chain does not authorize this device")
	}

	inst, err := installation(opts.Genesis, chain, opts.DeviceID, opts.Password, map[string][]byte{
		crypto.PurposeDeviceSigningKey:    opts.Signing.Seed(),
		crypto.PurposeDeviceEncryptionKey: []byte(opts.Encryption.ExportSecret()),
		crypto.PurposeVaultMetadataKey:    metadata[:],
		crypto.PurposeVaultSecretKey:      secret[:],
	})
	if err != nil {
		return nil, fmt.Errorf("join: %w", err)
	}
	inst.Heads = opts.Records
	inst.Cursor = opts.Bundle.Checkpoint.Seq.String()
	inst.Meta = map[string]string{
		MetaVaultID:           string(opts.Genesis.VaultID),
		MetaDeviceID:          string(opts.DeviceID),
		MetaKeyEpoch:          opts.Bundle.KeyEpoch.String(),
		MetaDeviceLabel:       opts.DeviceLabel,
		MetaRecoveryConfirmed: "true",
	}
	if err := store.Install(inst, nil); err != nil {
		return nil, fmt.Errorf("join: install the snapshot: %w", err)
	}

	m := &Manager{store: store, genesis: opts.Genesis, vaultID: opts.Genesis.VaultID, deviceID: opts.DeviceID}
	m.current = m.newSession(keys, opts.Signing, opts.Encryption)
	return m, nil
}

func installation(genesis *protocol.Genesis, chain *membership.Chain, deviceID protocol.ID, password []byte, secrets map[string][]byte) (Installation, error) {
	inst := Installation{
		Genesis:    genesis,
		Wrappers:   make(map[string]*crypto.Wrapper, len(secrets)),
		Membership: chain.Events(),
	}
	for purpose, material := range secrets {
		w, err := crypto.Wrap(password, genesis.VaultID, deviceID, purpose, material)
		if err != nil {
			return Installation{}, fmt.Errorf("wrap %s: %w", purpose, err)
		}
		inst.Wrappers[purpose] = w
	}
	for _, d := range chain.Devices() {
		status := DeviceActive
		if d.Revoked {
			status = DeviceRevoked
		}
		inst.Devices = append(inst.Devices, Device{
			ID:         d.ID,
			VerifyKey:  d.VerifyKey.Bytes(),
			Recipient:  d.Recipient,
			Status:     status,
			EnrolledAt: d.EnrolledAt,
		})
	}
	return inst, nil
}
