// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

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

	if err := store.PutGenesis(genesis); err != nil {
		return nil, nil, err
	}
	for purpose, material := range map[string][]byte{
		crypto.PurposeDeviceSigningKey:    deviceSigning.Seed(),
		crypto.PurposeDeviceEncryptionKey: []byte(deviceEncryption.ExportSecret()),
		crypto.PurposeVaultMetadataKey:    metadata[:],
		crypto.PurposeVaultSecretKey:      secret[:],
	} {
		w, err := crypto.Wrap(opts.Password, genesis.VaultID, deviceID, purpose, material)
		if err != nil {
			return nil, nil, fmt.Errorf("restore: wrap %s: %w", purpose, err)
		}
		if err := store.PutWrapper(purpose, w); err != nil {
			return nil, nil, err
		}
	}
	if err := store.PutMembershipEvents(chain.Events()); err != nil {
		return nil, nil, err
	}
	for _, d := range chain.Devices() {
		status := DeviceActive
		if d.Revoked {
			status = DeviceRevoked
		}
		if err := store.PutDevice(Device{
			ID:         d.ID,
			VerifyKey:  d.VerifyKey.Bytes(),
			Recipient:  d.Recipient,
			Status:     status,
			EnrolledAt: d.EnrolledAt,
		}); err != nil {
			return nil, nil, err
		}
	}

	records := append(append([]*protocol.Envelope{}, archive.Contents.Records...),
		archive.Contents.Conflicts...)
	if err := store.ApplyRemoteBatch(archive.Manifest.Checkpoint.Seq.String(), records); err != nil {
		return nil, nil, fmt.Errorf("restore: install records: %w", err)
	}

	for k, v := range map[string]string{
		MetaVaultID:           string(genesis.VaultID),
		MetaDeviceID:          string(deviceID),
		MetaKeyEpoch:          bundle.KeyEpoch.String(),
		MetaDeviceLabel:       opts.DeviceLabel,
		MetaRecoveryConfirmed: "true",
	} {
		if err := store.SetMeta(k, v); err != nil {
			return nil, nil, err
		}
	}

	m := &Manager{store: store, genesis: genesis, vaultID: genesis.VaultID, deviceID: deviceID}
	m.current = m.newSession(keys, deviceSigning, deviceEncryption)
	return m, &RestoreResult{
		VaultID:  genesis.VaultID,
		DeviceID: deviceID,
		Records:  len(records),
		Seq:      archive.Manifest.Checkpoint.Seq,
	}, nil
}
