// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	IdleTimeout = 15 * time.Minute
	HardTimeout = 8 * time.Hour
)

const MetaRecoveryConfirmed = "recovery_kit_confirmed"

const RecoveryConfirmDomain = "sshstate.recovery-kit-confirm.v1"

const recoveryChallengeTTL = 2 * time.Minute

var (
	ErrLocked              = errors.New("vault is locked")
	ErrNotInitialized      = errors.New("sshstate is not set up on this machine; run: sshstate setup")
	ErrRecoveryUnconfirmed = errors.New("recovery kit has not been confirmed; run: sshstate confirm-recovery --kit <path>")
)

type session struct {
	keys         *Keys
	signing      *crypto.SigningKey
	encryption   *crypto.EncryptionKey
	hardDeadline time.Time
	idleDeadline time.Time
}

type Manager struct {
	store   *Store
	genesis *protocol.Genesis

	vaultID  protocol.ID
	deviceID protocol.ID

	mu                      sync.Mutex
	current                 *session
	recoveryChallenge       []byte
	recoveryChallengeExpiry time.Time
	now                     func() time.Time
}

func NewManager(store *Store) (*Manager, error) {
	ok, err := store.Initialized()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotInitialized
	}
	g, _, err := store.Genesis()
	if err != nil {
		return nil, err
	}
	if err := g.Validate(crypto.SuiteID); err != nil {
		return nil, err
	}
	deviceID, err := store.Meta(MetaDeviceID)
	if err != nil {
		return nil, err
	}
	return &Manager{
		store:    store,
		genesis:  g,
		vaultID:  g.VaultID,
		deviceID: protocol.ID(deviceID),
	}, nil
}

func (m *Manager) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

type InitOptions struct {
	Password    []byte
	DeviceLabel string
}

func Init(store *Store, opts InitOptions) (*Manager, *Kit, error) {
	if len(opts.Password) == 0 {
		return nil, nil, errors.New("init: a device unlock password is required")
	}
	initialized, err := store.Initialized()
	if err != nil {
		return nil, nil, err
	}
	if initialized {
		return nil, nil, errors.New("a vault already exists here; refusing to replace it")
	}

	vaultID, err := protocol.NewID()
	if err != nil {
		return nil, nil, err
	}
	deviceID, err := protocol.NewID()
	if err != nil {
		return nil, nil, err
	}

	deviceSigning, err := crypto.GenerateSigningKey()
	if err != nil {
		return nil, nil, fmt.Errorf("device signing key: %w", err)
	}
	deviceEncryption, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("device encryption key: %w", err)
	}
	vaultKeys, err := NewKeys()
	if err != nil {
		return nil, nil, err
	}

	kit, recoverySigning, recoveryEncryption, err := NewKit(vaultID)
	if err != nil {
		return nil, nil, err
	}

	createdAt := time.Now().UTC().Format(time.RFC3339)
	g := &protocol.Genesis{
		Domain:               protocol.GenesisDomain,
		FormatVersion:        protocol.GenesisFormatVersion,
		Suite:                crypto.SuiteID,
		VaultID:              vaultID,
		CreatedAt:            createdAt,
		FirstDeviceID:        deviceID,
		FirstDeviceVerifyKey: deviceSigning.Verifier().Bytes(),
		FirstDeviceRecipient: deviceEncryption.Recipient().String(),
		RecoveryVerifyKey:    recoverySigning.Verifier().Bytes(),
		RecoveryRecipient:    recoveryEncryption.Recipient().String(),
	}
	if err := g.Validate(crypto.SuiteID); err != nil {
		return nil, nil, fmt.Errorf("init: %w", err)
	}
	digest, err := g.Digest()
	if err != nil {
		return nil, nil, err
	}
	kit.GenesisDigest = digest

	wrappers := map[string][]byte{
		crypto.PurposeDeviceSigningKey:    deviceSigning.Seed(),
		crypto.PurposeDeviceEncryptionKey: []byte(deviceEncryption.ExportSecret()),
		crypto.PurposeVaultMetadataKey:    vaultKeys.Metadata[:],
		crypto.PurposeVaultSecretKey:      vaultKeys.Secret[:],
	}
	if err := store.PutGenesis(g); err != nil {
		return nil, nil, err
	}
	for purpose, secret := range wrappers {
		w, err := crypto.Wrap(opts.Password, vaultID, deviceID, purpose, secret)
		if err != nil {
			return nil, nil, fmt.Errorf("wrap %s: %w", purpose, err)
		}
		if err := store.PutWrapper(purpose, w); err != nil {
			return nil, nil, err
		}
	}
	if err := store.PutDevice(Device{
		ID:         deviceID,
		VerifyKey:  deviceSigning.Verifier().Bytes(),
		Recipient:  deviceEncryption.Recipient().String(),
		Status:     DeviceActive,
		EnrolledAt: createdAt,
	}); err != nil {
		return nil, nil, err
	}
	root, err := membership.Root(g, deviceSigning, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := store.PutMembershipEvents([]protocol.SignedMembershipEvent{root}); err != nil {
		return nil, nil, err
	}
	for k, v := range map[string]string{
		MetaVaultID:           string(vaultID),
		MetaDeviceID:          string(deviceID),
		MetaKeyEpoch:          vaultKeys.Epoch.String(),
		MetaDeviceLabel:       opts.DeviceLabel,
		MetaRecoveryConfirmed: "false",
	} {
		if err := store.SetMeta(k, v); err != nil {
			return nil, nil, err
		}
	}

	m := &Manager{store: store, genesis: g, vaultID: vaultID, deviceID: deviceID}
	m.current = m.newSession(vaultKeys, deviceSigning, deviceEncryption)
	return m, kit, nil
}

func (m *Manager) newSession(keys *Keys, signing *crypto.SigningKey, encryption *crypto.EncryptionKey) *session {
	now := m.clock()
	return &session{
		keys:         keys,
		signing:      signing,
		encryption:   encryption,
		hardDeadline: now.Add(HardTimeout),
		idleDeadline: now.Add(IdleTimeout),
	}
}

func (m *Manager) ConfirmRecoveryKit(checksum string, kit *Kit) error {
	if kit == nil {
		return errors.New("no recovery kit to confirm")
	}
	if checksum != kit.Checksum() {
		return errors.New("that checksum does not match the recovery kit")
	}
	return m.store.SetMeta(MetaRecoveryConfirmed, "true")
}

func (m *Manager) RecoveryChallenge() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	m.recoveryChallenge = nonce
	m.recoveryChallengeExpiry = m.clock().Add(recoveryChallengeTTL)
	return nonce, nil
}

func (m *Manager) ConfirmRecoveryProof(nonce, signature []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	outstanding := m.recoveryChallenge
	expiry := m.recoveryChallengeExpiry
	m.recoveryChallenge = nil
	m.recoveryChallengeExpiry = time.Time{}

	if len(outstanding) == 0 {
		return errors.New("no recovery challenge is outstanding")
	}
	if m.clock().After(expiry) {
		return errors.New("the recovery challenge has expired; try again")
	}
	if subtle.ConstantTimeCompare(outstanding, nonce) != 1 {
		return errors.New("that answer is for a different challenge")
	}
	vk, err := crypto.VerifyKeyFromBytes(m.genesis.RecoveryVerifyKey)
	if err != nil {
		return fmt.Errorf("genesis recovery key: %w", err)
	}
	if err := crypto.Verify(vk, RecoveryConfirmDomain, nonce, signature); err != nil {
		return errors.New("that recovery kit does not belong to this vault")
	}
	return m.store.SetMeta(MetaRecoveryConfirmed, "true")
}

func (m *Manager) RecoveryConfirmed() bool {
	v, err := m.store.Meta(MetaRecoveryConfirmed)
	return err == nil && v == "true"
}

var ErrWrongPassword = errors.New("wrong password, or this vault does not belong to this device")

func (m *Manager) ChangePassword(current, next []byte) error {
	if len(next) == 0 {
		return errors.New("the new password is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rewrapped := make(map[string]*crypto.Wrapper, 4)
	for _, purpose := range []string{
		crypto.PurposeDeviceSigningKey,
		crypto.PurposeDeviceEncryptionKey,
		crypto.PurposeVaultMetadataKey,
		crypto.PurposeVaultSecretKey,
	} {
		w, err := m.store.Wrapper(purpose)
		if err != nil {
			return err
		}
		secret, err := w.Unwrap(current, m.vaultID, m.deviceID, purpose)
		if err != nil {
			return ErrWrongPassword
		}
		next, err := crypto.Wrap(next, m.vaultID, m.deviceID, purpose, secret)
		clear(secret)
		if err != nil {
			return fmt.Errorf("wrap %s: %w", purpose, err)
		}
		rewrapped[purpose] = next
	}
	return m.store.PutWrappers(rewrapped)
}

func (m *Manager) Unlock(password []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	get := func(purpose string) ([]byte, error) {
		w, err := m.store.Wrapper(purpose)
		if err != nil {
			return nil, err
		}
		return w.Unwrap(password, m.vaultID, m.deviceID, purpose)
	}

	signingSeed, err := get(crypto.PurposeDeviceSigningKey)
	if err != nil {
		return err
	}
	signing, err := crypto.SigningKeyFromSeed(signingSeed)
	clear(signingSeed)
	if err != nil {
		return err
	}
	if string(signing.Verifier().Bytes()) != string(m.genesis.FirstDeviceVerifyKey) &&
		m.deviceID == m.genesis.FirstDeviceID {
		return errors.New("stored device signing key does not match the one pinned in genesis")
	}

	identity, err := get(crypto.PurposeDeviceEncryptionKey)
	if err != nil {
		return err
	}
	encryption, err := crypto.ParseEncryptionKey(string(identity))
	clear(identity)
	if err != nil {
		return err
	}

	metadataRaw, err := get(crypto.PurposeVaultMetadataKey)
	if err != nil {
		return err
	}
	metadata, err := crypto.SymmetricKeyFromBytes(metadataRaw)
	clear(metadataRaw)
	if err != nil {
		return err
	}
	secretRaw, err := get(crypto.PurposeVaultSecretKey)
	if err != nil {
		metadata.Wipe()
		return err
	}
	secret, err := crypto.SymmetricKeyFromBytes(secretRaw)
	clear(secretRaw)
	if err != nil {
		metadata.Wipe()
		return err
	}

	epoch, err := m.store.Meta(MetaKeyEpoch)
	if err != nil {
		metadata.Wipe()
		secret.Wipe()
		return err
	}
	var e protocol.Counter
	if err := e.UnmarshalJSON([]byte(`"` + epoch + `"`)); err != nil {
		metadata.Wipe()
		secret.Wipe()
		return fmt.Errorf("stored key epoch is malformed: %w", err)
	}

	if m.current != nil {
		m.current.keys.Wipe()
	}
	m.current = m.newSession(&Keys{Epoch: e, Metadata: metadata, Secret: secret}, signing, encryption)
	return nil
}

func (m *Manager) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockLocked()
}

func (m *Manager) lockLocked() {
	if m.current == nil {
		return
	}
	m.current.keys.Wipe()
	m.current = nil
}

func (m *Manager) Touch() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		m.current.idleDeadline = m.clock().Add(IdleTimeout)
	}
}

func (m *Manager) session() (*session, error) {
	if m.current == nil {
		return nil, ErrLocked
	}
	now := m.clock()
	if now.After(m.current.hardDeadline) || now.After(m.current.idleDeadline) {
		m.lockLocked()
		return nil, ErrLocked
	}
	return m.current, nil
}

type Status struct {
	VaultID           protocol.ID
	DeviceID          protocol.ID
	DeviceLabel       string
	Unlocked          bool
	KeyEpoch          protocol.Counter
	RecoveryConfirmed bool
	IdleExpiresAt     time.Time
	HardExpiresAt     time.Time
	Hosts             int
	Keys              int
	KnownHosts        int
	Pending           int
	Relay             string
	LastExportPath    string
	LastExportAt      string
}

func (m *Manager) Status() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	label, _ := m.store.Meta(MetaDeviceLabel)
	st := Status{
		VaultID:           m.vaultID,
		DeviceID:          m.deviceID,
		DeviceLabel:       label,
		RecoveryConfirmed: m.RecoveryConfirmed(),
	}
	if s, err := m.session(); err == nil {
		st.Unlocked = true
		st.KeyEpoch = s.keys.Epoch
		st.IdleExpiresAt = s.idleDeadline
		st.HardExpiresAt = s.hardDeadline
	}
	for _, c := range []struct {
		t protocol.RecordType
		n *int
	}{
		{protocol.RecordHost, &st.Hosts},
		{protocol.RecordKey, &st.Keys},
		{protocol.RecordKnownHost, &st.KnownHosts},
	} {
		recs, err := m.store.LiveRecords(c.t)
		if err != nil {
			return st, err
		}
		*c.n = len(recs)
	}
	pending, err := m.store.Outbox()
	if err != nil {
		return st, err
	}
	st.Pending = len(pending)
	relay, err := m.RelayURL()
	if err != nil {
		return st, err
	}
	st.Relay = relay
	st.LastExportPath, st.LastExportAt = m.LastExport()
	return st, nil
}

func (m *Manager) Store() *Store { return m.store }

func (m *Manager) VaultID() protocol.ID  { return m.vaultID }
func (m *Manager) DeviceID() protocol.ID { return m.deviceID }

func (m *Manager) Genesis() *protocol.Genesis { return m.genesis }

func (m *Manager) MembershipSigner() (membership.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.session()
	if err != nil {
		return membership.Signer{}, err
	}
	return membership.Signer{DeviceID: m.deviceID, Key: s.signing}, nil
}

func (m *Manager) Now() time.Time { return m.clock() }
