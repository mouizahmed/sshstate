package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/enroll"
	"github.com/mouizahmed/sshstate/internal/httpsig"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relayclient"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const pairPoll = time.Second

func runPair(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "pair")
	label := fs.String("label", defaultDeviceLabel(), "label for this device")
	positional, err := fs.parsePositional(args, 2)
	if err != nil {
		return err
	}
	relayURL, vaultID := positional[0], protocol.ID(positional[1])
	if !vaultID.Valid() {
		return fmt.Errorf("%q is not a vault id", positional[1])
	}

	store, err := vault.OpenStore(env.Layout.Database())
	if err != nil {
		return err
	}
	defer store.Close()
	if initialized, err := store.Initialized(); err != nil {
		return err
	} else if initialized {
		return fmt.Errorf("a vault already exists at %s; pairing would replace it", env.Layout.Database())
	}

	deviceID, err := protocol.NewID()
	if err != nil {
		return err
	}
	signing, err := crypto.GenerateSigningKey()
	if err != nil {
		return err
	}
	encryption, err := crypto.GenerateEncryptionKey()
	if err != nil {
		return err
	}
	identity := enroll.Identity{DeviceID: deviceID, Signing: signing, Encryption: encryption}

	client, err := relayclient.New(relayclient.Options{
		BaseURL: strings.TrimSuffix(relayURL, "/"),
		Signer: &httpsig.Signer{
			VaultID:  vaultID,
			DeviceID: deviceID,
			Key:      signing,
		},
	})
	if err != nil {
		return err
	}
	joiner, err := enroll.Begin(ctx, client, vaultID, identity, time.Now)
	if err != nil {
		return err
	}

	env.printf("Pairing session %s\n\n", joiner.SessionID())
	env.printf("On a machine that already has this vault, run:\n")
	env.printf("  sshstate approve %s\n\n", joiner.SessionID())
	env.printf("Waiting for it...\n")

	if err := pollUntil(ctx, protocol.PairingLifetime, func() (bool, error) {
		_, err := joiner.Transcript(ctx)
		if err == nil {
			return true, nil
		}
		if strings.Contains(err.Error(), "has not confirmed yet") {
			return false, nil
		}
		return false, err
	}); err != nil {
		return err
	}

	fingerprint, err := joiner.Fingerprint()
	if err != nil {
		return err
	}
	ok, err := env.compareFingerprint(fingerprint)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("pairing cancelled; nothing was transferred")
	}
	if err := joiner.Confirm(ctx); err != nil {
		return err
	}

	env.printf("\nConfirmed. Waiting for the other device to hand over the keys...\n")
	var delivery *enroll.Delivery
	if err := pollUntil(ctx, protocol.PairingLifetime, func() (bool, error) {
		d, err := joiner.Receive(ctx)
		if err == nil {
			delivery = d
			return true, nil
		}
		if errors.Is(err, enroll.ErrNotDelivered) {
			return false, nil
		}
		return false, err
	}); err != nil {
		return err
	}

	password, err := env.ReadSecret("New device unlock password for this machine: ")
	if err != nil {
		return err
	}
	defer clear(password)
	again, err := env.ReadSecret("Repeat password: ")
	if err != nil {
		return err
	}
	defer clear(again)
	if string(password) != string(again) {
		return errors.New("passwords do not match")
	}

	mgr, err := vault.Join(store, vault.JoinOptions{
		Genesis:     delivery.Genesis,
		Bundle:      delivery.Bundle,
		Membership:  delivery.Membership,
		Records:     delivery.Snapshot,
		DeviceID:    deviceID,
		Signing:     signing,
		Encryption:  encryption,
		Password:    password,
		DeviceLabel: *label,
	})
	if err != nil {
		return err
	}
	if err := mgr.SetRelayURL(strings.TrimSuffix(relayURL, "/")); err != nil {
		return err
	}
	recordRelayHistory(ctx, mgr, client)
	if err := joiner.Acknowledge(ctx); err != nil {
		env.warnf("The vault is installed, but the pairing session could not be closed: %v\n", err)
	}

	env.printf("\nEnrolled as device %s in vault %s.\n", deviceID, delivery.Genesis.VaultID)
	env.printf("Installed %s from the other machine.\n", count(vault.LiveCount(delivery.Snapshot), "record", "records"))
	env.printf("\nFinish setting up this machine with: sshstate setup\n")
	return nil
}

func runApprove(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "approve")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("approve")
	}
	session, err := env.Client().PairApprove(ctx, fs.Arg(0))
	if err != nil {
		return env.hint(err)
	}

	env.printf("Device %s is asking to join.\n", session.JoinerDeviceID)
	ok, err := env.compareFingerprint(session.Fingerprint)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not approved; no keys were sent")
	}

	env.printf("\nWaiting for the other device to confirm the same fingerprint...\n")
	out, err := env.Client().PairDeliver(ctx, session.SessionID)
	if err != nil {
		return env.hint(err)
	}
	env.printf("\nEnrolled device %s and sent it %s.\n",
		out.DeviceID, count(out.Records, "record", "records"))
	env.printf("It is now an authorized writer. See it with: sshstate devices\n")
	return nil
}

func (e *Env) compareFingerprint(fingerprint string) (bool, error) {
	digest, err := protocol.ParseFingerprint(fingerprint)
	if err != nil {
		return false, err
	}
	block, err := protocol.FormatFingerprint(digest)
	if err != nil {
		return false, err
	}
	e.printf("\n%s\n", block)
	e.printf("Compare all 13 groups with the other device, through a channel that\n")
	e.printf("is not this relay. Checking only the first and last groups is not enough.\n\n")
	return e.confirm("Do both machines show exactly this?")
}

func pollUntil(ctx context.Context, within time.Duration, check func() (bool, error)) error {
	deadline := time.Now().Add(within)
	for {
		done, err := check()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("the pairing session expired before the other device answered")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pairPoll):
		}
	}
}

func recordRelayHistory(ctx context.Context, mgr *vault.Manager, client *relayclient.Client) {
	latest, err := client.Records(ctx, 0, 0, 1)
	if err != nil || latest.History == "" {
		return
	}
	_ = mgr.Store().SetCursor(vault.CursorHistory, latest.History)
}
