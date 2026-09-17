package export

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const Magic = "sshstate-export-v1"

const MaxArchiveBytes = crypto.MaxStreamBytes

type Signer interface {
	Sign(domain string, msg []byte) ([]byte, error)
}

type Contents struct {
	Genesis    *protocol.Genesis
	Membership []protocol.SignedMembershipEvent
	Records    []*protocol.Envelope
	Conflicts  []*protocol.Envelope
	Bundle     *protocol.SignedBundle
}

type Archive struct {
	Manifest protocol.ExportManifest
	Contents Contents
}

func Build(c Contents, checkpoint protocol.Checkpoint, by protocol.ID, signer Signer, recipient *crypto.Recipient, createdAt string) ([]byte, error) {
	if c.Genesis == nil {
		return nil, errors.New("export: no genesis")
	}
	if recipient == nil {
		return nil, errors.New("export: no recovery recipient")
	}
	if recipient.String() != c.Genesis.RecoveryRecipient {
		return nil, errors.New("export: the recipient is not the one genesis pins")
	}
	genesisDigest, err := c.Genesis.Digest()
	if err != nil {
		return nil, err
	}
	genesisBody, err := protocol.Canonical(c.Genesis)
	if err != nil {
		return nil, err
	}
	membershipBody, err := encodeEvents(c.Membership)
	if err != nil {
		return nil, err
	}
	recordsBody, err := encodeEnvelopes(c.Records)
	if err != nil {
		return nil, err
	}
	conflictsBody, err := encodeEnvelopes(c.Conflicts)
	if err != nil {
		return nil, err
	}
	if c.Bundle == nil {
		return nil, errors.New("export: no vault keys; the archive would decrypt to nothing")
	}
	bundleBody, err := protocol.Canonical(c.Bundle)
	if err != nil {
		return nil, err
	}

	bodies := map[string][]byte{
		protocol.MemberGenesis:    genesisBody,
		protocol.MemberMembership: membershipBody,
		protocol.MemberRecords:    recordsBody,
		protocol.MemberConflicts:  conflictsBody,
		protocol.MemberBundle:     bundleBody,
	}
	names := []string{
		protocol.MemberBundle, protocol.MemberConflicts, protocol.MemberGenesis,
		protocol.MemberMembership, protocol.MemberRecords,
	}
	members := make([]protocol.ExportMember, 0, len(names))
	for _, name := range names {
		sum := sha256.Sum256(bodies[name])
		members = append(members, protocol.ExportMember{
			Name:   name,
			Length: protocol.Counter(len(bodies[name])),
			Digest: sum[:],
		})
	}

	manifest := protocol.ExportManifest{
		Domain:        protocol.ExportDomain,
		FormatVersion: protocol.ExportFormatVersion,
		Suite:         crypto.SuiteID,
		VaultID:       c.Genesis.VaultID,
		GenesisDigest: genesisDigest,
		KeyEpoch:      checkpoint.KeyEpoch,
		ExportedBy:    by,
		CreatedAt:     createdAt,
		Checkpoint:    checkpoint,
		Members:       members,
	}
	if err := manifest.Validate(crypto.SuiteID); err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	msg, err := manifest.SigningInput()
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(protocol.ExportSignatureDomain, msg)
	if err != nil {
		return nil, err
	}
	header, err := protocol.Canonical(&protocol.SignedExportManifest{Manifest: manifest, Signature: sig})
	if err != nil {
		return nil, err
	}

	var archive bytes.Buffer
	archive.WriteString(Magic)
	archive.WriteByte('\n')
	archive.Write(header)
	archive.WriteByte('\n')
	for _, member := range members {
		archive.Write(bodies[member.Name])
	}
	return crypto.SealBounded(archive.Bytes(), MaxArchiveBytes, recipient)
}

func Open(sealed []byte, kit *crypto.EncryptionKey, genesisDigest []byte) (*Archive, error) {
	raw, err := crypto.OpenBounded(kit, sealed, MaxArchiveBytes)
	if err != nil {
		return nil, fmt.Errorf("open export: %w", err)
	}
	magic, rest, ok := bytes.Cut(raw, []byte("\n"))
	if !ok || string(magic) != Magic {
		return nil, errors.New("open export: this is not an sshstate export")
	}
	header, body, ok := bytes.Cut(rest, []byte("\n"))
	if !ok {
		return nil, errors.New("open export: the archive has no manifest")
	}
	var signed protocol.SignedExportManifest
	if err := protocol.StrictUnmarshal(header, &signed); err != nil {
		return nil, fmt.Errorf("open export: %w", err)
	}
	if err := signed.Manifest.Validate(crypto.SuiteID); err != nil {
		return nil, fmt.Errorf("open export: %w", err)
	}
	if len(genesisDigest) != 0 && !bytes.Equal(signed.Manifest.GenesisDigest, genesisDigest) {
		return nil, errors.New("open export: this archive is for a different vault")
	}

	bodies := make(map[string][]byte, len(signed.Manifest.Members))
	offset := 0
	for _, member := range signed.Manifest.Members {
		end := offset + int(member.Length)
		if end > len(body) {
			return nil, fmt.Errorf("open export: %q runs past the end of the archive", member.Name)
		}
		chunk := body[offset:end]
		sum := sha256.Sum256(chunk)
		if !bytes.Equal(sum[:], member.Digest) {
			return nil, fmt.Errorf("open export: %q does not match its digest", member.Name)
		}
		bodies[member.Name] = chunk
		offset = end
	}
	if offset != len(body) {
		return nil, errors.New("open export: the archive has trailing data no member accounts for")
	}

	var genesis protocol.Genesis
	if err := protocol.StrictUnmarshal(bodies[protocol.MemberGenesis], &genesis); err != nil {
		return nil, fmt.Errorf("open export genesis: %w", err)
	}
	actual, err := genesis.Digest()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(actual, signed.Manifest.GenesisDigest) {
		return nil, errors.New("open export: the archive's genesis is not the one its manifest names")
	}

	events, err := decodeEvents(bodies[protocol.MemberMembership])
	if err != nil {
		return nil, err
	}
	chain, err := membership.Validate(&genesis, events)
	if err != nil {
		return nil, fmt.Errorf("open export membership: %w", err)
	}
	exporter, ok := chain.Device(signed.Manifest.ExportedBy)
	if !ok {
		return nil, errors.New("open export: the exporting device is not in the membership chain")
	}
	msg, err := signed.Manifest.SigningInput()
	if err != nil {
		return nil, err
	}
	if err := crypto.Verify(exporter.VerifyKey, protocol.ExportSignatureDomain, msg, signed.Signature); err != nil {
		return nil, errors.New("open export: the manifest is not signed by the device it names")
	}

	var bundle protocol.SignedBundle
	if err := protocol.StrictUnmarshal(bodies[protocol.MemberBundle], &bundle); err != nil {
		return nil, fmt.Errorf("open export bundle: %w", err)
	}
	if err := bundle.Bundle.Validate(crypto.SuiteID); err != nil {
		return nil, fmt.Errorf("open export bundle: %w", err)
	}
	if bundle.Bundle.Purpose != protocol.PurposeRecovery {
		return nil, fmt.Errorf("open export: the bundle is for %s, not recovery", bundle.Bundle.Purpose)
	}
	if bundle.Bundle.Recipient != genesis.RecoveryRecipient {
		return nil, errors.New("open export: the bundle is addressed to a recipient genesis does not pin")
	}
	bundleMsg, err := bundle.Bundle.SigningInput()
	if err != nil {
		return nil, err
	}
	if err := crypto.Verify(exporter.VerifyKey, protocol.BundleSignatureDomain, bundleMsg, bundle.Signature); err != nil {
		return nil, errors.New("open export: the vault keys are not signed by the device that exported them")
	}

	records, err := decodeEnvelopes(bodies[protocol.MemberRecords])
	if err != nil {
		return nil, err
	}
	conflicts, err := decodeEnvelopes(bodies[protocol.MemberConflicts])
	if err != nil {
		return nil, err
	}
	for _, env := range append(append([]*protocol.Envelope{}, records...), conflicts...) {
		if err := verifyRecord(chain, &genesis, env); err != nil {
			return nil, fmt.Errorf("open export record %s: %w", env.Context.RecordID, err)
		}
	}
	return &Archive{
		Manifest: signed.Manifest,
		Contents: Contents{
			Genesis:    &genesis,
			Membership: events,
			Records:    records,
			Conflicts:  conflicts,
			Bundle:     &bundle,
		},
	}, nil
}

func verifyRecord(chain *membership.Chain, g *protocol.Genesis, env *protocol.Envelope) error {
	if err := env.Validate(); err != nil {
		return err
	}
	if env.Context.VaultID != g.VaultID {
		return errors.New("the record belongs to another vault")
	}
	d, ok := chain.Device(env.Context.UpdatedBy)
	if !ok {
		return fmt.Errorf("writer %s is not in the membership chain", env.Context.UpdatedBy)
	}
	msg, err := env.SigningInput()
	if err != nil {
		return err
	}
	if err := crypto.Verify(d.VerifyKey, protocol.RecordSignatureDomain, msg, env.Signature); err != nil {
		return errors.New("the signature does not verify")
	}
	return nil
}

func encodeEvents(events []protocol.SignedMembershipEvent) ([]byte, error) {
	var b bytes.Buffer
	for i := range events {
		line, err := protocol.Canonical(&events[i])
		if err != nil {
			return nil, err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func decodeEvents(raw []byte) ([]protocol.SignedMembershipEvent, error) {
	var out []protocol.SignedMembershipEvent
	for i, line := range lines(raw) {
		var ev protocol.SignedMembershipEvent
		if err := protocol.StrictUnmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("membership line %d: %w", i+1, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

func encodeEnvelopes(envs []*protocol.Envelope) ([]byte, error) {
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
	return b.Bytes(), nil
}

func decodeEnvelopes(raw []byte) ([]*protocol.Envelope, error) {
	var out []*protocol.Envelope
	for i, line := range lines(raw) {
		var env protocol.Envelope
		if err := protocol.StrictUnmarshal([]byte(line), &env); err != nil {
			return nil, fmt.Errorf("record line %d: %w", i+1, err)
		}
		out = append(out, &env)
	}
	return out, nil
}

func lines(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
