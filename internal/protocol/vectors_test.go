package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorPath = "testdata/vectors.json"

type vectorFile struct {
	Note       string             `json:"note"`
	Canonical  []canonicalVector  `json:"canonical"`
	Encodings  []encodingVector   `json:"encodings"`
	Record     recordVector       `json:"record"`
	Membership membershipVector   `json:"membership"`
	Pairing    pairingVector      `json:"pairing"`
	Conflicts  []conflictIDVector `json:"conflict_ids"`
}

type canonicalVector struct {
	Name      string          `json:"name"`
	Value     json.RawMessage `json:"value"`
	Canonical string          `json:"canonical"`
	SHA256    string          `json:"sha256"`
}

type encodingVector struct {
	Name    string          `json:"name"`
	Encoded json.RawMessage `json:"encoded"`
	HexBody string          `json:"hex,omitempty"`
	Counter string          `json:"counter,omitempty"`
}

type recordVector struct {
	Envelope     Envelope `json:"envelope"`
	AAD          string   `json:"aad"`
	SigningInput string   `json:"signing_input"`
	Digest       string   `json:"digest_sha256"`
}

type membershipVector struct {
	Event        SignedMembershipEvent `json:"event"`
	SigningInput string                `json:"signing_input"`
	Digest       string                `json:"digest_sha256"`
}

type pairingVector struct {
	Transcript  PairingTranscript `json:"transcript"`
	Canonical   string            `json:"canonical"`
	Digest      string            `json:"digest_sha256"`
	Fingerprint string            `json:"fingerprint"`
	Groups      []string          `json:"groups"`
}

type conflictIDVector struct {
	VaultID          ID `json:"vault_id"`
	SourceRecordID   ID `json:"source_record_id"`
	SourceMutationID ID `json:"source_mutation_id"`
	ConflictID       ID `json:"conflict_id"`
}

const (
	vecVault    ID = "11111111111111111111111111111111"
	vecRecord   ID = "22222222222222222222222222222222"
	vecMutation ID = "33333333333333333333333333333333"
	vecDevice   ID = "44444444444444444444444444444444"
	vecSecond   ID = "55555555555555555555555555555555"
	vecEvent    ID = "66666666666666666666666666666666"
	vecSession  ID = "77777777777777777777777777777777"
)

func fixedBytes(n int, seed byte) Bytes {
	b := make(Bytes, n)
	for i := range b {
		b[i] = seed ^ byte(i)
	}
	return b
}

const frenchSorting = `{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}`

func canonicalInputs() []canonicalVector {
	raw := []struct {
		name  string
		value string
	}{
		{"rfc8785 french sorting", frenchSorting},
		{"key ordering", `{"b":1,"a":2,"C":3,"c":4,"A":5}`},
		{"nested objects and arrays", `{"z":[{"b":1,"a":2},[3,2,1]],"a":{"y":null,"x":true}}`},
		{"escapes and non-ascii keys", "{\"\\u20ac\":\"Euro\",\"\\t\":\"Tab\",\"\\\"\":\"Quote\",\"1\":\"One\",\"\":\"Empty\",\"\\ud83d\\ude02\":\"Emoji\"}"},
		{"literals", `{"t":true,"f":false,"n":null,"s":"","e":{},"a":[]}`},
		{"protocol scalars are strings", `{"rev":"8","seq":"441","key_epoch":"1"}`},
	}
	out := make([]canonicalVector, 0, len(raw))
	for _, r := range raw {
		canon, err := Canonical(json.RawMessage(r.value))
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(canon)
		out = append(out, canonicalVector{
			Name:      r.name,
			Value:     json.RawMessage(r.value),
			Canonical: string(canon),
			SHA256:    hex.EncodeToString(sum[:]),
		})
	}
	return out
}

func encodingInputs() []encodingVector {
	out := []encodingVector{}
	for _, c := range []struct {
		name string
		b    Bytes
	}{
		{"empty bytes", Bytes{}},
		{"null bytes", nil},
		{"one byte", Bytes{0xff}},
		{"needs url alphabet", Bytes{0xfb, 0xff, 0xbf}},
		{"24-byte nonce", fixedBytes(24, 0x10)},
	} {
		enc, err := json.Marshal(c.b)
		if err != nil {
			panic(err)
		}
		out = append(out, encodingVector{Name: c.name, Encoded: enc, HexBody: hex.EncodeToString(c.b)})
	}
	for _, c := range []struct {
		name string
		v    Counter
	}{
		{"zero", 0},
		{"one", 1},
		{"above 2^53", 9007199254740993},
		{"max uint64", 18446744073709551615},
	} {
		enc, err := json.Marshal(c.v)
		if err != nil {
			panic(err)
		}
		out = append(out, encodingVector{Name: "counter " + c.name, Encoded: enc, Counter: c.v.String()})
	}
	return out
}

func recordInput() recordVector {
	parent := sha256.Sum256([]byte("parent envelope"))
	env := Envelope{
		Context: Context{
			Domain:        RecordDomain,
			FormatVersion: RecordFormatVersion,
			VaultID:       vecVault,
			RecordID:      vecRecord,
			RecordType:    RecordHost,
			KeyEpoch:      1,
			Rev:           8,
			ParentDigest:  parent[:],
			MutationID:    vecMutation,
			UpdatedBy:     vecDevice,
			Deleted:       false,
		},
		Nonce:      fixedBytes(24, 0x20),
		Ciphertext: fixedBytes(64, 0x30),
		Signature:  fixedBytes(3309, 0x40),
		Seq:        441,
	}
	aad, err := env.Context.AAD()
	if err != nil {
		panic(err)
	}
	signing, err := env.SigningInput()
	if err != nil {
		panic(err)
	}
	digest, err := env.Digest()
	if err != nil {
		panic(err)
	}
	return recordVector{
		Envelope:     env,
		AAD:          string(aad),
		SigningInput: string(signing),
		Digest:       hex.EncodeToString(digest),
	}
}

func membershipInput() membershipVector {
	parent := sha256.Sum256([]byte("previous membership event"))
	transcript := sha256.Sum256([]byte("confirmed pairing transcript"))
	recipient := "age1pq1joiner"
	ev := SignedMembershipEvent{
		Event: MembershipEvent{
			Domain:           MembershipDomain,
			FormatVersion:    MembershipFormatVersion,
			Suite:            testSuite,
			VaultID:          vecVault,
			EventID:          vecEvent,
			ChainSeq:         2,
			ParentDigest:     parent[:],
			Action:           ActionEnroll,
			DeviceID:         vecSecond,
			DeviceVerifyKey:  fixedBytes(1952, 0x50),
			DeviceRecipient:  &recipient,
			TranscriptDigest: transcript[:],
			Authority:        AuthorityDevice,
			AuthorizedBy:     vecDevice,
			CreatedAt:        "2026-09-12T00:05:00Z",
		},
		Signature: fixedBytes(3309, 0x60),
	}
	signing, err := ev.Event.SigningInput()
	if err != nil {
		panic(err)
	}
	digest, err := ev.Digest()
	if err != nil {
		panic(err)
	}
	return membershipVector{
		Event:        ev,
		SigningInput: string(signing),
		Digest:       hex.EncodeToString(digest),
	}
}

func pairingInput() pairingVector {
	tr := PairingTranscript{
		Domain:            PairingDomain,
		FormatVersion:     PairingFormatVersion,
		Suite:             testSuite,
		VaultID:           vecVault,
		SessionID:         vecSession,
		ApproverDeviceID:  vecDevice,
		ApproverVerifyKey: fixedBytes(1952, 0x70),
		ApproverRecipient: "age1pq1approver",
		JoinerDeviceID:    vecSecond,
		JoinerVerifyKey:   fixedBytes(1952, 0x80),
		JoinerRecipient:   "age1pq1joiner",
		ApproverChallenge: fixedBytes(ChallengeBytes, 0x90),
		JoinerChallenge:   fixedBytes(ChallengeBytes, 0xa0),
		CreatedAt:         "2026-09-12T00:00:00Z",
		ExpiresAt:         "2026-09-12T00:10:00Z",
	}
	canon, err := Canonical(&tr)
	if err != nil {
		panic(err)
	}
	digest, err := tr.Digest()
	if err != nil {
		panic(err)
	}
	fp, err := Fingerprint(digest)
	if err != nil {
		panic(err)
	}
	groups, err := FingerprintGroups(digest)
	if err != nil {
		panic(err)
	}
	return pairingVector{
		Transcript:  tr,
		Canonical:   string(canon),
		Digest:      hex.EncodeToString(digest),
		Fingerprint: fp,
		Groups:      groups,
	}
}

func conflictInputs() []conflictIDVector {
	inputs := []conflictIDVector{
		{VaultID: vecVault, SourceRecordID: vecRecord, SourceMutationID: vecMutation},
		{VaultID: vecVault, SourceRecordID: vecRecord, SourceMutationID: vecDevice},
		{VaultID: vecSecond, SourceRecordID: vecRecord, SourceMutationID: vecMutation},
	}
	for i := range inputs {
		id, err := ConflictID(inputs[i].VaultID, inputs[i].SourceRecordID, inputs[i].SourceMutationID)
		if err != nil {
			panic(err)
		}
		inputs[i].ConflictID = id
	}
	return inputs
}

func generate() vectorFile {
	return vectorFile{
		Note: "Frozen wire-format vectors for sshstate.suite.v1. See docs/protocol.md. " +
			"Signatures and public keys here are fixed placeholder bytes: these vectors pin " +
			"canonicalization and digests, not signature generation.",
		Canonical:  canonicalInputs(),
		Encodings:  encodingInputs(),
		Record:     recordInput(),
		Membership: membershipInput(),
		Pairing:    pairingInput(),
		Conflicts:  conflictInputs(),
	}
}

func TestGoldenVectors(t *testing.T) {
	got := generate()
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	if *update {
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s (%d bytes)", vectorPath, len(encoded))
		return
	}

	want, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("%v\n\nrun: go test ./internal/protocol -run TestGoldenVectors -update", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("the wire format no longer matches %s.\n\n"+
			"This is a format change, not a test failure to paper over: it needs a\n"+
			"format-version bump or an epoch transition. If the change is intended,\n"+
			"run: go test ./internal/protocol -run TestGoldenVectors -update", vectorPath)
	}
}

func TestCanonicalOrdersByUTF16CodeUnit(t *testing.T) {
	canon, err := Canonical(json.RawMessage(frenchSorting))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"peach\":\"This sorting order\"," +
		"\"péché\":\"is wrong according to French\"," +
		"\"pêche\":\"but canonicalization MUST\"," +
		"\"sin\":\"ignore locale\"}"
	if string(canon) != want {
		t.Fatalf("canonical form is\n  %s\nwant\n  %s", canon, want)
	}
}

func TestCanonicalIsIdempotent(t *testing.T) {
	for _, v := range canonicalInputs() {
		again, err := Canonical(json.RawMessage(v.Canonical))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(again) != v.Canonical {
			t.Fatalf("%s: canonicalizing twice changed the bytes:\n  %s\n  %s", v.Name, v.Canonical, again)
		}
	}
}
