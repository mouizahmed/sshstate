// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

const testSuite = "sshstate.suite.v1"

func challenge(seed byte) Bytes {
	b := make(Bytes, ChallengeBytes)
	for i := range b {
		b[i] = seed ^ byte(i)
	}
	return b
}

func sampleOffer() PairingOffer {
	return PairingOffer{
		Domain:          PairingOfferDomain,
		FormatVersion:   PairingFormatVersion,
		Suite:           testSuite,
		VaultID:         "11111111111111111111111111111111",
		JoinerDeviceID:  "22222222222222222222222222222222",
		JoinerVerifyKey: Bytes("joiner-verify-key"),
		JoinerRecipient: "age1pq1joiner",
		JoinerChallenge: challenge(0x11),
		CreatedAt:       "2026-09-12T00:00:00Z",
	}
}

func sampleApproval() PairingApproval {
	return PairingApproval{
		ApproverDeviceID:  "33333333333333333333333333333333",
		ApproverVerifyKey: Bytes("approver-verify-key"),
		ApproverRecipient: "age1pq1approver",
		ApproverChallenge: challenge(0x33),
		CreatedAt:         "2026-09-12T00:01:00Z",
		ExpiresAt:         "2026-09-12T00:11:00Z",
	}
}

const sampleSession ID = "44444444444444444444444444444444"

func mustTranscript(t *testing.T) *PairingTranscript {
	t.Helper()
	tr, err := BuildTranscript(sampleSession, sampleOffer(), sampleApproval(), testSuite)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestEveryTranscriptInputChangesTheDigest(t *testing.T) {
	base, err := mustTranscript(t).Digest()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*PairingOffer, *PairingApproval, *ID){
		"session id": func(o *PairingOffer, a *PairingApproval, s *ID) { *s = "55555555555555555555555555555555" },
		"vault id":   func(o *PairingOffer, a *PairingApproval, s *ID) { o.VaultID = "66666666666666666666666666666666" },
		"joiner device id": func(o *PairingOffer, a *PairingApproval, s *ID) {
			o.JoinerDeviceID = "77777777777777777777777777777777"
		},
		"joiner verify key": func(o *PairingOffer, a *PairingApproval, s *ID) { o.JoinerVerifyKey = Bytes("substituted") },
		"joiner recipient":  func(o *PairingOffer, a *PairingApproval, s *ID) { o.JoinerRecipient = "age1pq1elsewhere" },
		"joiner challenge":  func(o *PairingOffer, a *PairingApproval, s *ID) { o.JoinerChallenge = challenge(0x99) },
		"approver device id": func(o *PairingOffer, a *PairingApproval, s *ID) {
			a.ApproverDeviceID = "88888888888888888888888888888888"
		},
		"approver verify key": func(o *PairingOffer, a *PairingApproval, s *ID) {
			a.ApproverVerifyKey = Bytes("substituted")
		},
		"approver recipient": func(o *PairingOffer, a *PairingApproval, s *ID) { a.ApproverRecipient = "age1pq1elsewhere" },
		"approver challenge": func(o *PairingOffer, a *PairingApproval, s *ID) { a.ApproverChallenge = challenge(0xaa) },
		"session window": func(o *PairingOffer, a *PairingApproval, s *ID) {
			a.CreatedAt = "2026-09-12T00:02:00Z"
			a.ExpiresAt = "2026-09-12T00:12:00Z"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			offer, approval, session := sampleOffer(), sampleApproval(), sampleSession
			mutate(&offer, &approval, &session)
			tr, err := BuildTranscript(session, offer, approval, testSuite)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tr.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("substituting this field left the fingerprint unchanged")
			}
		})
	}
}

func TestTranscriptDigestIsCanonical(t *testing.T) {
	a, err := mustTranscript(t).Digest()
	if err != nil {
		t.Fatal(err)
	}
	b, err := mustTranscript(t).Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the same transcript produced two digests")
	}
	canon, err := Canonical(mustTranscript(t))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon)
	if !bytes.Equal(a, sum[:]) {
		t.Fatal("Digest is not SHA-256 over the canonical transcript")
	}
}

func TestSuiteAndSelfPairingAreRejected(t *testing.T) {
	offer := sampleOffer()
	offer.Suite = "sshstate.suite.v2"
	if _, err := BuildTranscript(sampleSession, offer, sampleApproval(), testSuite); err == nil {
		t.Fatal("an unknown suite was accepted")
	}
	offer = sampleOffer()
	approval := sampleApproval()
	approval.ApproverDeviceID = offer.JoinerDeviceID
	if _, err := BuildTranscript(sampleSession, offer, approval, testSuite); err == nil {
		t.Fatal("a device paired with itself")
	}
}

func TestSessionLifetimeIsFixed(t *testing.T) {
	approval := sampleApproval()
	approval.ExpiresAt = "2026-09-12T01:01:00Z"
	if err := approval.Validate(); err == nil {
		t.Fatal("a stretched session window was accepted")
	}
}

func TestExpiryUsesTheCallersClock(t *testing.T) {
	tr := mustTranscript(t)
	before := time.Date(2026, 9, 12, 0, 10, 59, 0, time.UTC)
	after := time.Date(2026, 9, 12, 0, 11, 0, 0, time.UTC)
	if tr.Expired(before) {
		t.Fatal("the session expired a second early")
	}
	if !tr.Expired(after) {
		t.Fatal("the session did not expire at expires_at")
	}
	tr.ExpiresAt = "not a timestamp"
	if !tr.Expired(before) {
		t.Fatal("an unparseable expiry was treated as live")
	}
}

func TestChallengeSizeIsEnforced(t *testing.T) {
	offer := sampleOffer()
	offer.JoinerChallenge = Bytes("short")
	if err := offer.Validate(testSuite); err == nil {
		t.Fatal("a short joiner challenge was accepted")
	}
	approval := sampleApproval()
	approval.ApproverChallenge = Bytes("short")
	if err := approval.Validate(); err == nil {
		t.Fatal("a short approver challenge was accepted")
	}
}

func TestFingerprintShapeAndRoundTrip(t *testing.T) {
	digest := sha256.Sum256([]byte("sshstate fingerprint vector"))
	s, err := Fingerprint(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != FingerprintChars {
		t.Fatalf("fingerprint is %d characters, want %d", len(s), FingerprintChars)
	}
	groups, err := FingerprintGroups(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != FingerprintGroupCount {
		t.Fatalf("got %d groups, want %d", len(groups), FingerprintGroupCount)
	}
	for i, g := range groups {
		if len(g) != FingerprintGroupSize {
			t.Fatalf("group %d has %d characters", i+1, len(g))
		}
	}
	back, err := ParseFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, digest[:]) {
		t.Fatal("the fingerprint did not round-trip to the same digest")
	}
}

func TestEveryGroupCarriesDigestBits(t *testing.T) {
	base := sha256.Sum256([]byte("base"))
	baseGroups, err := FingerprintGroups(base[:])
	if err != nil {
		t.Fatal(err)
	}
	flipped := base
	flipped[len(flipped)-1] ^= 0x01
	flippedGroups, err := FingerprintGroups(flipped[:])
	if err != nil {
		t.Fatal(err)
	}
	differing := 0
	for i := range baseGroups {
		if baseGroups[i] != flippedGroups[i] {
			differing++
			if i != FingerprintGroupCount-1 {
				t.Fatalf("group %d changed, but only the last byte differs", i+1)
			}
		}
	}
	if differing != 1 {
		t.Fatalf("%d groups differ, want exactly the final one", differing)
	}
}

func TestNonZeroTrailingBitsAreRejected(t *testing.T) {
	digest := sha256.Sum256([]byte("trailing bits"))
	s, err := Fingerprint(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	last := strings.IndexByte(alphabet, s[len(s)-1])
	if last < 0 {
		t.Fatalf("final character %q is not in the alphabet", s[len(s)-1])
	}
	rejected := 0
	for i := range alphabet {
		if i == last {
			continue
		}
		candidate := s[:len(s)-1] + string(alphabet[i])
		got, err := ParseFingerprint(candidate)
		if err != nil {
			rejected++
			continue
		}
		if bytes.Equal(got, digest[:]) {
			t.Fatalf("%q decoded to the same digest as %q", candidate, s)
		}
	}
	if rejected != 30 {
		t.Fatalf("%d of 31 alternative final characters were rejected, want 30", rejected)
	}
}

func TestFingerprintLayoutShowsEveryGroup(t *testing.T) {
	digest := sha256.Sum256([]byte("layout"))
	out, err := FormatFingerprint(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	groups, err := FingerprintGroups(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	for i, g := range groups {
		if !strings.Contains(out, g) {
			t.Fatalf("group %d (%s) is missing from the display:\n%s", i+1, g, out)
		}
	}
	if strings.Contains(out, "...") || strings.Contains(out, "…") {
		t.Fatalf("the display elides part of the fingerprint:\n%s", out)
	}
	if lines := strings.Count(strings.TrimRight(out, "\n"), "\n") + 1; lines != 4 {
		t.Fatalf("the display uses %d lines, want 4:\n%s", lines, out)
	}
}

func TestFingerprintRejectsWrongSizedDigests(t *testing.T) {
	if _, err := Fingerprint([]byte("too short")); err == nil {
		t.Fatal("a short digest produced a fingerprint")
	}
	if _, err := ParseFingerprint("ABCD"); err == nil {
		t.Fatal("a short fingerprint parsed")
	}
	if _, err := ParseFingerprint(strings.Repeat("!", FingerprintChars)); err == nil {
		t.Fatal("characters outside the alphabet parsed")
	}
}
