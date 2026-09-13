// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"testing"
)

func FuzzStrictUnmarshalEnvelope(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"context":{},"nonce":"AAAA","ciphertext":"AAAA","signature":"AAAA"}`))
	f.Add([]byte(`{"context":{"rev":"1"},"nonce":null,"ciphertext":null,"signature":null}`))
	f.Add([]byte(`{"seq":"18446744073709551615"}`))
	f.Add([]byte(`{"a":1}{"a":2}`))
	f.Add([]byte(`{"nonce":"AAAA","nonce":"BBBB"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var env Envelope
		if err := StrictUnmarshal(data, &env); err != nil {
			return
		}
		canon, err := Canonical(&env)
		if err != nil {
			t.Fatalf("accepted input did not canonicalize: %v", err)
		}
		again, err := Canonical(&env)
		if err != nil || !bytes.Equal(canon, again) {
			t.Fatal("canonicalization is not stable for accepted input")
		}
		if len(canon) > MaxObjectBytes {
			t.Fatalf("accepted input canonicalized to %d bytes, above the bound", len(canon))
		}
	})
}

func FuzzStrictUnmarshalMembership(f *testing.F) {
	f.Add([]byte(`{"event":{},"signature":null}`))
	f.Add([]byte(`{"event":{"chain_seq":"1","action":"enroll"},"signature":"AAAA"}`))
	f.Add([]byte(`{"event":{"chain_seq":"-1"},"signature":"AAAA"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ev SignedMembershipEvent
		if err := StrictUnmarshal(data, &ev); err != nil {
			return
		}
		_ = ev.Event.Validate("sshstate.suite.v1")
		if len(ev.Signature) != 0 {
			if _, err := ev.Digest(); err != nil {
				t.Fatalf("a signed event could not be digested: %v", err)
			}
		}
	})
}

func FuzzCounterAndBytes(f *testing.F) {
	f.Add(`"0"`)
	f.Add(`"01"`)
	f.Add(`"18446744073709551616"`)
	f.Add(`"-1"`)
	f.Add(`"AAAA"`)
	f.Add(`"AA=="`)
	f.Add(`"++//"`)

	f.Fuzz(func(t *testing.T, encoded string) {
		var c Counter
		if err := c.UnmarshalJSON([]byte(encoded)); err == nil {
			out, err := c.MarshalJSON()
			if err != nil {
				t.Fatalf("an accepted counter would not re-encode: %v", err)
			}
			var again Counter
			if err := again.UnmarshalJSON(out); err != nil || again != c {
				t.Fatalf("counter %s did not round-trip through %s", encoded, out)
			}
		}
		var b Bytes
		if err := b.UnmarshalJSON([]byte(encoded)); err == nil {
			out, err := b.MarshalJSON()
			if err != nil {
				t.Fatalf("accepted bytes would not re-encode: %v", err)
			}
			var again Bytes
			if err := again.UnmarshalJSON(out); err != nil || !bytes.Equal(again, b) {
				t.Fatalf("bytes %s did not round-trip through %s", encoded, out)
			}
			third, err := again.MarshalJSON()
			if err != nil || !bytes.Equal(third, out) {
				t.Fatalf("re-encoding is not stable: %s then %s", out, third)
			}
		}
	})
}

func TestBytesRejectNonCanonicalBase64(t *testing.T) {
	var canonical Bytes
	if err := canonical.UnmarshalJSON([]byte(`"0w"`)); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{`"01"`, `"02"`, `"0x"`, `"0_"`} {
		var b Bytes
		if err := b.UnmarshalJSON([]byte(spelling)); err == nil {
			t.Errorf("%s was accepted as well as the canonical form", spelling)
		}
	}
	if len(canonical) != 1 {
		t.Fatalf("the canonical form decoded to %d bytes", len(canonical))
	}
}

func FuzzParseFingerprint(f *testing.F) {
	f.Add("")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add(" 1 ABCD   2 EFGH ")
	f.Add("aaaa-bbbb-cccc")

	f.Fuzz(func(t *testing.T, s string) {
		digest, err := ParseFingerprint(s)
		if err != nil {
			return
		}
		if len(digest) != 32 {
			t.Fatalf("accepted a fingerprint that decoded to %d bytes", len(digest))
		}
		rendered, err := Fingerprint(digest)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseFingerprint(rendered)
		if err != nil || !bytes.Equal(back, digest) {
			t.Fatal("an accepted fingerprint did not round-trip")
		}
	})
}
