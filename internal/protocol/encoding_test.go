package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBytesRoundTripUnpaddedBase64URL(t *testing.T) {
	in := Bytes{0xfb, 0xff, 0xbf}
	out, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(out), "+/=") {
		t.Fatalf("encoding %s used padding or the standard alphabet", out)
	}
	var back Bytes
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if string(back) != string(in) {
		t.Fatalf("round trip changed bytes: %x -> %x", in, back)
	}
}

func TestBytesRejectsPaddedAndStandardAlphabet(t *testing.T) {
	for _, s := range []string{`"+w=="`, `"//8"`, `"YQ=="`, `"not base64!"`} {
		var b Bytes
		if err := json.Unmarshal([]byte(s), &b); err == nil {
			t.Errorf("accepted non-canonical binary encoding %s", s)
		}
	}
}

func TestCounterRejectsLeadingZeroAndNonDecimal(t *testing.T) {
	for _, s := range []string{`"01"`, `"00"`, `"1 "`, `"0x1"`, `""`, `"-1"`, `1`} {
		var c Counter
		if err := json.Unmarshal([]byte(s), &c); err == nil {
			t.Errorf("accepted invalid counter %s", s)
		}
	}
	var c Counter
	if err := json.Unmarshal([]byte(`"0"`), &c); err != nil || c != 0 {
		t.Fatalf("zero must encode as \"0\": %v %v", c, err)
	}
}

func TestCounterSurvivesAbove2Pow53(t *testing.T) {
	const big Counter = 1<<53 + 1
	out, err := json.Marshal(big)
	if err != nil {
		t.Fatal(err)
	}
	var back Counter
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back != big {
		t.Fatalf("lost precision: %d -> %d", big, back)
	}
}

func TestCanonicalSortsKeysAndIsStable(t *testing.T) {
	a, err := Canonical(map[string]any{"b": 1, "a": 2, "c": map[string]any{"z": 1, "y": 2}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1,"c":{"y":2,"z":1}}`
	if string(a) != want {
		t.Fatalf("canonical form is %s, want %s", a, want)
	}
}

func TestCanonicalIgnoresStructFieldOrder(t *testing.T) {
	type forward struct {
		A int `json:"a"`
		B int `json:"b"`
	}
	type reversed struct {
		B int `json:"b"`
		A int `json:"a"`
	}
	x, err := Canonical(forward{A: 1, B: 2})
	if err != nil {
		t.Fatal(err)
	}
	y, err := Canonical(reversed{B: 2, A: 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(y) {
		t.Fatalf("field order changed the canonical form: %s vs %s", x, y)
	}
}

func TestStrictUnmarshalRejectsDuplicateKeys(t *testing.T) {
	type doc struct {
		A int            `json:"a"`
		N map[string]int `json:"n"`
	}
	cases := map[string]string{
		"top level": `{"a":1,"a":2}`,
		"nested":    `{"a":1,"n":{"x":1,"x":2}}`,
	}
	for name, body := range cases {
		var d doc
		err := StrictUnmarshal([]byte(body), &d)
		if err == nil {
			t.Errorf("%s: accepted duplicate key; encoding/json would keep the last value", name)
			continue
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("%s: wrong error: %v", name, err)
		}
	}
}

func TestStrictUnmarshalRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	type doc struct {
		A int `json:"a"`
	}
	var d doc
	if err := StrictUnmarshal([]byte(`{"a":1,"b":2}`), &d); err == nil {
		t.Error("accepted unknown field")
	}
	if err := StrictUnmarshal([]byte(`{"a":1}{"a":2}`), &d); err == nil {
		t.Error("accepted a second document after the first")
	}
}

func TestStrictUnmarshalBoundsSize(t *testing.T) {
	var d map[string]any
	body := append([]byte(`{"a":"`), make([]byte, MaxObjectBytes)...)
	if err := StrictUnmarshal(body, &d); err == nil {
		t.Fatal("accepted an object over the size bound")
	}
}

func TestIDValidity(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if !id.Valid() {
		t.Fatalf("generated id %q is invalid", id)
	}
	for _, bad := range []ID{"", "abc", ID(strings.ToUpper(string(id))), id + "0"} {
		if bad.Valid() {
			t.Errorf("accepted invalid id %q", bad)
		}
	}
}

func TestIDsAreDistinct(t *testing.T) {
	seen := make(map[ID]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := MustNewID()
		if seen[id] {
			t.Fatalf("repeated id %q", id)
		}
		seen[id] = true
	}
}
