package httpsig

import "testing"

func FuzzParseSignatureParams(f *testing.F) {
	f.Add(`();created=1`)
	f.Add(`("@method" "@authority");created=1;expires=2;nonce="AAAA";keyid="x";tag="t"`)
	f.Add(`("@method"  "@authority")`)
	f.Add(`("@method" )`)
	f.Add(`(`)
	f.Add(`);created=1`)
	f.Add(`("\"");created=01`)

	f.Fuzz(func(t *testing.T, s string) {
		params, err := ParseSignatureParams(s)
		if err != nil {
			return
		}
		out, err := params.Value()
		if err != nil {
			t.Fatalf("accepted parameters would not re-serialize: %v", err)
		}
		again, err := ParseSignatureParams(out)
		if err != nil {
			t.Fatalf("re-serialized parameters would not re-parse: %v", err)
		}
		second, err := again.Value()
		if err != nil || second != out {
			t.Fatalf("serialization is not stable: %q then %q", out, second)
		}
	})
}

func FuzzParseByteSequence(f *testing.F) {
	f.Add(":AAAA:")
	f.Add("::")
	f.Add(":")
	f.Add(":AA=:")
	f.Add(":not base64:")

	f.Fuzz(func(t *testing.T, s string) {
		raw, err := ParseByteSequence(s)
		if err != nil {
			return
		}
		if out := ByteSequence(raw); out != s {
			t.Fatalf("accepted %q but re-encoded as %q", s, out)
		}
	})
}

func FuzzParseDictionaryMember(f *testing.F) {
	f.Add("sshstate=()")
	f.Add("sshstate=")
	f.Add("other=()")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		value, err := ParseDictionaryMember(s, Label)
		if err != nil {
			return
		}
		if value == "" {
			t.Fatal("accepted a member with no value")
		}
	})
}
