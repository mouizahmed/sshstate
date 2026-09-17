package httpsig

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"testing"
)

func testRequest() *Message {
	h := http.Header{}
	h.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	h.Set("Content-Type", "application/json")
	h.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	h.Set("Content-Length", "18")
	return &Message{
		Method:    "POST",
		Authority: "example.com",
		Path:      "/foo",
		Query:     "param=Value&Pet=dog",
		HasQuery:  true,
		Fields:    h,
	}
}

const baseB21 = `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`

const baseB23 = `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`

const baseB26 = `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`

const testKeyEd25519PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
`

const signatureB26 = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="

func paramsB21() SignatureParams {
	return SignatureParams{
		Components: nil,
		Params: []Param{
			{Name: "created", Value: int64(1618884473)},
			{Name: "keyid", Value: "test-key-rsa-pss"},
			{Name: "nonce", Value: "b3k2pp5k7z-50gnwp.yemd"},
		},
	}
}

func paramsB23() SignatureParams {
	return SignatureParams{
		Components: []string{"date", "@method", "@path", "@query", "@authority", "content-type", "content-digest", "content-length"},
		Params: []Param{
			{Name: "created", Value: int64(1618884473)},
			{Name: "keyid", Value: "test-key-rsa-pss"},
		},
	}
}

func paramsB26() SignatureParams {
	return SignatureParams{
		Components: []string{"date", "@method", "@path", "@authority", "content-type", "content-length"},
		Params: []Param{
			{Name: "created", Value: int64(1618884473)},
			{Name: "keyid", Value: "test-key-ed25519"},
		},
	}
}

func TestRFC9421PublishedSignatureBases(t *testing.T) {
	cases := map[string]struct {
		params SignatureParams
		want   string
	}{
		"B.2.1 minimal":       {paramsB21(), baseB21},
		"B.2.3 full coverage": {paramsB23(), baseB23},
		"B.2.6 ed25519":       {paramsB26(), baseB26},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Base(testRequest(), c.params)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("signature base does not match the RFC.\n got:\n%s\n\nwant:\n%s", got, c.want)
			}
		})
	}
}

func TestRFC9421Ed25519SignatureVerifiesAgainstOurBase(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyEd25519PEM))
	if block == nil {
		t.Fatal("could not decode the RFC's test key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("the RFC's test key parsed as %T", parsed)
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB26)
	if err != nil {
		t.Fatal(err)
	}

	base, err := Base(testRequest(), paramsB26())
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(base), sig) {
		t.Fatal("the RFC's published signature does not verify over the base we built")
	}

	for name, broken := range map[string]string{
		"trailing newline":   base + "\n",
		"missing final line": base[:len(base)-1],
		"altered method":     replaceOnce(t, base, `"@method": POST`, `"@method": GET`),
		"altered path":       replaceOnce(t, base, `"@path": /foo`, `"@path": /bar`),
		"altered authority":  replaceOnce(t, base, `"@authority": example.com`, `"@authority": example.org`),
		"altered created":    replaceOnce(t, base, "created=1618884473", "created=1618884474"),
	} {
		if ed25519.Verify(pub, []byte(broken), sig) {
			t.Fatalf("%s: an altered base verified anyway", name)
		}
	}
}

func TestSignatureParamsRoundTripThroughTheHeader(t *testing.T) {
	for name, p := range map[string]SignatureParams{
		"B.2.1": paramsB21(),
		"B.2.3": paramsB23(),
		"B.2.6": paramsB26(),
	} {
		t.Run(name, func(t *testing.T) {
			want, err := p.Value()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseSignatureParams(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parsed.Value()
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("round trip changed the value:\n got: %s\nwant: %s", got, want)
			}
			if len(parsed.Components) != len(p.Components) {
				t.Fatalf("got %d components, want %d", len(parsed.Components), len(p.Components))
			}
		})
	}
}

func TestSignatureInputHeaderMatchesTheRFC(t *testing.T) {
	value, err := paramsB23().Value()
	if err != nil {
		t.Fatal(err)
	}
	const want = `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`
	if got := DictionaryMember("sig-b23", value); got != want {
		t.Fatalf("Signature-Input is\n  %s\nwant\n  %s", got, want)
	}
}

func TestSignatureHeaderMatchesTheRFC(t *testing.T) {
	sig, err := base64.StdEncoding.DecodeString(signatureB26)
	if err != nil {
		t.Fatal(err)
	}
	want := "sig-b26=:" + signatureB26 + ":"
	if got := DictionaryMember("sig-b26", ByteSequence(sig)); got != want {
		t.Fatalf("Signature is\n  %s\nwant\n  %s", got, want)
	}
	back, err := ParseByteSequence(ByteSequence(sig))
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(sig) {
		t.Fatal("the byte sequence did not round-trip")
	}
}

func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	idx := indexOf(s, old)
	if idx < 0 {
		t.Fatalf("%q is not in the base", old)
	}
	return s[:idx] + new + s[idx+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
