// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package httpsig

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	testVault  protocol.ID = "11111111111111111111111111111111"
	testDevice protocol.ID = "22222222222222222222222222222222"
	testOther  protocol.ID = "33333333333333333333333333333333"
)

type fixedKeys struct {
	keys map[protocol.ID]*crypto.VerifyKey
	err  error
}

func (f fixedKeys) ResolveVerifyKey(_ protocol.ID, deviceID protocol.ID) (*crypto.VerifyKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	k, ok := f.keys[deviceID]
	if !ok {
		return nil, protocol.Errorf(protocol.CodeDeviceUnknown, "device %s is not in the membership chain", deviceID)
	}
	return k, nil
}

type harness struct {
	signer   *Signer
	verifier *Verifier
	now      time.Time
	key      *crypto.SigningKey
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{now: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC), key: key}
	h.signer = &Signer{
		VaultID:  testVault,
		DeviceID: testDevice,
		Key:      key,
		Now:      func() time.Time { return h.now },
	}
	nonces := NewMemoryNonceStore()
	nonces.Now = func() time.Time { return h.now }
	h.verifier = &Verifier{
		Keys:   fixedKeys{keys: map[protocol.ID]*crypto.VerifyKey{testDevice: key.Verifier()}},
		Nonces: nonces,
		Now:    func() time.Time { return h.now },
	}
	return h
}

func request(t *testing.T, method, url string, body []byte) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (h *harness) signed(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	body := []byte(`{"context":{"record_id":"22222222222222222222222222222222"}}`)
	r := request(t, http.MethodPut, "https://relay.example.com/v1/records/2222?dryRun=0", body)
	r.Header.Set(HeaderIdempotency, "33333333333333333333333333333333")
	if err := h.signer.Sign(r, body, true); err != nil {
		t.Fatal(err)
	}
	return r, body
}

func mustCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", want)
	}
	if got := protocol.CodeOf(err); got != want {
		t.Fatalf("got %s (%v), want %s", got, err, want)
	}
}

func TestSignedRequestVerifies(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)
	res, err := h.verifier.Verify(r, body, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.VaultID != testVault || res.DeviceID != testDevice {
		t.Fatalf("verified as vault %s device %s", res.VaultID, res.DeviceID)
	}
	if res.IdempotencyKey != "33333333333333333333333333333333" {
		t.Fatalf("idempotency key is %q", res.IdempotencyKey)
	}
	if res.Expires.Sub(res.Created) != MaxValidity {
		t.Fatalf("validity window is %s", res.Expires.Sub(res.Created))
	}
}

func TestSignedReadVerifies(t *testing.T) {
	h := newHarness(t)
	r := request(t, http.MethodGet, "https://relay.example.com/v1/records?since=438&limit=200", nil)
	if err := h.signer.Sign(r, nil, true); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get(HeaderContentDigest) != "" {
		t.Fatal("a bodiless request was given a content digest")
	}
	if _, err := h.verifier.Verify(r, nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestBodyTamperingIsCaught(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)
	tampered := append([]byte{}, body...)
	tampered[len(tampered)-1] = ' '
	mustCode(t, mustErr(h.verifier.Verify(r, tampered, true)), protocol.CodeDigestMismatch)
}

func TestReplayIsRejected(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)
	if _, err := h.verifier.Verify(r, body, true); err != nil {
		t.Fatal(err)
	}
	mustCode(t, mustErr(h.verifier.Verify(r, body, true)), protocol.CodeSignatureReplayed)
}

func TestAFailedRequestDoesNotConsumeItsNonce(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)
	if _, err := h.verifier.Verify(r, append(body, ' '), true); err == nil {
		t.Fatal("a tampered body verified")
	}
	if _, err := h.verifier.Verify(r, body, true); err != nil {
		t.Fatalf("the untampered request was refused after a failed attempt: %v", err)
	}
}

func TestExpiryAndSkew(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)

	h.now = h.now.Add(MaxValidity + SkewTolerance - time.Second)
	if _, err := h.verifier.Verify(r, body, true); err != nil {
		t.Fatalf("a signature inside the tolerance was rejected: %v", err)
	}

	h2 := newHarness(t)
	r2, body2 := h2.signed(t)
	h2.now = h2.now.Add(MaxValidity + SkewTolerance + time.Second)
	mustCode(t, mustErr(h2.verifier.Verify(r2, body2, true)), protocol.CodeSignatureExpired)

	h3 := newHarness(t)
	r3, body3 := h3.signed(t)
	h3.now = h3.now.Add(-2 * SkewTolerance)
	mustCode(t, mustErr(h3.verifier.Verify(r3, body3, true)), protocol.CodeSignatureExpired)
}

func TestAlteringACoveredComponentIsCaught(t *testing.T) {
	cases := map[string]func(*http.Request){
		"method":           func(r *http.Request) { r.Method = http.MethodPost },
		"path":             func(r *http.Request) { r.URL.Path = "/v1/records/9999" },
		"query added":      func(r *http.Request) { r.URL.RawQuery += "&force=1" },
		"query removed":    func(r *http.Request) { r.URL.RawQuery = "" },
		"authority":        func(r *http.Request) { r.Host = "attacker.example.com" },
		"vault header":     func(r *http.Request) { r.Header.Set(HeaderVault, testOther.String()) },
		"idempotency key":  func(r *http.Request) { r.Header.Set(HeaderIdempotency, "44444444444444444444444444444444") },
		"idempotency drop": func(r *http.Request) { r.Header.Del(HeaderIdempotency) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r, body := h.signed(t)
			mutate(r)
			if _, err := h.verifier.Verify(r, body, true); err == nil {
				t.Fatal("the altered request verified")
			}
		})
	}
}

type spyKeys struct {
	inner  KeyResolver
	called *bool
}

func (s spyKeys) ResolveVerifyKey(vaultID, deviceID protocol.ID) (*crypto.VerifyKey, error) {
	*s.called = true
	return s.inner.ResolveVerifyKey(vaultID, deviceID)
}

func TestClosedProfileRejections(t *testing.T) {
	cases := map[string]func(*http.Request){
		"alg parameter": func(r *http.Request) {
			r.Header.Set(HeaderSignatureInput, r.Header.Get(HeaderSignatureInput)+`;alg="ed25519"`)
		},
		"another label": func(r *http.Request) {
			r.Header.Set(HeaderSignatureInput, strings.Replace(r.Header.Get(HeaderSignatureInput), Label+"=", "sig1=", 1))
			r.Header.Set(HeaderSignature, strings.Replace(r.Header.Get(HeaderSignature), Label+"=", "sig1=", 1))
		},
		"a second signature": func(r *http.Request) {
			r.Header.Add(HeaderSignatureInput, `sig1=("@method");created=1;expires=2;nonce="AAAAAAAAAAAAAAAAAAAAAA";keyid="x";tag="`+Tag+`"`)
		},
		"wrong tag": func(r *http.Request) {
			r.Header.Set(HeaderSignatureInput, strings.Replace(r.Header.Get(HeaderSignatureInput), Tag, "other.profile.v1", 1))
		},
		"reordered parameters": func(r *http.Request) {
			in := r.Header.Get(HeaderSignatureInput)
			open := strings.Index(in, ")")
			params := strings.Split(in[open+1:], ";")
			params[1], params[2] = params[2], params[1]
			r.Header.Set(HeaderSignatureInput, in[:open+1]+strings.Join(params, ";"))
		},
		"no signature at all": func(r *http.Request) {
			r.Header.Del(HeaderSignature)
		},
		"non-canonical inner list": func(r *http.Request) {
			r.Header.Set(HeaderSignatureInput, strings.Replace(r.Header.Get(HeaderSignatureInput), `");`, `" );`, 1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r, body := h.signed(t)
			resolved := false
			h.verifier.Keys = spyKeys{inner: h.verifier.Keys, called: &resolved}
			mutate(r)
			mustCode(t, mustErr(h.verifier.Verify(r, body, true)), protocol.CodeSignatureInvalid)
			if resolved {
				t.Fatal("the request reached key resolution instead of being rejected on shape")
			}
		})
	}
}

func TestKeyidMustMatchTheDeviceHeader(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)
	r.Header.Set(HeaderDevice, testOther.String())
	mustCode(t, mustErr(h.verifier.Verify(r, body, true)), protocol.CodeSignatureInvalid)
}

func TestUnknownDeviceIsReportedAsSuch(t *testing.T) {
	h := newHarness(t)
	h.verifier.Keys = fixedKeys{keys: map[protocol.ID]*crypto.VerifyKey{}}
	r, body := h.signed(t)
	mustCode(t, mustErr(h.verifier.Verify(r, body, true)), protocol.CodeDeviceUnknown)
}

func TestAnotherDevicesKeyDoesNotVerify(t *testing.T) {
	h := newHarness(t)
	other, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.Keys = fixedKeys{keys: map[protocol.ID]*crypto.VerifyKey{testDevice: other.Verifier()}}
	r, body := h.signed(t)
	mustCode(t, mustErr(h.verifier.Verify(r, body, true)), protocol.CodeSignatureInvalid)
}

func TestRequestSignaturesAreDomainSeparated(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)
	msg, err := FromRequest(r, true)
	if err != nil {
		t.Fatal(err)
	}
	input, err := ParseDictionaryMember(r.Header.Get(HeaderSignatureInput), Label)
	if err != nil {
		t.Fatal(err)
	}
	params, err := ParseSignatureParams(input)
	if err != nil {
		t.Fatal(err)
	}
	base, err := Base(msg, params)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := h.key.Sign(protocol.RecordSignatureDomain, []byte(base))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HeaderSignature, DictionaryMember(Label, ByteSequence(forged)))
	mustCode(t, mustErr(h.verifier.Verify(r, body, true)), protocol.CodeSignatureInvalid)
	_ = body
}

func TestOversizedSignatureHeaderIsRejectedNotTruncated(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)

	h.verifier.MaxHeaderBytes = 1024
	err := mustErr(h.verifier.Verify(r, body, true))
	mustCode(t, err, protocol.CodeHeaderTooLarge)
	var pe *protocol.Error
	if !errorsAs(err, &pe) {
		t.Fatal("the error is not a protocol error")
	}
	if pe.Status() != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status is %d, want 431", pe.Status())
	}
	if pe.Status() == http.StatusUnauthorized {
		t.Fatal("a size problem was reported as an authentication problem")
	}

	h2 := newHarness(t)
	h2.signer.MaxHeaderBytes = 1024
	r2 := request(t, http.MethodGet, "https://relay.example.com/v1/records", nil)
	mustCode(t, h2.signer.Sign(r2, nil, false), protocol.CodeHeaderTooLarge)
}

func TestMLDSASignatureHeaderSize(t *testing.T) {
	h := newHarness(t)
	r, _ := h.signed(t)
	size := len(r.Header.Get(HeaderSignature))
	t.Logf("Signature header value: %d bytes (label %q + ML-DSA-65 byte sequence)", size, Label)
	if size < 4000 {
		t.Fatalf("the signature header is only %d bytes; ML-DSA-65 should produce roughly 4.4 KB", size)
	}
	const commonProxyLimit = 8190
	if size >= commonProxyLimit {
		t.Fatalf("the signature header is %d bytes, at or above the %d-byte limit commonly deployed", size, commonProxyLimit)
	}
}

func TestContentDigestPresenceMustMatchTheBody(t *testing.T) {
	h := newHarness(t)
	r, body := h.signed(t)
	mustCode(t, mustErr(h.verifier.Verify(r, nil, true)), protocol.CodeSignatureInvalid)

	h2 := newHarness(t)
	r2 := request(t, http.MethodGet, "https://relay.example.com/v1/records", nil)
	if err := h2.signer.Sign(r2, nil, true); err != nil {
		t.Fatal(err)
	}
	mustCode(t, mustErr(h2.verifier.Verify(r2, body, true)), protocol.CodeSignatureInvalid)
}

func TestAuthorityNormalization(t *testing.T) {
	for _, c := range []struct {
		authority string
		https     bool
		want      string
	}{
		{"Relay.Example.COM", true, "relay.example.com"},
		{"relay.example.com:443", true, "relay.example.com"},
		{"relay.example.com:8443", true, "relay.example.com:8443"},
		{"relay.example.com:80", false, "relay.example.com"},
		{"relay.example.com:443", false, "relay.example.com:443"},
		{"[2001:db8::1]:443", true, "[2001:db8::1]"},
		{"[2001:db8::1]", true, "[2001:db8::1]"},
	} {
		if got := normalizeAuthority(c.authority, c.https); got != c.want {
			t.Errorf("%q (https=%v) normalized to %q, want %q", c.authority, c.https, got, c.want)
		}
	}
}

func TestVerifyAServerSideRequest(t *testing.T) {
	h := newHarness(t)
	body := []byte(`{"hello":"world"}`)
	signed := request(t, http.MethodPut, "https://relay.example.com/v1/records/2222?a=b", body)
	signed.Header.Set(HeaderIdempotency, testOther.String())
	if err := h.signer.Sign(signed, body, true); err != nil {
		t.Fatal(err)
	}

	received := httptest.NewRequest(http.MethodPut, "/v1/records/2222?a=b", bytes.NewReader(body))
	received.Host = "relay.example.com"
	for k, vs := range signed.Header {
		for _, v := range vs {
			received.Header.Add(k, v)
		}
	}
	if _, err := h.verifier.Verify(received, body, true); err != nil {
		t.Fatalf("a request that crossed the wire did not verify: %v", err)
	}
}

func mustErr(_ *Result, err error) error { return err }

func errorsAs(err error, target **protocol.Error) bool {
	for err != nil {
		if pe, ok := err.(*protocol.Error); ok {
			*target = pe
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
