// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package httpsig

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const (
	Label         = "sshstate"
	Tag           = "sshstate.request.v1"
	SigningDomain = "sshstate.request.v1"

	MaxValidity   = 300 * time.Second
	SkewTolerance = 60 * time.Second

	NonceBytes = 16

	DefaultMaxHeaderBytes = 16 << 10

	HeaderSignature      = "Signature"
	HeaderSignatureInput = "Signature-Input"
	HeaderContentDigest  = "Content-Digest"
	HeaderVault          = "SSHState-Vault"
	HeaderDevice         = "SSHState-Device"
	HeaderIdempotency    = "Idempotency-Key"

	contentDigestAlgorithm = "sha-256"
)

var paramOrder = []string{"created", "expires", "nonce", "keyid", "tag"}

func expectedComponents(h http.Header, hasBody bool) []string {
	c := []string{ComponentMethod, ComponentAuthority, ComponentPath, ComponentQuery}
	if hasBody {
		c = append(c, strings.ToLower(HeaderContentDigest))
	}
	c = append(c, strings.ToLower(HeaderVault), strings.ToLower(HeaderDevice))
	if h.Get(HeaderIdempotency) != "" {
		c = append(c, strings.ToLower(HeaderIdempotency))
	}
	return c
}

type Signer struct {
	VaultID        protocol.ID
	DeviceID       protocol.ID
	Key            *crypto.SigningKey
	Now            func() time.Time
	MaxHeaderBytes int
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Signer) maxHeader() int {
	if s.MaxHeaderBytes > 0 {
		return s.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

func (s *Signer) Sign(r *http.Request, body []byte, https bool) error {
	if s.Key == nil {
		return protocol.Errorf(protocol.CodeInternal, "signer has no key")
	}
	if !s.VaultID.Valid() || !s.DeviceID.Valid() {
		return protocol.Errorf(protocol.CodeInternal, "signer has no vault or device identity")
	}
	r.Header.Set(HeaderVault, s.VaultID.String())
	r.Header.Set(HeaderDevice, s.DeviceID.String())
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		r.Header.Set(HeaderContentDigest, DictionaryMember(contentDigestAlgorithm, ByteSequence(sum[:])))
	} else {
		r.Header.Del(HeaderContentDigest)
	}

	nonce := make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return protocol.Errorf(protocol.CodeInternal, "request nonce: %v", err)
	}
	created := s.now().UTC().Truncate(time.Second)
	params := SignatureParams{
		Components: expectedComponents(r.Header, len(body) > 0),
		Params: []Param{
			{Name: "created", Value: created.Unix()},
			{Name: "expires", Value: created.Add(MaxValidity).Unix()},
			{Name: "nonce", Value: base64.RawURLEncoding.EncodeToString(nonce)},
			{Name: "keyid", Value: s.DeviceID.String()},
			{Name: "tag", Value: Tag},
		},
	}

	msg, err := FromRequest(r, https)
	if err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	base, err := Base(msg, params)
	if err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	sig, err := s.Key.Sign(SigningDomain, []byte(base))
	if err != nil {
		return protocol.Errorf(protocol.CodeInternal, "sign request: %v", err)
	}
	value, err := params.Value()
	if err != nil {
		return protocol.Errorf(protocol.CodeInternal, "%v", err)
	}

	input := DictionaryMember(Label, value)
	signature := DictionaryMember(Label, ByteSequence(sig))
	if err := s.checkSize(HeaderSignatureInput, input); err != nil {
		return err
	}
	if err := s.checkSize(HeaderSignature, signature); err != nil {
		return err
	}
	r.Header.Set(HeaderSignatureInput, input)
	r.Header.Set(HeaderSignature, signature)
	return nil
}

func (s *Signer) checkSize(name, value string) error {
	if len(value) > s.maxHeader() {
		return protocol.Errorf(protocol.CodeHeaderTooLarge,
			"%s would be %d bytes, above the %d-byte limit; raise the limit on the reverse proxy and on both ends rather than truncating it",
			name, len(value), s.maxHeader()).WithDetail("header", name).WithDetail("size", len(value))
	}
	return nil
}

type KeyResolver interface {
	ResolveVerifyKey(vaultID, deviceID protocol.ID) (*crypto.VerifyKey, error)
}

type NonceStore interface {
	Use(deviceID protocol.ID, nonce string, until time.Time) (bool, error)
}

type Result struct {
	VaultID        protocol.ID
	DeviceID       protocol.ID
	Created        time.Time
	Expires        time.Time
	Nonce          string
	IdempotencyKey string
}

type Verifier struct {
	Keys           KeyResolver
	Nonces         NonceStore
	Now            func() time.Time
	MaxHeaderBytes int
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) maxHeader() int {
	if v.MaxHeaderBytes > 0 {
		return v.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

func (v *Verifier) Verify(r *http.Request, body []byte, https bool) (*Result, error) {
	rawInput := r.Header.Get(HeaderSignatureInput)
	rawSig := r.Header.Get(HeaderSignature)
	if rawInput == "" || rawSig == "" {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "request is not signed")
	}
	for name, value := range map[string]string{HeaderSignatureInput: rawInput, HeaderSignature: rawSig} {
		if len(value) > v.maxHeader() {
			return nil, protocol.Errorf(protocol.CodeHeaderTooLarge,
				"%s is %d bytes, above the %d-byte limit", name, len(value), v.maxHeader()).
				WithDetail("header", name).WithDetail("size", len(value))
		}
	}
	if len(r.Header.Values(HeaderSignatureInput)) != 1 || len(r.Header.Values(HeaderSignature)) != 1 {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "exactly one signature is required")
	}

	inputValue, err := ParseDictionaryMember(rawInput, Label)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "%s: %v", HeaderSignatureInput, err)
	}
	sigValue, err := ParseDictionaryMember(rawSig, Label)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "%s: %v", HeaderSignature, err)
	}
	sig, err := ParseByteSequence(sigValue)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "%s: %v", HeaderSignature, err)
	}
	params, err := ParseSignatureParams(inputValue)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "%s: %v", HeaderSignatureInput, err)
	}
	if reserialized, err := params.Value(); err != nil || reserialized != inputValue {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "%s is not in this profile's canonical form", HeaderSignatureInput)
	}

	if err := v.checkShape(r, params, len(body) > 0); err != nil {
		return nil, err
	}
	result, err := v.checkParams(r, params)
	if err != nil {
		return nil, err
	}
	if err := checkContentDigest(r, body); err != nil {
		return nil, err
	}

	key, err := v.Keys.ResolveVerifyKey(result.VaultID, result.DeviceID)
	if err != nil {
		return nil, err
	}
	msg, err := FromRequest(r, https)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest, "%v", err)
	}
	base, err := Base(msg, params)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "%v", err)
	}
	if err := crypto.Verify(key, SigningDomain, []byte(base), sig); err != nil {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "signature does not verify")
	}

	if v.Nonces != nil {
		fresh, err := v.Nonces.Use(result.DeviceID, result.Nonce, result.Expires.Add(SkewTolerance))
		if err != nil {
			return nil, protocol.Errorf(protocol.CodeInternal, "record request nonce: %v", err)
		}
		if !fresh {
			return nil, protocol.Errorf(protocol.CodeSignatureReplayed, "this request has already been accepted")
		}
	}
	return result, nil
}

func (v *Verifier) checkShape(r *http.Request, params SignatureParams, hasBody bool) error {
	want := expectedComponents(r.Header, hasBody)
	if !slices.Equal(params.Components, want) {
		return protocol.Errorf(protocol.CodeSignatureInvalid,
			"covered components are %v, this profile requires %v", params.Components, want)
	}
	names := make([]string, 0, len(params.Params))
	for _, p := range params.Params {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, paramOrder) {
		return protocol.Errorf(protocol.CodeSignatureInvalid,
			"signature parameters are %v, this profile requires %v", names, paramOrder)
	}
	if hasBody && r.Header.Get(HeaderContentDigest) == "" {
		return protocol.Errorf(protocol.CodeInvalidRequest, "a request with a body must carry %s", HeaderContentDigest)
	}
	if !hasBody && r.Header.Get(HeaderContentDigest) != "" {
		return protocol.Errorf(protocol.CodeInvalidRequest, "%s is present on a request with no body", HeaderContentDigest)
	}
	return nil
}

func (v *Verifier) checkParams(r *http.Request, params SignatureParams) (*Result, error) {
	created, ok := intParam(params, "created")
	if !ok {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "created is not an integer")
	}
	expires, ok := intParam(params, "expires")
	if !ok {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "expires is not an integer")
	}
	nonce, ok := stringParam(params, "nonce")
	if !ok {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "nonce is not a string")
	}
	keyid, ok := stringParam(params, "keyid")
	if !ok {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "keyid is not a string")
	}
	tag, ok := stringParam(params, "tag")
	if !ok || tag != Tag {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "tag is not %q", Tag)
	}

	createdAt := time.Unix(created, 0).UTC()
	expiresAt := time.Unix(expires, 0).UTC()
	if !expiresAt.After(createdAt) {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "expires is not after created")
	}
	if expiresAt.Sub(createdAt) > MaxValidity {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid,
			"validity window is %s, the limit is %s", expiresAt.Sub(createdAt), MaxValidity)
	}
	now := v.now()
	if createdAt.After(now.Add(SkewTolerance)) {
		return nil, protocol.Errorf(protocol.CodeSignatureExpired, "signature was created in the future")
	}
	if now.After(expiresAt.Add(SkewTolerance)) {
		return nil, protocol.Errorf(protocol.CodeSignatureExpired, "signature expired at %s", expiresAt.Format(time.RFC3339))
	}

	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != NonceBytes {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "nonce must be %d bytes of unpadded base64url", NonceBytes)
	}

	vaultID := protocol.ID(r.Header.Get(HeaderVault))
	deviceID := protocol.ID(r.Header.Get(HeaderDevice))
	if !vaultID.Valid() || !deviceID.Valid() {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest, "%s and %s must be 128-bit lowercase hex ids", HeaderVault, HeaderDevice)
	}
	if subtle.ConstantTimeCompare([]byte(keyid), []byte(deviceID)) != 1 {
		return nil, protocol.Errorf(protocol.CodeSignatureInvalid, "keyid does not match %s", HeaderDevice)
	}
	return &Result{
		VaultID:        vaultID,
		DeviceID:       deviceID,
		Created:        createdAt,
		Expires:        expiresAt,
		Nonce:          nonce,
		IdempotencyKey: r.Header.Get(HeaderIdempotency),
	}, nil
}

func checkContentDigest(r *http.Request, body []byte) error {
	header := r.Header.Get(HeaderContentDigest)
	if header == "" {
		return nil
	}
	value, err := ParseDictionaryMember(header, contentDigestAlgorithm)
	if err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest,
			"%s must be a single %s entry: %v", HeaderContentDigest, contentDigestAlgorithm, err)
	}
	want, err := ParseByteSequence(value)
	if err != nil {
		return protocol.Errorf(protocol.CodeInvalidRequest, "%s: %v", HeaderContentDigest, err)
	}
	got := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return protocol.Errorf(protocol.CodeDigestMismatch, "%s does not match the body", HeaderContentDigest)
	}
	return nil
}

func intParam(p SignatureParams, name string) (int64, bool) {
	v, ok := p.Param(name)
	if !ok {
		return 0, false
	}
	n, ok := v.(int64)
	return n, ok
}

func stringParam(p SignatureParams, name string) (string, bool) {
	v, ok := p.Param(name)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

type MemoryNonceStore struct {
	Now func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{seen: map[string]time.Time{}}
}

func (m *MemoryNonceStore) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *MemoryNonceStore) Use(deviceID protocol.ID, nonce string, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, exp := range m.seen {
		if now.After(exp) {
			delete(m.seen, k)
		}
	}
	key := fmt.Sprintf("%s\x00%s", deviceID, nonce)
	if _, used := m.seen[key]; used {
		return false, nil
	}
	m.seen[key] = until
	return true, nil
}
