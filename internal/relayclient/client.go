// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relayclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/mouizahmed/sshstate/internal/httpsig"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const MaxResponseBytes = 8 << 20

const DefaultTimeout = 30 * time.Second

type Client struct {
	base   *url.URL
	http   *http.Client
	signer *httpsig.Signer
	https  bool
}

type Options struct {
	BaseURL string
	Signer  *httpsig.Signer
	HTTP    *http.Client
}

func New(opts Options) (*Client, error) {
	base, err := url.Parse(strings.TrimSuffix(opts.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("relay url: %w", err)
	}
	switch base.Scheme {
	case "https":
	case "http":
		if !isLoopback(base.Hostname()) {
			return nil, fmt.Errorf("relay url %q uses plain HTTP; that is loopback-only", opts.BaseURL)
		}
	default:
		return nil, fmt.Errorf("relay url %q must be https", opts.BaseURL)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("relay url %q has no host", opts.BaseURL)
	}
	client := opts.HTTP
	if client == nil {
		client = &http.Client{
			Timeout: DefaultTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{base: base, http: client, signer: opts.Signer, https: base.Scheme == "https"}, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

func (c *Client) send(ctx context.Context, method, path string, in any, headers map[string]string) (int, []byte, *http.Request, error) {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("encode request: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.signer != nil {
		if err := c.signer.Sign(req, body, c.https); err != nil {
			return 0, nil, nil, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, &UnreachableError{URL: c.base.String(), Err: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read the relay's response: %w", err)
	}
	if len(raw) > MaxResponseBytes {
		return 0, nil, nil, protocol.Errorf(protocol.CodeBodyTooLarge,
			"the relay returned more than %d bytes", MaxResponseBytes)
	}
	return resp.StatusCode, raw, req, nil
}

func (c *Client) call(ctx context.Context, method, path string, in, out any, headers map[string]string) error {
	status, raw, req, err := c.send(ctx, method, path, in, headers)
	if err != nil {
		return err
	}
	if status >= 300 {
		return decodeError(status, raw, signatureBytes(req))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode the relay's response: %w", err)
	}
	return nil
}

func (c *Client) asMember(err error) error {
	switch protocol.CodeOf(err) {
	case protocol.CodeNotFound:
		return fmt.Errorf("the relay at %s does not hold this vault; if the relay was reset or started on a new database, "+
			"this machine still has the vault, and the relay's data has to be restored from a backup of its volume: %w", c.base.String(), err)
	case protocol.CodeDeviceRevoked:
		return fmt.Errorf("the relay refuses this device because another device revoked it, so nothing changed here will sync\n"+
			"to use this machine with the vault again: sshstate uninstall --purge, then sshstate pair: %w", err)
	}
	return err
}

func (c *Client) asPairing(sessionID protocol.ID, err error) error {
	if protocol.CodeOf(err) == protocol.CodeNotFound {
		return fmt.Errorf("the relay has no pairing session %s; check the id the joining machine printed, "+
			"or start again with sshstate pair, since sessions expire: %w", sessionID, err)
	}
	return err
}

func (c *Client) asVaultID(vaultID protocol.ID, err error) error {
	if protocol.CodeOf(err) == protocol.CodeNotFound {
		return fmt.Errorf("the relay at %s holds no vault %s; copy the vault id from sshstate status on a machine already in the vault: %w",
			c.base.String(), vaultID, err)
	}
	return err
}

type UnreachableError struct {
	URL string
	Err error
}

func (e *UnreachableError) Unwrap() error { return e.Err }

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("cannot reach the relay at %s: %s", e.URL, unreachableCause(e.Err))
}

func unreachableCause(err error) string {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var dns *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &unknownAuthority):
		return "its TLS certificate is not signed by an authority this machine trusts"
	case errors.As(err, &hostname):
		return "its TLS certificate is for a different name"
	case errors.As(err, &invalid):
		return "its TLS certificate is not valid (" + invalid.Error() + ")"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "nothing is listening there (connection refused)"
	case errors.As(err, &dns):
		return "the name " + dns.Name + " does not resolve"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "it did not answer in time"
	}
	return err.Error()
}

func signatureBytes(r *http.Request) int {
	if r == nil {
		return 0
	}
	return len(r.Header.Get(httpsig.HeaderSignature))
}

func decodeError(status int, raw []byte, signatureHeaderBytes int) error {
	var body protocol.ErrorResponse
	if err := json.Unmarshal(raw, &body); err != nil || !protocol.KnownCode(body.Error.Code) {
		hint := ""
		if status >= 400 && status < 500 && signatureHeaderBytes > 4000 {
			hint = fmt.Sprintf("\nThe request carried a %d-byte %s header. "+
				"A reverse proxy in front of the relay is the likely cause: "+
				"raise its header buffer (nginx: large_client_header_buffers 4 16k).",
				signatureHeaderBytes, httpsig.HeaderSignature)
		}
		return protocol.Errorf(protocol.CodeInternal,
			"the relay returned HTTP %d with an unrecognized body%s", status, hint)
	}
	return &protocol.Error{
		Code:    body.Error.Code,
		Message: body.Error.Message,
		Detail:  body.Error.Detail,
	}
}

func (c *Client) Bootstrap(ctx context.Context, secret []byte, g *protocol.Genesis, root protocol.SignedMembershipEvent) (protocol.ID, error) {
	var out protocol.BootstrapResponse
	err := c.call(ctx, http.MethodPost, "/v1/bootstrap",
		protocol.BootstrapRequest{Genesis: *g, MembershipRoot: root}, &out,
		map[string]string{"Authorization": "Bootstrap " + protocol.EncodeBootstrapSecret(secret)})
	return out.VaultID, err
}

func (c *Client) Membership(ctx context.Context) ([]protocol.SignedMembershipEvent, error) {
	var out protocol.MembershipResponse
	if err := c.call(ctx, http.MethodGet, "/v1/membership", nil, &out, nil); err != nil {
		return nil, c.asMember(err)
	}
	return out.Events, nil
}

func (c *Client) AppendMembership(ctx context.Context, ev protocol.SignedMembershipEvent) (*protocol.AppendMembershipResponse, error) {
	var out protocol.AppendMembershipResponse
	err := c.call(ctx, http.MethodPost, "/v1/membership",
		protocol.AppendMembershipRequest{Event: ev}, &out, nil)
	if err != nil {
		return nil, c.asMember(err)
	}
	return &out, nil
}

func (c *Client) Records(ctx context.Context, since, through protocol.Counter, limit int) (*protocol.RecordsResponse, error) {
	q := url.Values{}
	q.Set("since", since.String())
	if through != 0 {
		q.Set("through", through.String())
	}
	if limit > 0 {
		q.Set("limit", protocol.Counter(limit).String())
	}
	var out protocol.RecordsResponse
	if err := c.call(ctx, http.MethodGet, "/v1/records?"+q.Encode(), nil, &out, nil); err != nil {
		return nil, c.asMember(err)
	}
	return &out, nil
}

type PutResult struct {
	Accepted bool
	Seq      protocol.Counter
	Digest   []byte
	Head     *protocol.Envelope
}

func (c *Client) PutRecord(ctx context.Context, env *protocol.Envelope) (*PutResult, error) {
	out := *env
	out.Seq = 0
	status, raw, req, err := c.send(ctx, http.MethodPut, "/v1/records/"+env.Context.RecordID.String(), out,
		map[string]string{httpsig.HeaderIdempotency: env.Context.MutationID.String()})
	if err != nil {
		return nil, err
	}
	if status < 300 {
		var accepted protocol.PutRecordResponse
		if err := json.Unmarshal(raw, &accepted); err != nil {
			return nil, fmt.Errorf("decode the relay's response: %w", err)
		}
		return &PutResult{Accepted: true, Seq: accepted.Seq, Digest: accepted.Digest}, nil
	}

	var body protocol.ErrorResponse
	if err := json.Unmarshal(raw, &body); err != nil || !protocol.KnownCode(body.Error.Code) {
		return nil, decodeError(status, raw, signatureBytes(req))
	}
	if body.Error.Code != protocol.CodeParentMismatch {
		return nil, c.asMember(&protocol.Error{Code: body.Error.Code, Message: body.Error.Message, Detail: body.Error.Detail})
	}
	if body.Head == nil {
		return nil, protocol.Errorf(protocol.CodeInternal,
			"the relay rejected a write without returning the head it rejected it against")
	}
	return &PutResult{Accepted: false, Head: body.Head}, nil
}

func (c *Client) Envelopes(ctx context.Context) ([]protocol.EnvelopeBody, error) {
	var out protocol.EnvelopesResponse
	if err := c.call(ctx, http.MethodGet, "/v1/envelopes", nil, &out, nil); err != nil {
		return nil, c.asMember(err)
	}
	return out.Envelopes, nil
}

func (c *Client) PutEnvelope(ctx context.Context, env protocol.EnvelopeBody) error {
	return c.asMember(c.call(ctx, http.MethodPut, "/v1/envelopes/"+env.ID.String(), env, nil, nil))
}

func (c *Client) RecoveryChallenge(ctx context.Context, vaultID protocol.ID) (*protocol.RecoveryChallengeResponse, error) {
	var out protocol.RecoveryChallengeResponse
	err := c.call(ctx, http.MethodPost, "/v1/recovery/challenge",
		protocol.RecoveryChallengeRequest{VaultID: vaultID}, &out, nil)
	if err != nil {
		return nil, c.asVaultID(vaultID, err)
	}
	return &out, nil
}

func (c *Client) RecoveryComplete(ctx context.Context, req protocol.RecoveryCompleteRequest) (*protocol.RecoveryCompleteResponse, error) {
	var out protocol.RecoveryCompleteResponse
	if err := c.call(ctx, http.MethodPost, "/v1/recovery/complete", req, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreatePairing(ctx context.Context, vaultID protocol.ID, offer protocol.SignedPairingOffer) (*protocol.CreatePairingResponse, error) {
	var out protocol.CreatePairingResponse
	err := c.call(ctx, http.MethodPost, "/v1/pairings", protocol.CreatePairingRequest{
		VaultID: vaultID, Offer: offer.Offer, Signature: offer.Signature,
	}, &out, nil)
	if err != nil {
		return nil, c.asVaultID(vaultID, err)
	}
	return &out, nil
}

func (c *Client) Pairing(ctx context.Context, sessionID protocol.ID) (*protocol.PairingResponse, error) {
	var out protocol.PairingResponse
	if err := c.call(ctx, http.MethodGet, "/v1/pairings/"+sessionID.String(), nil, &out, nil); err != nil {
		return nil, c.asPairing(sessionID, err)
	}
	return &out, nil
}

func (c *Client) ConfirmPairing(ctx context.Context, sessionID protocol.ID, req protocol.ConfirmPairingRequest) (*protocol.PairingResponse, error) {
	var out protocol.PairingResponse
	if err := c.call(ctx, http.MethodPost, "/v1/pairings/"+sessionID.String()+"/confirm", req, &out, nil); err != nil {
		return nil, c.asPairing(sessionID, err)
	}
	return &out, nil
}

func (c *Client) CompletePairing(ctx context.Context, sessionID protocol.ID, req protocol.CompletePairingRequest) (*protocol.PairingResponse, error) {
	var out protocol.PairingResponse
	if err := c.call(ctx, http.MethodPost, "/v1/pairings/"+sessionID.String()+"/complete", req, &out, nil); err != nil {
		return nil, c.asPairing(sessionID, err)
	}
	return &out, nil
}
