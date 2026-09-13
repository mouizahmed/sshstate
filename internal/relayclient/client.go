// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

func (c *Client) send(ctx context.Context, method, path string, in any, headers map[string]string) (int, []byte, error) {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return 0, nil, fmt.Errorf("encode request: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.signer != nil {
		if err := c.signer.Sign(req, body, c.https); err != nil {
			return 0, nil, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("reach the relay: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read the relay's response: %w", err)
	}
	if len(raw) > MaxResponseBytes {
		return 0, nil, protocol.Errorf(protocol.CodeBodyTooLarge,
			"the relay returned more than %d bytes", MaxResponseBytes)
	}
	return resp.StatusCode, raw, nil
}

func (c *Client) call(ctx context.Context, method, path string, in, out any, headers map[string]string) error {
	status, raw, err := c.send(ctx, method, path, in, headers)
	if err != nil {
		return err
	}
	if status >= 300 {
		return decodeError(status, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode the relay's response: %w", err)
	}
	return nil
}

func decodeError(status int, raw []byte) error {
	var body protocol.ErrorResponse
	if err := json.Unmarshal(raw, &body); err != nil || !protocol.KnownCode(body.Error.Code) {
		return protocol.Errorf(protocol.CodeInternal,
			"the relay returned HTTP %d with an unrecognized body", status)
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
		return nil, err
	}
	return out.Events, nil
}

func (c *Client) AppendMembership(ctx context.Context, ev protocol.SignedMembershipEvent) (*protocol.AppendMembershipResponse, error) {
	var out protocol.AppendMembershipResponse
	err := c.call(ctx, http.MethodPost, "/v1/membership",
		protocol.AppendMembershipRequest{Event: ev}, &out, nil)
	if err != nil {
		return nil, err
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
		return nil, err
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
	status, raw, err := c.send(ctx, http.MethodPut, "/v1/records/"+env.Context.RecordID.String(), out,
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
		return nil, protocol.Errorf(protocol.CodeInternal,
			"the relay returned HTTP %d with an unrecognized body", status)
	}
	if body.Error.Code != protocol.CodeParentMismatch {
		return nil, &protocol.Error{Code: body.Error.Code, Message: body.Error.Message, Detail: body.Error.Detail}
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
		return nil, err
	}
	return out.Envelopes, nil
}

func (c *Client) PutEnvelope(ctx context.Context, env protocol.EnvelopeBody) error {
	return c.call(ctx, http.MethodPut, "/v1/envelopes/"+env.ID.String(), env, nil, nil)
}

func (c *Client) RecoveryChallenge(ctx context.Context, vaultID protocol.ID) (*protocol.RecoveryChallengeResponse, error) {
	var out protocol.RecoveryChallengeResponse
	err := c.call(ctx, http.MethodPost, "/v1/recovery/challenge",
		protocol.RecoveryChallengeRequest{VaultID: vaultID}, &out, nil)
	if err != nil {
		return nil, err
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
