// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Client struct {
	http   *http.Client
	socket string
}

func NewClient(socket string) *Client {
	return &Client{
		socket: socket,
		http: &http.Client{
			Timeout: 2 * time.Minute,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

var ErrDaemonUnavailable = errors.New("the sshstate daemon is not running")

type APIError struct {
	Status  int
	Message string
	Code    string
}

func (e *APIError) Error() string { return e.Message }

func (e *APIError) Is(target error) bool {
	other, ok := target.(*APIError)
	return ok && other.Code == e.Code
}

var (
	ErrLocked              = &APIError{Code: CodeLocked}
	ErrRecoveryUnconfirmed = &APIError{Code: CodeRecoveryUnconfirmed}
)

func (c *Client) do(ctx context.Context, method, route string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		if len(raw) > MaxRequestBytes {
			return fmt.Errorf("request body exceeds %d bytes", MaxRequestBytes)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://sshstate"+route, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return fmt.Errorf("%w (socket %s)", ErrDaemonUnavailable, c.socket)
		}
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxRequestBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e Error
		if err := json.Unmarshal(raw, &e); err != nil || e.Error == "" {
			return &APIError{Status: resp.StatusCode, Message: fmt.Sprintf("daemon returned %s", resp.Status)}
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error, Code: e.Code}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	return &out, c.do(ctx, http.MethodGet, RouteStatus, nil, &out)
}

func (c *Client) Unlock(ctx context.Context, password string) (*StatusResponse, error) {
	var out StatusResponse
	return &out, c.do(ctx, http.MethodPost, RouteUnlock, UnlockRequest{Password: password}, &out)
}

func (c *Client) Lock(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	return &out, c.do(ctx, http.MethodPost, RouteLock, struct{}{}, &out)
}

func (c *Client) Keys(ctx context.Context) ([]KeyResponse, error) {
	var out ListResponse[KeyResponse]
	return out.Items, c.do(ctx, http.MethodGet, RouteKeys, nil, &out)
}

func (c *Client) AddKey(ctx context.Context, req AddKeyRequest) (*KeyResponse, error) {
	var out KeyResponse
	return &out, c.do(ctx, http.MethodPost, RouteKeys, req, &out)
}

func (c *Client) Hosts(ctx context.Context) ([]HostResponse, error) {
	var out ListResponse[HostResponse]
	return out.Items, c.do(ctx, http.MethodGet, RouteHosts, nil, &out)
}

func (c *Client) AddHost(ctx context.Context, req AddHostRequest) (*HostResponse, error) {
	var out HostResponse
	return &out, c.do(ctx, http.MethodPost, RouteHosts, req, &out)
}

func (c *Client) EditHost(ctx context.Context, req EditHostRequest) (*HostResponse, error) {
	var out HostResponse
	return &out, c.do(ctx, http.MethodPost, RouteHostEdit, req, &out)
}

func (c *Client) Import(ctx context.Context, req ImportRequest) (*ImportResponse, error) {
	var out ImportResponse
	return &out, c.do(ctx, http.MethodPost, RouteImport, req, &out)
}

func (c *Client) TrustList(ctx context.Context) (*TrustListResponse, error) {
	var out TrustListResponse
	return &out, c.do(ctx, http.MethodGet, RouteTrustList, nil, &out)
}

func (c *Client) TrustApprove(ctx context.Context, req TrustApproveRequest) (*TrustApproveResponse, error) {
	var out TrustApproveResponse
	return &out, c.do(ctx, http.MethodPost, RouteTrustApprove, req, &out)
}

func (c *Client) RemoveHost(ctx context.Context, req RemoveRequest) (*RemoveResponse, error) {
	var out RemoveResponse
	return &out, c.do(ctx, http.MethodPost, RouteHostRemove, req, &out)
}

func (c *Client) RemoveKey(ctx context.Context, req RemoveRequest) (*RemoveResponse, error) {
	var out RemoveResponse
	return &out, c.do(ctx, http.MethodPost, RouteKeyRemove, req, &out)
}

func (c *Client) Generate(ctx context.Context) (*GenerateResponse, error) {
	var out GenerateResponse
	return &out, c.do(ctx, http.MethodPost, RouteGenerate, struct{}{}, &out)
}

func (c *Client) Doctor(ctx context.Context) (*DoctorResponse, error) {
	var out DoctorResponse
	return &out, c.do(ctx, http.MethodGet, RouteDoctor, nil, &out)
}

func (c *Client) TrustPreview(ctx context.Context) (*TrustPreviewResponse, error) {
	var out TrustPreviewResponse
	return &out, c.do(ctx, http.MethodGet, RouteTrust, nil, &out)
}

func (c *Client) TrustImport(ctx context.Context, digests []string) (*TrustImportResponse, error) {
	var out TrustImportResponse
	return &out, c.do(ctx, http.MethodPost, RouteTrustImport, TrustImportRequest{Digests: digests}, &out)
}

func (c *Client) RecoveryChallenge(ctx context.Context) (*RecoveryChallengeResponse, error) {
	var out RecoveryChallengeResponse
	return &out, c.do(ctx, http.MethodPost, RouteRecoveryChallenge, struct{}{}, &out)
}

func (c *Client) RecoveryConfirm(ctx context.Context, nonce, signature string) (*StatusResponse, error) {
	var out StatusResponse
	return &out, c.do(ctx, http.MethodPost, RouteRecoveryConfirm,
		RecoveryConfirmRequest{Nonce: nonce, Signature: signature}, &out)
}

func (c *Client) Shutdown(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, RouteShutdown, struct{}{}, nil)
}

func (c *Client) Connect(ctx context.Context, req ConnectRequest) (*ConnectResponse, error) {
	var out ConnectResponse
	return &out, c.do(ctx, http.MethodPost, RouteConnect, req, &out)
}

func (c *Client) Sync(ctx context.Context) (*SyncResponse, error) {
	var out SyncResponse
	return &out, c.do(ctx, http.MethodPost, RouteSync, struct{}{}, &out)
}

func (c *Client) Devices(ctx context.Context) (*DevicesResponse, error) {
	var out DevicesResponse
	return &out, c.do(ctx, http.MethodGet, RouteDevices, nil, &out)
}

func (c *Client) Revoke(ctx context.Context, req RevokeRequest) (*RevokeResponse, error) {
	var out RevokeResponse
	return &out, c.do(ctx, http.MethodPost, RouteRevoke, req, &out)
}

func (c *Client) Export(ctx context.Context, path string) (*ExportResponse, error) {
	var out ExportResponse
	return &out, c.do(ctx, http.MethodPost, RouteExport, ExportRequest{Path: path}, &out)
}

func (c *Client) Conflicts(ctx context.Context) (*ConflictsResponse, error) {
	var out ConflictsResponse
	return &out, c.do(ctx, http.MethodGet, RouteConflicts, nil, &out)
}

func (c *Client) PairApprove(ctx context.Context, sessionID string) (*PairApproveResponse, error) {
	var out PairApproveResponse
	return &out, c.do(ctx, http.MethodPost, RoutePairApprove,
		PairApproveRequest{SessionID: sessionID}, &out)
}

func (c *Client) PairDeliver(ctx context.Context, sessionID string) (*PairDeliverResponse, error) {
	var out PairDeliverResponse
	return &out, c.do(ctx, http.MethodPost, RoutePairDeliver,
		PairDeliverRequest{SessionID: sessionID}, &out)
}

func (c *Client) Resolve(ctx context.Context, req ResolveRequest) (*ResolveResponse, error) {
	var out ResolveResponse
	return &out, c.do(ctx, http.MethodPost, RouteResolve, req, &out)
}
