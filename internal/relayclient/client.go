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
	"runtime"
	"syscall"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
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
	base, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, errors.New("relay URL is malformed")
	}
	if base.User != nil || base.Opaque != "" ||
		(base.Path != "" && base.Path != "/") || base.RawPath != "" ||
		base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return nil, errors.New("relay URL must contain only a scheme, host, and optional port")
	}
	base.Path = ""
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

type reply struct {
	status int
	body   []byte
	req    *http.Request
	sent   time.Time
	date   time.Time
}

func (c *Client) send(ctx context.Context, method, path string, in any, headers map[string]string) (reply, error) {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return reply{}, fmt.Errorf("encode request: %w", err)
		}
	}
	return c.transfer(ctx, method, path, body, headers, MaxResponseBytes)
}

func (c *Client) transfer(ctx context.Context, method, path string, body []byte, headers map[string]string, limit int) (reply, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.signer != nil {
		if err := c.signer.Sign(req, body, c.https); err != nil {
			return reply{}, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return reply{}, &UnreachableError{URL: c.base.String(), Err: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return reply{}, fmt.Errorf("read the relay's response: %w", err)
	}
	if len(raw) > limit {
		return reply{}, protocol.Errorf(protocol.CodeBodyTooLarge,
			"the relay returned more than %d bytes", limit)
	}
	if gatewayFailure(resp.StatusCode) {
		if _, ok := relayErrorBody(raw); !ok {
			return reply{}, &UnreachableError{URL: c.base.String(), Err: gatewayError(resp.StatusCode)}
		}
	}
	date, _ := http.ParseTime(resp.Header.Get("Date"))
	return reply{status: resp.StatusCode, body: raw, req: req, sent: c.localTime(), date: date}, nil
}

func (c *Client) call(ctx context.Context, method, path string, in, out any, headers map[string]string) error {
	rep, err := c.send(ctx, method, path, in, headers)
	if err != nil {
		return err
	}
	status, raw := rep.status, rep.body
	if status >= 300 {
		return explainClock(decodeError(status, raw, signatureBytes(rep.req)), rep)
	}
	if out == nil {
		return nil
	}
	if err := protocol.StrictUnmarshalLimit(raw, out, MaxResponseBytes); err != nil {
		return fmt.Errorf("decode the relay's response: %w", err)
	}
	return nil
}

func (c *Client) asMember(err error) error {
	switch protocol.CodeOf(err) {
	case protocol.CodeNotFound:
		return fmt.Errorf("the relay at %s does not hold this vault; if the relay was reset or started on a new database, "+
			"this machine still has the vault: give the relay a new bootstrap secret, then run on your most up-to-date machine: "+
			"sshstate connect %s --bootstrap-secret <file>: %w", c.base.String(), c.base.String(), err)
	case protocol.CodeDeviceUnknown:
		return fmt.Errorf("the relay at %s does not know this device, which happens when it was restored from a backup older than this device; "+
			"run sshstate connect %s --rejoin on a machine that has been in the vault longer, then run it here: %w",
			c.base.String(), c.base.String(), err)
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

func (c *Client) localTime() time.Time {
	if c.signer != nil && c.signer.Now != nil {
		return c.signer.Now()
	}
	return time.Now()
}

func explainClock(err error, rep reply) error {
	if protocol.CodeOf(err) != protocol.CodeSignatureExpired {
		return err
	}
	if rep.date.IsZero() {
		return fmt.Errorf("the relay refused this request's timestamp, so this machine's clock and the relay's disagree; "+
			"make sure both set their time automatically, then try again: %w", err)
	}
	skew := rep.sent.Sub(rep.date).Round(time.Minute)
	direction := "ahead of"
	if skew < 0 {
		skew, direction = -skew, "behind"
	}
	return fmt.Errorf("the relay refused this request's timestamp: this machine's clock is %s %s the relay's; "+
		"make sure both set their time automatically, then try again: %w", skew, direction, err)
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
	var gateway gatewayError
	switch {
	case errors.As(err, &gateway):
		return fmt.Sprintf("the proxy in front of it answered %s, so the relay behind that proxy is not running or the proxy cannot reach it", gateway)
	case errors.As(err, &unknownAuthority):
		return "its TLS certificate is not signed by an authority this machine trusts"
	case errors.As(err, &hostname):
		return "its TLS certificate is for a different name"
	case errors.As(err, &invalid):
		return "its TLS certificate is not valid (" + invalid.Error() + ")"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "nothing is listening there (connection refused)"
	case errors.Is(err, syscall.EHOSTUNREACH) && runtime.GOOS == "darwin":
		return "no route to host; for a relay on your local network, check that sshstate is allowed under System Settings > Privacy & Security > Local Network"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "no route to host"
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

func relayErrorBody(raw []byte) (protocol.ErrorResponse, bool) {
	var body protocol.ErrorResponse
	if err := protocol.StrictUnmarshalLimit(raw, &body, MaxResponseBytes); err != nil || !protocol.KnownCode(body.Error.Code) {
		return body, false
	}
	return body, true
}

type gatewayError int

func (g gatewayError) Error() string { return fmt.Sprintf("HTTP %d", int(g)) }

func gatewayFailure(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func decodeError(status int, raw []byte, signatureHeaderBytes int) error {
	body, ok := relayErrorBody(raw)
	if !ok {
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

func (c *Client) stream(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	headers := map[string]string{}
	if body != nil {
		headers["Content-Type"] = "application/octet-stream"
	}
	rep, err := c.transfer(ctx, method, path, body, headers, crypto.MaxStreamBytes)
	if err != nil {
		return nil, err
	}
	if rep.status >= 300 {
		return nil, explainClock(decodeError(rep.status, rep.body, signatureBytes(rep.req)), rep)
	}
	return rep.body, nil
}

func (c *Client) PutPairingSnapshot(ctx context.Context, sessionID protocol.ID, snapshot []byte) error {
	_, err := c.stream(ctx, http.MethodPut, "/v1/pairings/"+sessionID.String()+"/snapshot", snapshot)
	return c.asPairing(sessionID, err)
}

func (c *Client) PairingSnapshot(ctx context.Context, sessionID protocol.ID) ([]byte, error) {
	return c.stream(ctx, http.MethodGet, "/v1/pairings/"+sessionID.String()+"/snapshot", nil)
}

func (c *Client) PutRecoveryArchive(ctx context.Context, epoch protocol.Counter, archive []byte) error {
	_, err := c.stream(ctx, http.MethodPut, "/v1/recovery/archive?key_epoch="+epoch.String(), archive)
	return c.asMember(err)
}

func (c *Client) RecoveryArchive(ctx context.Context, vaultID protocol.ID) ([]byte, error) {
	body, err := c.stream(ctx, http.MethodGet, "/v1/recovery/archive?vault_id="+vaultID.String(), nil)
	return body, c.asVaultID(vaultID, err)
}

func (c *Client) Bootstrap(ctx context.Context, secret []byte, g *protocol.Genesis, root protocol.SignedMembershipEvent) (protocol.ID, error) {
	var out protocol.BootstrapResponse
	err := c.call(ctx, http.MethodPost, "/v1/bootstrap",
		protocol.BootstrapRequest{Genesis: *g, MembershipRoot: root}, &out,
		map[string]string{"Authorization": "Bootstrap " + protocol.EncodeBootstrapSecret(secret)})
	return out.VaultID, err
}

func (c *Client) Seed(ctx context.Context, secret []byte, g *protocol.Genesis, events []protocol.SignedMembershipEvent) (protocol.ID, error) {
	if len(events) == 0 {
		return "", fmt.Errorf("seed: no membership chain")
	}
	var out protocol.BootstrapResponse
	err := c.call(ctx, http.MethodPost, "/v1/bootstrap",
		protocol.BootstrapRequest{Genesis: *g, MembershipRoot: events[0], Membership: events[1:], Seeded: true}, &out,
		map[string]string{"Authorization": "Bootstrap " + protocol.EncodeBootstrapSecret(secret)})
	return out.VaultID, err
}

func (c *Client) ImportRecords(ctx context.Context, req *protocol.ImportRequest) (*protocol.ImportResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	rep, err := c.transfer(ctx, http.MethodPost, "/v1/records/import", body,
		map[string]string{"Content-Type": "application/json"}, MaxResponseBytes)
	if err != nil {
		return nil, err
	}
	if rep.status >= 300 {
		return nil, c.asMember(explainClock(decodeError(rep.status, rep.body, signatureBytes(rep.req)), rep))
	}
	var out protocol.ImportResponse
	if err := protocol.StrictUnmarshalLimit(rep.body, &out, MaxResponseBytes); err != nil {
		return nil, fmt.Errorf("decode the relay's response: %w", err)
	}
	return &out, nil
}

func (c *Client) URL() string { return c.base.String() }

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
	rep, err := c.send(ctx, http.MethodPut, "/v1/records/"+env.Context.RecordID.String(), out,
		map[string]string{httpsig.HeaderIdempotency: env.Context.MutationID.String()})
	if err != nil {
		return nil, err
	}
	status, raw := rep.status, rep.body
	if status < 300 {
		var accepted protocol.PutRecordResponse
		if err := protocol.StrictUnmarshalLimit(raw, &accepted, MaxResponseBytes); err != nil {
			return nil, fmt.Errorf("decode the relay's response: %w", err)
		}
		return &PutResult{Accepted: true, Seq: accepted.Seq, Digest: accepted.Digest}, nil
	}

	body, ok := relayErrorBody(raw)
	if !ok {
		return nil, decodeError(status, raw, signatureBytes(rep.req))
	}
	if body.Error.Code != protocol.CodeParentMismatch {
		return nil, c.asMember(explainClock(&protocol.Error{Code: body.Error.Code, Message: body.Error.Message, Detail: body.Error.Detail}, rep))
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
