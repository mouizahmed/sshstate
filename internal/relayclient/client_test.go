package relayclient

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/crypto"
	"github.com/mouizahmed/sshstate/internal/httpsig"
	"github.com/mouizahmed/sshstate/internal/membership"
	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/relay"
)

const stamp = "2026-09-12T00:00:00Z"

type device struct {
	id      protocol.ID
	signing *crypto.SigningKey
	enc     *crypto.EncryptionKey
}

func newDevice(t *testing.T) device {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := crypto.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	return device{id: protocol.MustNewID(), signing: sk, enc: ek}
}

type fixture struct {
	store   *relay.Store
	client  *Client
	genesis *protocol.Genesis
	first   device
	vaultID protocol.ID
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	first := newDevice(t)
	recovery := newDevice(t)
	g := &protocol.Genesis{
		Domain:               protocol.GenesisDomain,
		FormatVersion:        protocol.GenesisFormatVersion,
		Suite:                crypto.SuiteID,
		VaultID:              protocol.MustNewID(),
		CreatedAt:            stamp,
		FirstDeviceID:        first.id,
		FirstDeviceVerifyKey: first.signing.Verifier().Bytes(),
		FirstDeviceRecipient: first.enc.Recipient().String(),
		RecoveryVerifyKey:    recovery.signing.Verifier().Bytes(),
		RecoveryRecipient:    recovery.enc.Recipient().String(),
	}
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	root, err := membership.Root(g, first.signing, now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := relay.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.CreateVault(g, root); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(relay.NewServer(store, relay.Config{PublicHTTPS: false}).Handler())
	t.Cleanup(srv.Close)

	client, err := New(Options{
		BaseURL: srv.URL,
		Signer: &httpsig.Signer{
			VaultID:  g.VaultID,
			DeviceID: first.id,
			Key:      first.signing,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{store: store, client: client, genesis: g, first: first, vaultID: g.VaultID, now: now}
}

func (f *fixture) envelope(t *testing.T, recordID protocol.ID, rev protocol.Counter, parent []byte, filler string) *protocol.Envelope {
	t.Helper()
	env := &protocol.Envelope{
		Context: protocol.Context{
			Domain:        protocol.RecordDomain,
			FormatVersion: protocol.RecordFormatVersion,
			VaultID:       f.vaultID,
			RecordID:      recordID,
			RecordType:    protocol.RecordHost,
			KeyEpoch:      1,
			Rev:           rev,
			ParentDigest:  parent,
			MutationID:    protocol.MustNewID(),
			UpdatedBy:     f.first.id,
		},
		Nonce:      bytes.Repeat([]byte{0x11}, 24),
		Ciphertext: []byte("ciphertext:" + filler),
	}
	msg, err := env.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := f.first.signing.Sign(protocol.RecordSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	return env
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

func TestURLValidation(t *testing.T) {
	for name, url := range map[string]string{
		"https":         "https://relay.example.com",
		"loopback http": "http://127.0.0.1:8080",
		"localhost":     "http://localhost:8080",
	} {
		if _, err := New(Options{BaseURL: url}); err != nil {
			t.Errorf("%s was rejected: %v", name, err)
		}
	}
	for name, url := range map[string]string{
		"public http": "http://relay.example.com",
		"no scheme":   "relay.example.com",
		"no host":     "https://",
		"ftp":         "ftp://relay.example.com",
	} {
		if _, err := New(Options{BaseURL: url}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestMembershipRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	events, err := f.client.Membership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want the root", len(events))
	}
	chain, err := membership.Validate(f.genesis, events)
	if err != nil {
		t.Fatalf("the fetched chain did not validate: %v", err)
	}

	second := newDevice(t)
	ev, err := chain.Enroll(
		membership.Signer{DeviceID: f.first.id, Key: f.first.signing},
		membership.DeviceKeys{
			ID:        second.id,
			VerifyKey: second.signing.Verifier().Bytes(),
			Recipient: second.enc.Recipient().String(),
		},
		bytes.Repeat([]byte{7}, 32), f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.client.AppendMembership(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if out.ChainSeq != 2 {
		t.Fatalf("chain_seq is %s after enrolment", out.ChainSeq)
	}

	_, err = f.client.AppendMembership(ctx, ev)
	mustCode(t, err, protocol.CodeChainMismatch)
}

func TestPutAndFetchRecords(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := protocol.MustNewID()

	create := f.envelope(t, id, 1, nil, "one")
	res, err := f.client.PutRecord(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || res.Seq != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}

	page, err := f.client.Records(ctx, 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Changes) != 1 || page.SnapshotCursor != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	got, err := page.Changes[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	want, err := create.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the envelope came back with a different digest")
	}
}

func TestRetryIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	create := f.envelope(t, protocol.MustNewID(), 1, nil, "one")

	first, err := f.client.PutRecord(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.client.PutRecord(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Accepted || again.Seq != first.Seq {
		t.Fatalf("the retry produced a different outcome: %+v", again)
	}
	page, err := f.client.Records(ctx, 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Changes) != 1 {
		t.Fatalf("the retry appended a second change: %d", len(page.Changes))
	}
}

func TestParentMismatchReturnsTheHead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := protocol.MustNewID()

	create := f.envelope(t, id, 1, nil, "one")
	if _, err := f.client.PutRecord(ctx, create); err != nil {
		t.Fatal(err)
	}
	loser := f.envelope(t, id, 2, bytes.Repeat([]byte{9}, 32), "loser")
	res, err := f.client.PutRecord(ctx, loser)
	if err != nil {
		t.Fatalf("a parent mismatch surfaced as an error: %v", err)
	}
	if res.Accepted {
		t.Fatal("the losing candidate was accepted")
	}
	if res.Head == nil || res.Head.Context.Rev != 1 {
		t.Fatalf("the rejection did not carry the head: %+v", res)
	}
	if err := res.Head.Validate(); err != nil {
		t.Fatalf("the returned head is not a valid envelope: %v", err)
	}
}

func TestErrorCodesSurviveTheWire(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	stranger := newDevice(t)
	env := f.envelope(t, protocol.MustNewID(), 1, nil, "one")
	env.Context.UpdatedBy = stranger.id
	msg, err := env.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := stranger.signing.Sign(protocol.RecordSignatureDomain, msg)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	_, err = f.client.PutRecord(ctx, env)
	mustCode(t, err, protocol.CodeDeviceUnknown)

	_, err = f.client.Records(ctx, 9, 2, 10)
	mustCode(t, err, protocol.CodeInvalidRequest)
}

func TestUnrecognizedResponsesAreNotGuessedAt(t *testing.T) {
	if got := protocol.CodeOf(decodeError(502, []byte("<html>bad gateway</html>"), 0)); got != protocol.CodeInternal {
		t.Fatalf("an HTML error page decoded as %s", got)
	}
	if got := protocol.CodeOf(decodeError(400, []byte(`{"error":{"code":"invented","message":"x"}}`), 0)); got != protocol.CodeInternal {
		t.Fatalf("an unknown code was passed through as %s", got)
	}
	known := decodeError(409, []byte(`{"error":{"code":"parent_mismatch","message":"x"}}`), 0)
	if got := protocol.CodeOf(known); got != protocol.CodeParentMismatch {
		t.Fatalf("a frozen code decoded as %s", got)
	}
}

func TestAProxyHeaderLimitIsNamed(t *testing.T) {
	err := decodeError(400, []byte("<html>400 Bad Request</html>"), 4423)
	if !strings.Contains(err.Error(), "large_client_header_buffers") {
		t.Fatalf("the error does not point at the proxy: %v", err)
	}
	if !strings.Contains(err.Error(), "4423-byte") {
		t.Fatalf("the error does not say how big the header was: %v", err)
	}
	quiet := decodeError(400, []byte("<html>400 Bad Request</html>"), 120)
	if strings.Contains(quiet.Error(), "large_client_header_buffers") {
		t.Fatalf("a small request was blamed on the proxy: %v", quiet)
	}
	upstream := decodeError(502, []byte("<html>502</html>"), 4423)
	if strings.Contains(upstream.Error(), "large_client_header_buffers") {
		t.Fatalf("a gateway error was blamed on the proxy's header buffers: %v", upstream)
	}
}

func TestEnvelopesRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	recipient := f.first.id
	body := protocol.EnvelopeBody{
		ID:                protocol.MustNewID(),
		RecipientDeviceID: &recipient,
		Purpose:           protocol.PurposeRotation,
		KeyEpoch:          1,
		Ciphertext:        []byte("age-sealed"),
	}
	if err := f.client.PutEnvelope(ctx, body); err != nil {
		t.Fatal(err)
	}
	got, err := f.client.Envelopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != body.ID || string(got[0].Ciphertext) != "age-sealed" {
		t.Fatalf("unexpected envelopes: %+v", got)
	}
}

func TestRecoveryChallenge(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	got, err := f.client.RecoveryChallenge(ctx, f.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce == "" || got.Genesis == nil || got.Genesis.VaultID != f.vaultID {
		t.Fatalf("incomplete challenge: %+v", got)
	}
	_, err = f.client.RecoveryChallenge(ctx, protocol.MustNewID())
	mustCode(t, err, protocol.CodeNotFound)
}

func TestBootstrapThroughTheClient(t *testing.T) {
	store, err := relay.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secret := bytes.Repeat([]byte{3}, protocol.BootstrapSecretBytes)
	if err := store.SetBootstrapSecret(secret); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.NewServer(store, relay.Config{}).Handler())
	defer srv.Close()

	client, err := New(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	root, err := membership.Root(f.genesis, f.first.signing, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, err := client.Bootstrap(ctx, secret, f.genesis, root)
	if err != nil {
		t.Fatal(err)
	}
	if id != f.genesis.VaultID {
		t.Fatalf("bootstrap created vault %s", id)
	}
	_, err = client.Bootstrap(ctx, secret, f.genesis, root)
	mustCode(t, err, protocol.CodeBootstrapConsumed)
}

func TestAnUnreachableRelayIsExplained(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	client, err := New(Options{BaseURL: url})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RecoveryChallenge(context.Background(), protocol.MustNewID())
	var unreachable *UnreachableError
	if !errors.As(err, &unreachable) {
		t.Fatalf("want an UnreachableError, got %v", err)
	}
	if got := err.Error(); !strings.HasPrefix(got, "cannot reach the relay at "+url+": ") || !strings.Contains(got, "connection refused") {
		t.Fatalf("unhelpful message: %s", got)
	}
}

func TestAProxyWhoseRelayIsDownIsExplained(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(status)
			w.Write([]byte("<html>gateway</html>"))
		}))
		client, err := New(Options{BaseURL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.RecoveryChallenge(context.Background(), protocol.MustNewID())
		srv.Close()
		var unreachable *UnreachableError
		if !errors.As(err, &unreachable) {
			t.Fatalf("HTTP %d: want an UnreachableError, got %v", status, err)
		}
		if got := err.Error(); !strings.HasPrefix(got, "cannot reach the relay at "+srv.URL+": the proxy in front of it answered HTTP "+strconv.Itoa(status)) {
			t.Fatalf("HTTP %d: unhelpful message: %s", status, got)
		}
	}
}

func TestARelayErrorOnAGatewayStatusIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":{"code":"rate_limited","message":"slow down"}}`))
	}))
	defer srv.Close()
	client, err := New(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RecoveryChallenge(context.Background(), protocol.MustNewID())
	mustCode(t, err, protocol.CodeRateLimited)
}

func TestARelayThatLostTheVaultSaysSo(t *testing.T) {
	f := newFixture(t)
	empty, err := relay.Open(filepath.Join(t.TempDir(), "reset.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { empty.Close() })
	srv := httptest.NewServer(relay.NewServer(empty, relay.Config{PublicHTTPS: false}).Handler())
	t.Cleanup(srv.Close)
	client, err := New(Options{BaseURL: srv.URL, Signer: f.client.signer})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Membership(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not hold this vault") || !strings.Contains(err.Error(), "--bootstrap-secret") {
		t.Fatalf("a relay that lost the vault was not explained: %v", err)
	}
	if protocol.CodeOf(err) != protocol.CodeNotFound {
		t.Fatalf("the explanation hid the protocol code: %v", err)
	}
}

func TestAnUntrustedCertificateIsExplained(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	client, err := New(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RecoveryChallenge(context.Background(), protocol.MustNewID())
	if err == nil || !strings.Contains(err.Error(), "TLS certificate is not signed by an authority this machine trusts") {
		t.Fatalf("an untrusted certificate was not explained: %v", err)
	}
}

func TestASkewedClockIsNamedWithTheDifference(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(relay.NewServer(f.store, relay.Config{PublicHTTPS: false}).Handler())
	t.Cleanup(srv.Close)
	client, err := New(Options{
		BaseURL: srv.URL,
		Signer: &httpsig.Signer{
			VaultID:  f.vaultID,
			DeviceID: f.first.id,
			Key:      f.first.signing,
			Now:      func() time.Time { return time.Now().Add(10 * time.Minute) },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Membership(context.Background())
	if err == nil || !strings.Contains(err.Error(), "this machine's clock is 10m") || !strings.Contains(err.Error(), "ahead of the relay's") {
		t.Fatalf("a skewed clock was not explained: %v", err)
	}
	if protocol.CodeOf(err) != protocol.CodeSignatureExpired {
		t.Fatalf("the explanation hid the protocol code: %v", err)
	}
}
