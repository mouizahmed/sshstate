// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/httpsig"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

type api struct {
	*harness
	server *httptest.Server
	signer *httpsig.Signer
}

func newAPI(t *testing.T) *api {
	t.Helper()
	h := newHarness(t)
	srv := httptest.NewServer(NewServer(h.store, Config{PublicHTTPS: false}).Handler())
	t.Cleanup(srv.Close)
	return &api{
		harness: h,
		server:  srv,
		signer: &httpsig.Signer{
			VaultID:  h.vaultID,
			DeviceID: h.first.id,
			Key:      h.first.signing,
			Now:      func() time.Time { return h.store.now() },
		},
	}
}

func (a *api) do(t *testing.T, method, path string, payload any, headers map[string]string) (int, []byte) {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, a.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	if err := a.signer.Sign(r, body, false); err != nil {
		t.Fatal(err)
	}
	return send(t, r)
}

func (a *api) raw(t *testing.T, method, path string, payload any, headers map[string]string) (int, []byte) {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, a.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return send(t, r)
}

func send(t *testing.T, r *http.Request) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func decodeInto(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
}

func wantCode(t *testing.T, status int, body []byte, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status %d, want %d: %s", status, wantStatus, body)
	}
	var e protocol.ErrorResponse
	decodeInto(t, body, &e)
	if e.Error.Code != wantCode {
		t.Fatalf("code %q, want %q: %s", e.Error.Code, wantCode, body)
	}
}

func TestSignedRoutesRequireASignature(t *testing.T) {
	a := newAPI(t)
	for _, path := range []string{"/v1/membership", "/v1/envelopes", "/v1/records"} {
		status, body := a.raw(t, http.MethodGet, path, nil, nil)
		wantCode(t, status, body, http.StatusUnauthorized, protocol.CodeSignatureInvalid)
	}
	status, body := a.do(t, http.MethodGet, "/v1/membership", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("a signed request failed: %d %s", status, body)
	}
	var got protocol.MembershipResponse
	decodeInto(t, body, &got)
	if len(got.Events) != 1 {
		t.Fatalf("membership returned %d events, want the root", len(got.Events))
	}
}

func TestRecordRoundTripOverHTTP(t *testing.T) {
	a := newAPI(t)
	id := protocol.MustNewID()
	create := a.envelope(a.first, id, 1, nil, false, "one")

	status, body := a.do(t, http.MethodPut, "/v1/records/"+id.String(), create,
		map[string]string{httpsig.HeaderIdempotency: create.Context.MutationID.String()})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var put protocol.PutRecordResponse
	decodeInto(t, body, &put)
	if !put.Accepted || put.Seq != 1 {
		t.Fatalf("unexpected outcome: %+v", put)
	}

	status, body = a.do(t, http.MethodGet, "/v1/records?since=0&limit=10", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var page protocol.RecordsResponse
	decodeInto(t, body, &page)
	if len(page.Changes) != 1 || page.Changes[0].Seq != 1 || page.HasMore {
		t.Fatalf("unexpected page: %+v", page)
	}
	roundTripped, err := page.Changes[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	original, err := create.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTripped, original) {
		t.Fatal("the envelope came back with a different digest")
	}
}

func TestParentMismatchReturnsTheHead(t *testing.T) {
	a := newAPI(t)
	id := protocol.MustNewID()
	create := a.envelope(a.first, id, 1, nil, false, "one")
	a.mustPut(create)

	loser := a.envelope(a.first, id, 2, bytes.Repeat([]byte{9}, 32), false, "loser")
	status, body := a.do(t, http.MethodPut, "/v1/records/"+id.String(), loser,
		map[string]string{httpsig.HeaderIdempotency: loser.Context.MutationID.String()})
	if status != http.StatusConflict {
		t.Fatalf("status %d: %s", status, body)
	}
	var e protocol.ErrorResponse
	decodeInto(t, body, &e)
	if e.Error.Code != protocol.CodeParentMismatch {
		t.Fatalf("code %q", e.Error.Code)
	}
	if e.Head == nil || e.Head.Context.Rev != 1 {
		t.Fatalf("the rejection did not carry the head: %s", body)
	}
}

func TestIdempotencyKeyMustMatchTheMutationID(t *testing.T) {
	a := newAPI(t)
	id := protocol.MustNewID()
	env := a.envelope(a.first, id, 1, nil, false, "one")

	status, body := a.do(t, http.MethodPut, "/v1/records/"+id.String(), env,
		map[string]string{httpsig.HeaderIdempotency: protocol.MustNewID().String()})
	wantCode(t, status, body, http.StatusBadRequest, protocol.CodeIDMismatch)

	other := protocol.MustNewID()
	status, body = a.do(t, http.MethodPut, "/v1/records/"+other.String(), env,
		map[string]string{httpsig.HeaderIdempotency: env.Context.MutationID.String()})
	wantCode(t, status, body, http.StatusBadRequest, protocol.CodeIDMismatch)
}

func TestSubmittedEnvelopeMustNotCarrySeq(t *testing.T) {
	a := newAPI(t)
	id := protocol.MustNewID()
	env := a.envelope(a.first, id, 1, nil, false, "one")
	env.Seq = 99
	status, body := a.do(t, http.MethodPut, "/v1/records/"+id.String(), env,
		map[string]string{httpsig.HeaderIdempotency: env.Context.MutationID.String()})
	wantCode(t, status, body, http.StatusBadRequest, protocol.CodeInvalidRequest)
}

func TestEnvelopesAreScopedToTheCaller(t *testing.T) {
	a := newAPI(t)
	id := protocol.MustNewID()
	recipient := a.first.id
	body := protocol.EnvelopeBody{
		ID:                id,
		RecipientDeviceID: &recipient,
		Purpose:           protocol.PurposeRotation,
		KeyEpoch:          1,
		Ciphertext:        []byte("sealed"),
	}
	status, resp := a.do(t, http.MethodPut, "/v1/envelopes/"+id.String(), body, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, resp)
	}

	status, resp = a.do(t, http.MethodGet, "/v1/envelopes", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, resp)
	}
	var got protocol.EnvelopesResponse
	decodeInto(t, resp, &got)
	if len(got.Envelopes) != 1 || got.Envelopes[0].ID != id {
		t.Fatalf("unexpected envelopes: %+v", got)
	}
	if string(got.Envelopes[0].Ciphertext) != "sealed" {
		t.Fatal("the ciphertext did not survive the round trip")
	}

	status, resp = a.do(t, http.MethodPut, "/v1/envelopes/"+protocol.MustNewID().String(), body, nil)
	wantCode(t, status, resp, http.StatusBadRequest, protocol.CodeIDMismatch)
}

func TestBootstrapOverHTTP(t *testing.T) {
	store := emptyStore(t)
	if err := store.SetBootstrapSecret(secret(1)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store, Config{}).Handler())
	defer srv.Close()

	g, root := newVault(t)
	payload := protocol.BootstrapRequest{Genesis: *g, MembershipRoot: root}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	post := func(auth string) (int, []byte) {
		r, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/bootstrap", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		return send(t, r)
	}

	status, resp := post("")
	wantCode(t, status, resp, http.StatusForbidden, protocol.CodeNotAuthorized)

	status, resp = post("Bootstrap " + EncodeBootstrapSecret(secret(9)))
	wantCode(t, status, resp, http.StatusForbidden, protocol.CodeNotAuthorized)

	status, resp = post("Bootstrap " + EncodeBootstrapSecret(secret(1)))
	if status != http.StatusCreated {
		t.Fatalf("status %d: %s", status, resp)
	}
	var created protocol.BootstrapResponse
	decodeInto(t, resp, &created)
	if created.VaultID != g.VaultID {
		t.Fatalf("bootstrap created vault %s", created.VaultID)
	}

	status, resp = post("Bootstrap " + EncodeBootstrapSecret(secret(1)))
	wantCode(t, status, resp, http.StatusForbidden, protocol.CodeBootstrapConsumed)
}

func TestPairingOverHTTP(t *testing.T) {
	a := newAPI(t)
	joiner := newDevice(t)
	offer := a.offer(joiner, a.vaultID)

	status, body := a.raw(t, http.MethodPost, "/v1/pairings", protocol.CreatePairingRequest{
		VaultID: a.vaultID, Offer: offer.Offer, Signature: offer.Signature,
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("status %d: %s", status, body)
	}
	var created protocol.CreatePairingResponse
	decodeInto(t, body, &created)

	status, body = a.raw(t, http.MethodGet, "/v1/pairings/"+created.SessionID.String(), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var session protocol.PairingResponse
	decodeInto(t, body, &session)
	if session.State != string(PairingOffered) {
		t.Fatalf("session is %s", session.State)
	}

	approval := approval(a.first)
	digest := a.transcriptDigest(created.SessionID, offer, approval)
	status, body = a.raw(t, http.MethodPost, "/v1/pairings/"+created.SessionID.String()+"/confirm",
		protocol.ConfirmPairingRequest{
			Approver:     &approval,
			Confirmation: a.confirmation(a.first, created.SessionID, a.vaultID, digest).Confirmation,
			Signature:    a.confirmation(a.first, created.SessionID, a.vaultID, digest).Signature,
		}, nil)
	if status != http.StatusOK {
		t.Fatalf("approver confirm: %d %s", status, body)
	}

	joinerConf := a.confirmation(joiner, created.SessionID, a.vaultID, digest)
	status, body = a.raw(t, http.MethodPost, "/v1/pairings/"+created.SessionID.String()+"/confirm",
		protocol.ConfirmPairingRequest{
			Confirmation: joinerConf.Confirmation,
			Signature:    joinerConf.Signature,
		}, nil)
	if status != http.StatusOK {
		t.Fatalf("joiner confirm: %d %s", status, body)
	}
	decodeInto(t, body, &session)
	if session.State != string(PairingConfirmed) {
		t.Fatalf("session is %s after both confirmations", session.State)
	}

	ev := a.enrolment(joiner, digest)
	status, body = a.raw(t, http.MethodPost, "/v1/pairings/"+created.SessionID.String()+"/complete",
		protocol.CompletePairingRequest{
			MembershipEvent: &ev,
			Bundle:          []byte("sealed-bundle"),
		}, nil)
	if status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}

	status, body = a.raw(t, http.MethodPost, "/v1/pairings/"+created.SessionID.String()+"/complete",
		protocol.CompletePairingRequest{Acknowledged: true}, nil)
	if status != http.StatusOK {
		t.Fatalf("acknowledge: %d %s", status, body)
	}
	decodeInto(t, body, &session)
	if session.State != string(PairingCompleted) {
		t.Fatalf("session is %s after acknowledgement", session.State)
	}
	if string(session.Bundle) != "sealed-bundle" {
		t.Fatal("the sealed bundle did not reach the joiner")
	}
}

func TestRecoveryChallengeOverHTTP(t *testing.T) {
	a := newAPI(t)
	status, body := a.raw(t, http.MethodPost, "/v1/recovery/challenge",
		protocol.RecoveryChallengeRequest{VaultID: a.vaultID}, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var got protocol.RecoveryChallengeResponse
	decodeInto(t, body, &got)
	if got.Nonce == "" || got.Genesis == nil {
		t.Fatalf("the challenge is incomplete: %s", body)
	}
	if got.Genesis.VaultID != a.vaultID {
		t.Fatal("the challenge returned another vault's genesis")
	}

	status, body = a.raw(t, http.MethodPost, "/v1/recovery/challenge",
		protocol.RecoveryChallengeRequest{VaultID: protocol.MustNewID()}, nil)
	wantCode(t, status, body, http.StatusNotFound, protocol.CodeNotFound)
}

func TestRotationRoutesAreReserved(t *testing.T) {
	a := newAPI(t)
	status, body := a.do(t, http.MethodPost, "/v1/rotations", struct{}{}, nil)
	wantCode(t, status, body, http.StatusNotImplemented, protocol.CodeNotImplemented)

	status, body = a.do(t, http.MethodDelete, "/v1/rotations/"+protocol.MustNewID().String(), nil, nil)
	wantCode(t, status, body, http.StatusNotImplemented, protocol.CodeNotImplemented)
}

func TestUnknownRouteAndOversizedBody(t *testing.T) {
	a := newAPI(t)
	status, body := a.raw(t, http.MethodGet, "/v1/nothing", nil, nil)
	wantCode(t, status, body, http.StatusNotFound, protocol.CodeNotFound)

	oversized := bytes.Repeat([]byte{'a'}, MaxBodyBytes+1)
	r, err := http.NewRequest(http.MethodPost, a.server.URL+"/v1/pairings", bytes.NewReader(oversized))
	if err != nil {
		t.Fatal(err)
	}
	status, body = send(t, r)
	wantCode(t, status, body, http.StatusRequestEntityTooLarge, protocol.CodeBodyTooLarge)
}

func TestPaginationBoundsOverHTTP(t *testing.T) {
	a := newAPI(t)
	a.mustPut(a.envelope(a.first, protocol.MustNewID(), 1, nil, false, "one"))

	for _, query := range []string{"?since=5&through=2", "?since=0&through=99", "?since=x", "?since=01"} {
		status, body := a.do(t, http.MethodGet, "/v1/records"+query, nil, nil)
		wantCode(t, status, body, http.StatusBadRequest, protocol.CodeInvalidRequest)
	}
}

func TestErrorBodiesCarryOnlyFrozenCodes(t *testing.T) {
	a := newAPI(t)
	status, body := a.do(t, http.MethodPut, "/v1/records/not-an-id", struct{}{},
		map[string]string{httpsig.HeaderIdempotency: protocol.MustNewID().String()})
	if status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", status, body)
	}
	var e protocol.ErrorResponse
	decodeInto(t, body, &e)
	if !protocol.KnownCode(e.Error.Code) {
		t.Fatalf("error code %q is not in the frozen set", e.Error.Code)
	}
}
