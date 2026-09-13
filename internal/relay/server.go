// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/httpsig"
	"github.com/mouizahmed/sshstate/internal/protocol"
)

const MaxBodyBytes = 4 << 20

type Config struct {
	PublicHTTPS     bool
	BootstrapSecret []byte
}

type Server struct {
	store    *Store
	cfg      Config
	verifier *httpsig.Verifier
}

func NewServer(store *Store, cfg Config) *Server {
	return &Server{
		store: store,
		cfg:   cfg,
		verifier: &httpsig.Verifier{
			Keys:   store,
			Nonces: store,
			Now:    store.now,
		},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/bootstrap", s.wrap(s.handleBootstrap))
	mux.HandleFunc("POST /v1/pairings", s.wrap(s.handleCreatePairing))
	mux.HandleFunc("GET /v1/pairings/{id}", s.wrap(s.handleGetPairing))
	mux.HandleFunc("POST /v1/pairings/{id}/confirm", s.wrap(s.handleConfirmPairing))
	mux.HandleFunc("POST /v1/pairings/{id}/complete", s.wrap(s.handleCompletePairing))
	mux.HandleFunc("GET /v1/membership", s.wrap(s.signed(s.handleGetMembership)))
	mux.HandleFunc("POST /v1/membership", s.wrap(s.signed(s.handleAppendMembership)))
	mux.HandleFunc("GET /v1/envelopes", s.wrap(s.signed(s.handleGetEnvelopes)))
	mux.HandleFunc("PUT /v1/envelopes/{id}", s.wrap(s.signed(s.handlePutEnvelope)))
	mux.HandleFunc("POST /v1/recovery/challenge", s.wrap(s.handleRecoveryChallenge))
	mux.HandleFunc("POST /v1/recovery/complete", s.wrap(s.handleRecoveryComplete))
	mux.HandleFunc("GET /v1/records", s.wrap(s.signed(s.handleGetRecords)))
	mux.HandleFunc("PUT /v1/records/{id}", s.wrap(s.signed(s.handlePutRecord)))

	for _, pattern := range []string{
		"POST /v1/rotations",
		"GET /v1/rotations/{id}",
		"PUT /v1/rotations/{id}/staged/{item}",
		"POST /v1/rotations/{id}/commit",
		"DELETE /v1/rotations/{id}",
	} {
		mux.HandleFunc(pattern, s.wrap(func(w http.ResponseWriter, r *http.Request, req *request) error {
			return protocol.Errorf(protocol.CodeNotImplemented,
				"rotation ships in milestone 3b; see docs/rotation.md")
		}))
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, protocol.Errorf(protocol.CodeNotFound, "no such route"))
	})
	return mux
}

type request struct {
	Body   []byte
	Signed *httpsig.Result
}

type handler func(http.ResponseWriter, *http.Request, *request) error

func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			s.fail(w, err)
			return
		}
		if err := h(w, r, &request{Body: body}); err != nil {
			s.fail(w, err)
		}
	}
}

func (s *Server) signed(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, req *request) error {
		result, err := s.verifier.Verify(r, req.Body, s.cfg.PublicHTTPS)
		if err != nil {
			return err
		}
		vaultID, err := s.store.VaultID()
		if err != nil {
			return err
		}
		if result.VaultID != vaultID {
			return protocol.Errorf(protocol.CodeNotFound, "no such vault")
		}
		req.Signed = result
		return h(w, r, req)
	}
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidRequest, "could not read the request body")
	}
	if len(body) > MaxBodyBytes {
		return nil, protocol.Errorf(protocol.CodeBodyTooLarge,
			"the request body exceeds %d bytes", MaxBodyBytes)
	}
	return body, nil
}

func decode(req *request, v any) error {
	if len(req.Body) == 0 {
		return protocol.Errorf(protocol.CodeInvalidRequest, "the request has no body")
	}
	if err := protocol.StrictUnmarshal(req.Body, v); err != nil {
		return protocol.Errorf(protocol.CodeMalformedEncoding, "%v", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":{"code":"internal","message":"could not encode the response"}}`,
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		pe = protocol.Errorf(protocol.CodeInternal, "internal error")
	}
	writeJSON(w, pe.Status(), protocol.ErrorResponse{
		Error: protocol.ErrorBody{Code: pe.Code, Message: pe.Message, Detail: pe.Detail},
	})
}

func pathID(r *http.Request, name string) (protocol.ID, error) {
	id := protocol.ID(r.PathValue(name))
	if !id.Valid() {
		return "", protocol.Errorf(protocol.CodeInvalidRequest,
			"%s is not a 128-bit lowercase hex id", name)
	}
	return id, nil
}

func queryCounter(r *http.Request, name string) (protocol.Counter, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, nil
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, protocol.Errorf(protocol.CodeInvalidRequest, "%s has a leading zero", name)
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, protocol.Errorf(protocol.CodeInvalidRequest, "%s is not a decimal number", name)
	}
	return protocol.Counter(v), nil
}

func bootstrapSecret(r *http.Request) ([]byte, error) {
	const prefix = "Bootstrap "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return nil, protocol.Errorf(protocol.CodeNotAuthorized, "bootstrap requires the one-time secret")
	}
	secret, err := DecodeBootstrapSecret(strings.TrimPrefix(header, prefix))
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeNotAuthorized, "bootstrap requires the one-time secret")
	}
	return secret, nil
}

func stampOf(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }
