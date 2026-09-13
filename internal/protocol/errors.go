// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"errors"
	"fmt"
	"net/http"
)

const (
	CodeInvalidRequest    = "invalid_request"
	CodeMalformedEncoding = "malformed_encoding"
	CodeUnsupportedVer    = "unsupported_version"
	CodeUnknownSuite      = "unknown_suite"
	CodeDigestMismatch    = "digest_mismatch"
	CodeIDMismatch        = "id_mismatch"
	CodeSignatureInvalid  = "signature_invalid"
	CodeSignatureExpired  = "signature_expired"
	CodeSignatureReplayed = "signature_replayed"
	CodeDeviceUnknown     = "device_unknown"
	CodeDeviceRevoked     = "device_revoked"
	CodeNotAuthorized     = "not_authorized"
	CodeBootstrapConsumed = "bootstrap_consumed"
	CodeNotFound          = "not_found"
	CodePairingExpired    = "pairing_expired"
	CodePairingConsumed   = "pairing_consumed"
	CodePairingIncomplete = "pairing_incomplete"
	CodeParentMismatch    = "parent_mismatch"
	CodeIdempotencyMismat = "idempotency_mismatch"
	CodeConflictContent   = "conflict_content_mismatch"
	CodeChainMismatch     = "chain_mismatch"
	CodeRotationActive    = "rotation_in_progress"
	CodeBodyTooLarge      = "body_too_large"
	CodeHeaderTooLarge    = "header_too_large"
	CodeRateLimited       = "rate_limited"
	CodeNotImplemented    = "not_implemented"
	CodeInternal          = "internal"
)

var statuses = map[string]int{
	CodeInvalidRequest:    http.StatusBadRequest,
	CodeMalformedEncoding: http.StatusBadRequest,
	CodeUnsupportedVer:    http.StatusBadRequest,
	CodeUnknownSuite:      http.StatusBadRequest,
	CodeDigestMismatch:    http.StatusBadRequest,
	CodeIDMismatch:        http.StatusBadRequest,
	CodeSignatureInvalid:  http.StatusUnauthorized,
	CodeSignatureExpired:  http.StatusUnauthorized,
	CodeSignatureReplayed: http.StatusUnauthorized,
	CodeDeviceUnknown:     http.StatusUnauthorized,
	CodeDeviceRevoked:     http.StatusForbidden,
	CodeNotAuthorized:     http.StatusForbidden,
	CodeBootstrapConsumed: http.StatusForbidden,
	CodeNotFound:          http.StatusNotFound,
	CodePairingExpired:    http.StatusGone,
	CodePairingConsumed:   http.StatusConflict,
	CodePairingIncomplete: http.StatusConflict,
	CodeParentMismatch:    http.StatusConflict,
	CodeIdempotencyMismat: http.StatusConflict,
	CodeConflictContent:   http.StatusConflict,
	CodeChainMismatch:     http.StatusConflict,
	CodeRotationActive:    http.StatusConflict,
	CodeBodyTooLarge:      http.StatusRequestEntityTooLarge,
	CodeHeaderTooLarge:    http.StatusRequestHeaderFieldsTooLarge,
	CodeRateLimited:       http.StatusTooManyRequests,
	CodeNotImplemented:    http.StatusNotImplemented,
	CodeInternal:          http.StatusInternalServerError,
}

type Error struct {
	Code    string
	Message string
	Detail  map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func (e *Error) Status() int {
	if s, ok := statuses[e.Code]; ok {
		return s
	}
	return http.StatusInternalServerError
}

func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func (e *Error) WithDetail(key string, value any) *Error {
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	e.Detail[key] = value
	return e
}

func CodeOf(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return CodeInternal
}

func KnownCode(code string) bool {
	_, ok := statuses[code]
	return ok
}
