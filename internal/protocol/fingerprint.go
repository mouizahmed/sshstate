// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

const (
	FingerprintChars      = 52
	FingerprintGroupSize  = 4
	FingerprintGroupCount = 13
)

var fingerprintEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func Fingerprint(digest []byte) (string, error) {
	if len(digest) != sha256.Size {
		return "", fmt.Errorf("fingerprint needs a %d-byte digest, got %d", sha256.Size, len(digest))
	}
	s := fingerprintEncoding.EncodeToString(digest)
	if len(s) != FingerprintChars {
		return "", fmt.Errorf("fingerprint encoded to %d characters, expected %d", len(s), FingerprintChars)
	}
	return s, nil
}

func FingerprintGroups(digest []byte) ([]string, error) {
	s, err := Fingerprint(digest)
	if err != nil {
		return nil, err
	}
	groups := make([]string, 0, FingerprintGroupCount)
	for i := 0; i < len(s); i += FingerprintGroupSize {
		groups = append(groups, s[i:i+FingerprintGroupSize])
	}
	return groups, nil
}

func FormatFingerprint(digest []byte) (string, error) {
	groups, err := FingerprintGroups(digest)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, g := range groups {
		fmt.Fprintf(&b, "%2d %s", i+1, g)
		switch {
		case i == len(groups)-1:
			b.WriteString("\n")
		case (i+1)%4 == 0:
			b.WriteString("\n")
		default:
			b.WriteString("   ")
		}
	}
	return b.String(), nil
}

func ParseFingerprint(s string) ([]byte, error) {
	var clean strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			clean.WriteRune(r)
		case r >= 'a' && r <= 'z':
			clean.WriteRune(r - 'a' + 'A')
		case r == ' ', r == '\t', r == '\n', r == '\r', r == '-':
		default:
			return nil, fmt.Errorf("fingerprint contains %q, which is not in the alphabet", r)
		}
	}
	text := clean.String()
	if len(text) != FingerprintChars {
		return nil, fmt.Errorf("fingerprint has %d characters, expected %d", len(text), FingerprintChars)
	}
	digest, err := fingerprintEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("fingerprint is not valid base32: %w", err)
	}
	if len(digest) != sha256.Size {
		return nil, errors.New("fingerprint did not decode to a 32-byte digest")
	}
	if fingerprintEncoding.EncodeToString(digest) != text {
		return nil, errors.New("fingerprint has non-zero unused bits in its final character")
	}
	return digest, nil
}
