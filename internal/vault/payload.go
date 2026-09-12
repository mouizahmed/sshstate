// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

const PayloadFormatVersion = 1

const DefaultPort = 22

type HostPayload struct {
	FormatVersion int           `json:"format_version"`
	Alias         string        `json:"alias"`
	HostName      string        `json:"hostname"`
	User          string        `json:"user"`
	Port          int           `json:"port"`
	ProxyJump     *string       `json:"proxy_jump"`
	KeyIDs        []protocol.ID `json:"key_ids"`
}

func (p *HostPayload) Validate() error {
	if p.FormatVersion != PayloadFormatVersion {
		return fmt.Errorf("unsupported host payload version %d", p.FormatVersion)
	}
	if err := ValidateAlias(p.Alias); err != nil {
		return err
	}
	if p.HostName == "" {
		return errors.New("host has no HostName")
	}
	if err := validateConfigToken("HostName", p.HostName); err != nil {
		return err
	}
	if p.User == "" {
		return errors.New("host has no User")
	}
	if err := validateConfigToken("User", p.User); err != nil {
		return err
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("port %d is out of range", p.Port)
	}
	if p.ProxyJump != nil {
		if err := ValidateAlias(*p.ProxyJump); err != nil {
			return fmt.Errorf("proxy_jump: %w", err)
		}
		if *p.ProxyJump == p.Alias {
			return fmt.Errorf("host %q lists itself as its own ProxyJump", p.Alias)
		}
	}
	seen := make(map[protocol.ID]bool, len(p.KeyIDs))
	for _, id := range p.KeyIDs {
		if !id.Valid() {
			return fmt.Errorf("host %q references malformed key id %q", p.Alias, id)
		}
		if seen[id] {
			return fmt.Errorf("host %q lists key %s twice", p.Alias, id)
		}
		seen[id] = true
	}
	return nil
}

type KeyPayload struct {
	FormatVersion int    `json:"format_version"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	Fingerprint   string `json:"fingerprint"`
	Algorithm     string `json:"algorithm"`
	Comment       string `json:"comment"`
}

func (p *KeyPayload) Validate() error {
	if p.FormatVersion != PayloadFormatVersion {
		return fmt.Errorf("unsupported key payload version %d", p.FormatVersion)
	}
	if p.PrivateKey == "" {
		return errors.New("key record has no private key")
	}
	if p.PublicKey == "" {
		return errors.New("key record has no public key")
	}
	if !strings.HasPrefix(p.Fingerprint, "SHA256:") {
		return fmt.Errorf("fingerprint %q is not an OpenSSH SHA256 fingerprint", p.Fingerprint)
	}
	if p.Algorithm == "" {
		return errors.New("key record has no algorithm")
	}
	return nil
}

type TrustStatus string

const (
	TrustApproved TrustStatus = "approved"
	TrustPending  TrustStatus = "pending"
)

type KnownHostPayload struct {
	FormatVersion int            `json:"format_version"`
	Line          string         `json:"line"`
	KeyType       string         `json:"key_type"`
	Fingerprint   string         `json:"fingerprint"`
	Marker        string         `json:"marker"`
	Status        TrustStatus    `json:"status"`
	LineDigest    protocol.Bytes `json:"line_digest"`
}

func (p *KnownHostPayload) Validate() error {
	if p.FormatVersion != PayloadFormatVersion {
		return fmt.Errorf("unsupported known_host payload version %d", p.FormatVersion)
	}
	if p.Line == "" {
		return errors.New("known_host record has no line")
	}
	if strings.ContainsAny(p.Line, "\n\r") {
		return errors.New("known_host line contains a newline")
	}
	switch p.Marker {
	case "", "@revoked", "@cert-authority":
	default:
		return fmt.Errorf("unknown known_hosts marker %q", p.Marker)
	}
	switch p.Status {
	case TrustApproved, TrustPending:
	default:
		return fmt.Errorf("unknown trust status %q", p.Status)
	}
	if len(p.LineDigest) == 0 {
		return errors.New("known_host record has no line digest")
	}
	return nil
}

func validateConfigToken(field, value string) error {
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("%s contains a newline", field)
	}
	if strings.ContainsAny(value, "\"\\") {
		return fmt.Errorf("%s contains a quote or backslash, which OpenSSH would reparse", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s has leading or trailing whitespace", field)
	}
	if strings.ContainsAny(value, " \t") {
		return fmt.Errorf("%s contains whitespace", field)
	}
	return nil
}
