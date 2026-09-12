// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

func TestValidateAlias(t *testing.T) {
	good := []string{"prod", "prod-1", "db.internal", "a", "x_y", "0host"}
	for _, a := range good {
		if err := ValidateAlias(a); err != nil {
			t.Errorf("rejected valid alias %q: %v", a, err)
		}
	}
	bad := map[string]string{
		"empty":            "",
		"uppercase":        "Prod",
		"leading dot":      ".prod",
		"leading hyphen":   "-prod",
		"wildcard":         "prod*",
		"negation":         "!prod",
		"space":            "prod host",
		"slash":            "prod/db",
		"too long":         strings.Repeat("a", MaxAliasLen+1),
		"newline":          "prod\nHost evil",
		"non-ascii":        "pröd",
		"question mark":    "prod?",
		"config separator": "prod=x",
	}
	for name, a := range bad {
		if err := ValidateAlias(a); err == nil {
			t.Errorf("%s: accepted invalid alias %q", name, a)
		}
	}
}

func TestUppercaseAliasSuggestsLowercase(t *testing.T) {
	err := ValidateAlias("ProdDB")
	if err == nil || !strings.Contains(err.Error(), `"proddb"`) {
		t.Fatalf("unhelpful message: %v", err)
	}
}

func TestHostPayloadValidation(t *testing.T) {
	base := func() *HostPayload {
		return &HostPayload{
			FormatVersion: PayloadFormatVersion,
			Alias:         "prod",
			HostName:      "10.0.0.5",
			User:          "ubuntu",
			Port:          22,
			KeyIDs:        []protocol.ID{protocol.MustNewID()},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid host rejected: %v", err)
	}

	bad := map[string]func(p *HostPayload){
		"bad version":      func(p *HostPayload) { p.FormatVersion = 2 },
		"no hostname":      func(p *HostPayload) { p.HostName = "" },
		"no user":          func(p *HostPayload) { p.User = "" },
		"port zero":        func(p *HostPayload) { p.Port = 0 },
		"port too high":    func(p *HostPayload) { p.Port = 70000 },
		"bad alias":        func(p *HostPayload) { p.Alias = "Prod" },
		"self jump":        func(p *HostPayload) { j := "prod"; p.ProxyJump = &j },
		"bad jump alias":   func(p *HostPayload) { j := "*"; p.ProxyJump = &j },
		"malformed key id": func(p *HostPayload) { p.KeyIDs = []protocol.ID{"nope"} },
		"duplicate key":    func(p *HostPayload) { p.KeyIDs = append(p.KeyIDs, p.KeyIDs[0]) },
	}
	for name, mutate := range bad {
		p := base()
		mutate(p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted invalid host payload", name)
		}
	}
}

func TestHostPayloadRejectsConfigInjection(t *testing.T) {
	injections := []string{
		"10.0.0.5\n    ProxyCommand touch /tmp/pwned",
		"10.0.0.5\r\n    User root",
		"10.0.0.5 extra",
		" 10.0.0.5",
		"10.0.0.5\t",
		`ho"st`,
	}
	for _, v := range injections {
		p := &HostPayload{
			FormatVersion: PayloadFormatVersion,
			Alias:         "prod",
			HostName:      v,
			User:          "ubuntu",
			Port:          22,
		}
		if err := p.Validate(); err == nil {
			t.Errorf("accepted hostname %q", v)
		}
		p.HostName = "10.0.0.5"
		p.User = v
		if err := p.Validate(); err == nil {
			t.Errorf("accepted user %q", v)
		}
	}
}

func TestKeyPayloadValidation(t *testing.T) {
	base := func() *KeyPayload {
		return &KeyPayload{
			FormatVersion: PayloadFormatVersion,
			PrivateKey:    "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n",
			PublicKey:     "ssh-ed25519 AAAAC3Nz",
			Fingerprint:   "SHA256:abcdef",
			Algorithm:     "ssh-ed25519",
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	bad := map[string]func(p *KeyPayload){
		"no private":      func(p *KeyPayload) { p.PrivateKey = "" },
		"no public":       func(p *KeyPayload) { p.PublicKey = "" },
		"md5 fingerprint": func(p *KeyPayload) { p.Fingerprint = "MD5:aa:bb" },
		"no fingerprint":  func(p *KeyPayload) { p.Fingerprint = "" },
		"no algorithm":    func(p *KeyPayload) { p.Algorithm = "" },
		"unknown version": func(p *KeyPayload) { p.FormatVersion = 99 },
	}
	for name, mutate := range bad {
		p := base()
		mutate(p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted invalid key payload", name)
		}
	}
}

func TestKnownHostPayloadValidation(t *testing.T) {
	base := func() *KnownHostPayload {
		return &KnownHostPayload{
			FormatVersion: PayloadFormatVersion,
			Line:          "10.0.0.5 ssh-ed25519 AAAAC3Nz",
			KeyType:       "ssh-ed25519",
			Fingerprint:   "SHA256:abcdef",
			Status:        TrustApproved,
			LineDigest:    []byte{1, 2, 3},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid known_host rejected: %v", err)
	}
	for _, marker := range []string{"", "@revoked", "@cert-authority"} {
		p := base()
		p.Marker = marker
		if err := p.Validate(); err != nil {
			t.Errorf("rejected marker %q: %v", marker, err)
		}
	}
	bad := map[string]func(p *KnownHostPayload){
		"unknown marker": func(p *KnownHostPayload) { p.Marker = "@trusted" },
		"unknown status": func(p *KnownHostPayload) { p.Status = "maybe" },
		"no line":        func(p *KnownHostPayload) { p.Line = "" },
		"newline":        func(p *KnownHostPayload) { p.Line = "a\nb" },
		"no digest":      func(p *KnownHostPayload) { p.LineDigest = nil },
	}
	for name, mutate := range bad {
		p := base()
		mutate(p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted invalid known_host payload", name)
		}
	}
}
