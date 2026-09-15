// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestKitRedactsItsSecretsInEveryFormatVerb(t *testing.T) {
	store := newStore(t)
	_, kit, err := Init(store, InitOptions{Password: []byte("pw"), DeviceLabel: "redaction"})
	if err != nil {
		t.Fatal(err)
	}
	seed := base64.RawURLEncoding.EncodeToString(kit.SigningSeed)
	if seed == "" || kit.EncryptionIdentity == "" {
		t.Fatal("the kit carries no secret to redact")
	}

	for _, rendered := range []string{
		fmt.Sprintf("%v", kit),
		fmt.Sprintf("%s", kit),
		fmt.Sprintf("%#v", kit),
		fmt.Sprintf("%v", *kit),
		fmt.Sprintf("%v", []*Kit{kit}),
		fmt.Sprintf("%v", struct{ K *Kit }{kit}),
		fmt.Sprintf("%v", map[string]*Kit{"k": kit}),
	} {
		if strings.Contains(rendered, seed) {
			t.Fatalf("the signing seed reached %q", rendered)
		}
		if strings.Contains(rendered, kit.EncryptionIdentity) {
			t.Fatalf("the encryption identity reached %q", rendered)
		}
		if !strings.Contains(rendered, "redacted") {
			t.Fatalf("nothing marks this as redacted: %q", rendered)
		}
		if !strings.Contains(rendered, string(kit.VaultID)) {
			t.Fatalf("the vault id was redacted too, leaving nothing to identify: %q", rendered)
		}
	}
}

func TestMarshalStillCarriesTheSecrets(t *testing.T) {
	store := newStore(t)
	_, kit, err := Init(store, InitOptions{Password: []byte("pw"), DeviceLabel: "redaction"})
	if err != nil {
		t.Fatal(err)
	}
	body := kit.Marshal()
	seed := base64.RawURLEncoding.EncodeToString(kit.SigningSeed)
	if !strings.Contains(body, seed) {
		t.Fatal("Marshal redacted the seed; the saved kit would be useless")
	}
	back, err := ParseKit(body)
	if err != nil {
		t.Fatal(err)
	}
	if back.Checksum() != kit.Checksum() {
		t.Fatal("the round trip changed the kit")
	}
}
