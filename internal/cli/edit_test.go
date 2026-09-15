// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/vault"
)

func editReady(t *testing.T) *scripted {
	t.Helper()
	s := newScripted(t)
	kitPath := filepath.Join(t.TempDir(), "kit.txt")
	s.secrets = []string{password, password}
	s.answer = func(string) (string, error) {
		body, _ := os.ReadFile(kitPath)
		kit, err := vault.ParseKit(string(body))
		if err != nil {
			return "", err
		}
		return kit.Checksum(), nil
	}
	s.mustRun(t, "init", "--kit", kitPath)
	s.answer = nil
	s.startDaemon(t)
	s.secrets = []string{password}
	s.mustRun(t, "unlock")
	s.mustRun(t, "add", "bastion", "--hostname", "10.0.0.1", "--user", "ubuntu")
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--jump", "bastion")
	s.mustRun(t, "add", "staging", "--hostname", "10.0.0.7", "--user", "ubuntu")
	s.out.Reset()
	s.errOut.Reset()
	return s
}

func hostByAlias(t *testing.T, s *scripted, alias string) (recordID, hostname, user string, port int) {
	t.Helper()
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.Alias == alias {
			return h.RecordID, h.HostName, h.User, h.Port
		}
	}
	t.Fatalf("no host named %q", alias)
	return "", "", "", 0
}

func TestEditRevisesTheSameRecord(t *testing.T) {
	s := editReady(t)
	before, _, _, _ := hostByAlias(t, s, "prod")

	s.mustRun(t, "edit", "prod", "--hostname", "10.0.0.9")

	after, hostname, _, _ := hostByAlias(t, s, "prod")
	if after != before {
		t.Fatalf("edit created record %s; the host was %s", after, before)
	}
	if hostname != "10.0.0.9" {
		t.Fatalf("HostName is %q", hostname)
	}
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Fatalf("the vault holds %d hosts, expected 3", len(hosts))
	}
	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "HostName 10.0.0.9") {
		t.Fatalf("the generated config was not rewritten:\n%s", body)
	}
}

func TestEditLeavesUngivenFieldsAlone(t *testing.T) {
	s := editReady(t)
	s.mustRun(t, "edit", "prod", "--port", "2222")

	_, hostname, user, port := hostByAlias(t, s, "prod")
	if port != 2222 {
		t.Fatalf("port is %d", port)
	}
	if hostname != "10.0.0.5" || user != "ubuntu" {
		t.Fatalf("edit changed %s@%s as well as the port", user, hostname)
	}
	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ProxyJump bastion") {
		t.Fatalf("the jump host was lost:\n%s", body)
	}
}

func TestEditClearsTheJumpHost(t *testing.T) {
	s := editReady(t)
	s.mustRun(t, "edit", "prod", "--jump", "none")

	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ProxyJump none") {
		t.Fatalf("the jump host was not cleared:\n%s", body)
	}
}

func TestEditRenamesAndRewritesTheConfig(t *testing.T) {
	s := editReady(t)
	before, _, _, _ := hostByAlias(t, s, "prod")

	s.mustRun(t, "edit", "prod", "--alias", "production")

	after, _, _, _ := hostByAlias(t, s, "production")
	if after != before {
		t.Fatalf("a rename moved the host from record %s to %s", before, after)
	}
	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Host production") {
		t.Fatalf("the generated config still names the old alias:\n%s", body)
	}
}

func TestEditRefusesToOrphanAJumpHost(t *testing.T) {
	s := editReady(t)
	err := s.run(t, "edit", "bastion", "--alias", "gateway")
	if err == nil {
		t.Fatal("the rename was accepted")
	}
	if !strings.Contains(err.Error(), "prod") {
		t.Fatalf("the refusal does not name the host that would break: %v", err)
	}
	if _, hostname, _, _ := hostByAlias(t, s, "bastion"); hostname != "10.0.0.1" {
		t.Fatalf("the refused rename changed the host anyway: %s", hostname)
	}
}

func TestEditRefusesADuplicateAlias(t *testing.T) {
	s := editReady(t)
	err := s.run(t, "edit", "staging", "--alias", "prod")
	if err == nil {
		t.Fatal("two hosts were allowed to share an alias")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if _, hostname, _, _ := hostByAlias(t, s, "staging"); hostname != "10.0.0.7" {
		t.Fatalf("the refused edit changed the host anyway: %s", hostname)
	}
	if _, hostname, _, _ := hostByAlias(t, s, "prod"); hostname != "10.0.0.5" {
		t.Fatalf("the refused edit overwrote the host it collided with: %s", hostname)
	}
}

func TestEditNeedsAnAliasThatExists(t *testing.T) {
	s := editReady(t)
	err := s.run(t, "edit", "nowhere", "--hostname", "10.0.0.7")
	if err == nil || !strings.Contains(err.Error(), "nowhere") {
		t.Fatalf("expected a refusal naming the alias, got %v", err)
	}
}

func TestEditWithNothingToChangeSaysSo(t *testing.T) {
	s := editReady(t)
	err := s.run(t, "edit", "prod")
	if err == nil {
		t.Fatal("an edit with no flags was accepted")
	}
	for _, want := range []string{"--hostname", "--key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
}
