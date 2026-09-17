package cli

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestRemoveDropsTheHostAndRegenerates(t *testing.T) {
	s, firstID, _ := listReady(t)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", firstID)
	s.mustRun(t, "add", "web", "--hostname", "10.0.0.6", "--user", "ubuntu")
	s.out.Reset()

	s.mustRun(t, "remove", "prod", "--yes")

	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Alias != "web" {
		t.Fatalf("after removing prod the vault holds %+v", hosts)
	}
	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "Host prod") {
		t.Fatalf("the generated config still has the host:\n%s", body)
	}
	keys, err := s.Env.Client().Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("removing a host took %d keys with it", 2-len(keys))
	}
}

func TestRemoveRefusesWhileAnotherHostJumpsThroughIt(t *testing.T) {
	s, _ := newUnlocked(t)
	s.mustRun(t, "add", "bastion", "--hostname", "10.0.0.1", "--user", "ubuntu")
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--jump", "bastion")

	err := s.run(t, "remove", "bastion", "--yes")
	if err == nil {
		t.Fatal("the jump host was removed out from under prod")
	}
	if !strings.Contains(err.Error(), "prod") {
		t.Fatalf("the refusal does not name the host that would break: %v", err)
	}
	hosts, herr := s.Env.Client().Hosts(context.Background())
	if herr != nil {
		t.Fatal(herr)
	}
	if len(hosts) != 2 {
		t.Fatalf("the refused removal changed the vault: %+v", hosts)
	}
}

func TestRemoveKeyRefusesWhileAHostOffersIt(t *testing.T) {
	s, firstID, _ := listReady(t)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", firstID)

	err := s.run(t, "remove-key", firstID, "--yes")
	if err == nil {
		t.Fatal("a key still referenced by a host was removed")
	}
	if !strings.Contains(err.Error(), "prod") {
		t.Fatalf("the refusal does not name the host: %v", err)
	}

	s.mustRun(t, "edit", "prod", "--key", "")
	s.mustRun(t, "remove-key", firstID, "--yes")
	keys, kerr := s.Env.Client().Keys(context.Background())
	if kerr != nil {
		t.Fatal(kerr)
	}
	for _, k := range keys {
		if k.RecordID == firstID {
			t.Fatal("the key survived removal once nothing referenced it")
		}
	}
}

func TestRemoveAsksBeforeDestroying(t *testing.T) {
	s, firstID, _ := listReady(t)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu", "--key", firstID)
	s.lines = []string{"n"}
	s.out.Reset()

	s.mustRun(t, "remove", "prod")

	if !strings.Contains(s.out.String(), "Nothing changed") {
		t.Fatalf("a declined removal did not say so:\n%s", s.out)
	}
	hosts, err := s.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatal("the declined removal went ahead anyway")
	}
}

func TestResolveResurrectsAHostThatWasRemoved(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, a)
	a.mustRun(t, "sync")

	b := pairInto(t, r.url, a, vaultID, "b's own password")

	b.mustRun(t, "edit", "prod", "--hostname", "10.9.9.9")
	a.mustRun(t, "remove", "prod", "--yes")
	a.mustRun(t, "sync")
	if err := b.run(t, "sync"); err != nil {
		t.Fatalf("sync after a removal: %v\n%s", err, b.errOut)
	}

	b.out.Reset()
	b.mustRun(t, "conflicts")
	conflictID := ""
	for _, line := range strings.Split(b.out.String(), "\n") {
		for _, f := range strings.Fields(line) {
			if len(f) == 32 {
				conflictID = f
			}
		}
	}
	if conflictID == "" {
		t.Fatalf("the edit that lost to a removal was not preserved:\n%s", b.out)
	}

	if err := b.run(t, "resolve", conflictID); err == nil {
		t.Fatal("a conflict against a deleted record resolved without --resurrect")
	}
	b.mustRun(t, "resolve", conflictID, "--resurrect")

	hosts, err := b.Env.Client().Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hosts {
		if h.Alias == "prod" {
			found = true
			if h.HostName != "10.9.9.9" {
				t.Fatalf("the resurrected host is %s, expected the preserved edit", h.HostName)
			}
		}
	}
	if !found {
		t.Fatalf("--resurrect did not bring the host back: %+v", hosts)
	}
}

func TestADeviceThatJoinsAfterARemovalFollowsItsResurrection(t *testing.T) {
	r := newTestRelay(t)
	a, _ := ready(t)
	a.mustRun(t, "connect", r.url, "--bootstrap-secret", r.secretPath)
	vaultID := vaultIDOf(t, a)
	b := pairInto(t, r.url, a, vaultID, "b's own password")

	b.mustRun(t, "edit", "prod", "--hostname", "10.9.9.9")
	a.mustRun(t, "remove", "prod", "--yes")
	a.mustRun(t, "sync")
	b.mustRun(t, "sync")

	c := pairInto(t, r.url, a, vaultID, "c's own password")

	b.out.Reset()
	b.mustRun(t, "conflicts")
	conflictID := ""
	for _, f := range strings.Fields(b.out.String()) {
		if len(f) == 32 {
			conflictID = f
		}
	}
	if conflictID == "" {
		t.Fatalf("no conflict to resurrect from:\n%s", b.out)
	}
	b.mustRun(t, "resolve", conflictID, "--resurrect")
	b.mustRun(t, "sync")

	if err := c.run(t, "sync"); err != nil {
		t.Fatalf("a device that joined after the removal could not follow the resurrection: %v", err)
	}
	if !hostAliases(t, c)["prod"] {
		t.Fatal("the resurrected host did not reach the device that joined after its removal")
	}
}
