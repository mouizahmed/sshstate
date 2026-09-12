// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
)

func doctorFixture(t *testing.T, extraBefore string) (*harness, []control.DoctorFinding) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh is not installed")
	}
	h := start(t)
	if _, err := h.client.Unlock(context.Background(), testPassword); err != nil {
		t.Fatal(err)
	}
	var keyIDs []string
	for _, comment := range []string{"first@test", "second@test"} {
		key, err := h.client.AddKey(context.Background(), control.AddKeyRequest{
			PrivateKey: string(testKeyPEM(t, comment)),
		})
		if err != nil {
			t.Fatal(err)
		}
		keyIDs = append(keyIDs, key.RecordID)
	}
	if _, err := h.client.AddHost(context.Background(), control.AddHostRequest{
		Alias: "prod", HostName: "10.0.0.5", User: "ubuntu", Port: 2222,
		KeyIDs: keyIDs,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sshconfig.Install(h.layout); err != nil {
		t.Fatal(err)
	}
	if extraBefore != "" {
		body, err := os.ReadFile(h.layout.UserSSHConfig)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.layout.UserSSHConfig, append([]byte(extraBefore+"\n"), body...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.daemon.effectiveConfigArgs = []string{"-F", h.layout.UserSSHConfig}

	findings, err := h.daemon.diagnose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return h, findings
}

func problems(findings []control.DoctorFinding) []string {
	var out []string
	for _, f := range findings {
		if f.Severity == sevProblem {
			out = append(out, f.Check+": "+f.Detail)
		}
	}
	return out
}

func TestDoctorReportsNoProblemsOnGeneratedConfig(t *testing.T) {
	_, findings := doctorFixture(t, "")
	if got := problems(findings); len(got) != 0 {
		t.Fatalf("doctor reported problems on a freshly generated config:\n  %s", strings.Join(got, "\n  "))
	}
	var checked bool
	for _, f := range findings {
		if f.Check == "ssh config include" && f.Severity == sevOK {
			checked = true
		}
	}
	if !checked {
		t.Fatal("doctor did not confirm the Include")
	}
}

func TestDoctorDetectsManagedFieldOverrides(t *testing.T) {
	cases := []struct {
		name     string
		override string
		want     string
	}{
		{"hostname", "Host prod\n    HostName 192.168.1.1\n", "hostname"},
		{"user", "Host prod\n    User someone-else\n", "user"},
		{"port", "Host prod\n    Port 22\n", "port"},
		{"proxyjump", "Host prod\n    ProxyJump bastion.example.com\n", "proxyjump"},
		{"stricthostkeychecking", "Host prod\n    StrictHostKeyChecking no\n", "stricthostkeychecking"},
		{"updatehostkeys", "Host prod\n    UpdateHostKeys yes\n", "updatehostkeys"},
		{"identityagent", "Host prod\n    IdentityAgent /tmp/someone-elses.sock\n", "identityagent"},
		{"identitiesonly", "Host prod\n    IdentitiesOnly no\n", "identitiesonly"},
		{"forwardagent", "Host prod\n    ForwardAgent yes\n", "forwardagent"},
		{"userknownhostsfile", "Host prod\n    UserKnownHostsFile /tmp/somewhere-else\n", "UserKnownHostsFile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, findings := doctorFixture(t, tc.override)
			got := problems(findings)
			found := false
			for _, p := range got {
				if strings.Contains(strings.ToLower(p), strings.ToLower(tc.want)) {
					found = true
				}
			}
			if !found {
				t.Fatalf("overriding %s was not reported.\nproblems:\n  %s",
					tc.name, strings.Join(got, "\n  "))
			}
		})
	}
}

func TestDoctorReportsAccumulatedIdentities(t *testing.T) {
	_, findings := doctorFixture(t, "Host prod\n    IdentityFile /tmp/unmanaged_key\n")
	var warned bool
	for _, f := range findings {
		if f.Check == "accumulated identities" && strings.Contains(f.Detail, "/tmp/unmanaged_key") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("an unmanaged IdentityFile was not reported: %+v", findings)
	}
}

func TestDoctorChecksTrustFileOrder(t *testing.T) {
	h, findings := doctorFixture(t, "")
	if got := problems(findings); len(got) != 0 {
		t.Fatalf("unexpected problems: %v", got)
	}
	swapped := "Host prod\n    UserKnownHostsFile " +
		h.layout.KnownHosts() + " " + h.layout.CaptureFile() + "\n"
	_, findings = doctorFixture(t, swapped)
	var reported bool
	for _, p := range problems(findings) {
		if strings.Contains(p, "UserKnownHostsFile") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("swapping the trust files was not reported:\n  %s",
			strings.Join(problems(findings), "\n  "))
	}
}

func TestDoctorSkipsEffectiveConfigWhenLocked(t *testing.T) {
	h := start(t)
	if _, err := sshconfig.Install(h.layout); err != nil {
		t.Fatal(err)
	}
	findings, err := h.daemon.diagnose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var explained bool
	for _, f := range findings {
		if f.Check == "effective configuration" && strings.Contains(f.Detail, "locked") {
			explained = true
		}
	}
	if !explained {
		t.Fatalf("doctor did not explain that the vault is locked: %+v", findings)
	}
}

func TestDoctorReportsWrongPermissions(t *testing.T) {
	h := start(t)
	if err := os.Chmod(h.layout.Data, 0o755); err != nil {
		t.Fatal(err)
	}
	findings, err := h.daemon.diagnose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, p := range problems(findings) {
		if strings.Contains(p, "permissions") && strings.Contains(p, filepath.Base(h.layout.Data)) {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("a world-readable data directory was not reported:\n  %s",
			strings.Join(problems(findings), "\n  "))
	}
}

func TestDoctorReportsPendingTrust(t *testing.T) {
	first := publicKeyLine(t)
	h := trustHarness(t, "[10.0.0.5]:2222 "+first+"\n")
	preview, err := h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.TrustImport(context.Background(), []string{preview.Candidates[0].Digest}); err != nil {
		t.Fatal(err)
	}
	second := publicKeyLine(t)
	if err := os.WriteFile(h.layout.UserKnownHosts(),
		[]byte("[10.0.0.5]:2222 "+first+"\n[10.0.0.5]:2222 "+second+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err = h.client.TrustPreview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range preview.Candidates {
		if c.Status == control.TrustStatusConflict {
			if _, err := h.client.TrustImport(context.Background(), []string{c.Digest}); err != nil {
				t.Fatal(err)
			}
		}
	}

	report, err := h.client.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, f := range report.Findings {
		if f.Check == "host key trust" && strings.Contains(f.Detail, "pending") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("pending trust was not reported: %+v", report.Findings)
	}
}

func TestDoctorDetectsReorderedIdentities(t *testing.T) {
	h, findings := doctorFixture(t, "")
	if got := problems(findings); len(got) != 0 {
		t.Fatalf("unexpected problems before tampering: %v", got)
	}

	body, err := os.ReadFile(h.layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(body), "\n")
	var first, second int = -1, -1
	for i, line := range lines {
		if strings.Contains(line, "IdentityFile") {
			if first < 0 {
				first = i
			} else if second < 0 {
				second = i
			}
		}
	}
	if first < 0 || second < 0 {
		t.Fatalf("the generated config has fewer than two IdentityFile lines:\n%s", body)
	}
	lines[first], lines[second] = lines[second], lines[first]
	if err := os.WriteFile(h.layout.Config(), []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err = h.daemon.diagnose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, p := range problems(findings) {
		if strings.Contains(p, "managed identities") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("reordered identities were not reported:\n  %s",
			strings.Join(problems(findings), "\n  "))
	}
}

func TestDoctorDetectsAMissingManagedIdentity(t *testing.T) {
	h, _ := doctorFixture(t, "")
	body, err := os.ReadFile(h.layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	dropped := false
	for _, line := range strings.Split(string(body), "\n") {
		if !dropped && strings.Contains(line, "IdentityFile") {
			dropped = true
			continue
		}
		kept = append(kept, line)
	}
	if err := os.WriteFile(h.layout.Config(), []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := h.daemon.diagnose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, p := range problems(findings) {
		if strings.Contains(p, "managed identities") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("a dropped managed identity was not reported:\n  %s",
			strings.Join(problems(findings), "\n  "))
	}
}
