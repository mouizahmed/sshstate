// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const (
	sevOK      = "ok"
	sevWarn    = "warn"
	sevProblem = "problem"
)

const effectiveConfigTimeout = 10 * time.Second

func (d *Daemon) handleDoctor(w http.ResponseWriter, r *http.Request) {
	findings, err := d.diagnose(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control.DoctorResponse{Findings: findings})
}

func (d *Daemon) diagnose(ctx context.Context) ([]control.DoctorFinding, error) {
	var out []control.DoctorFinding
	add := func(sev, check, detail, remedy string) {
		out = append(out, control.DoctorFinding{Severity: sev, Check: check, Detail: detail, Remedy: remedy})
	}

	installed, err := sshconfig.IsInstalled(d.layout)
	if err != nil {
		add(sevProblem, "ssh config include", err.Error(), "")
	} else if installed {
		add(sevOK, "ssh config include", "the managed Include is present in "+d.layout.UserSSHConfig, "")
	} else {
		add(sevWarn, "ssh config include", "the managed Include is not installed, so generated hosts are inert",
			"run: sshstate install")
	}

	d.checkPermissions(add)
	d.checkSystemTrustSources(add)
	d.checkMatchExec(add)

	hosts, err := d.mgr.Hosts()
	if errors.Is(err, vault.ErrLocked) {
		add(sevWarn, "effective configuration",
			"the vault is locked, so managed hosts could not be compared against ssh -G",
			"run: sshstate unlock")
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	d.checkPendingTrust(add)
	if len(hosts) == 0 {
		add(sevOK, "effective configuration", "no managed hosts to check", "")
		return out, nil
	}
	if !installed {
		add(sevWarn, "effective configuration",
			"skipped: the managed Include is not active yet", "run: sshstate install")
		return out, nil
	}
	expected := map[string][]string{}
	if rendered, err := d.renderable(); err != nil {
		add(sevProblem, "generated configuration", err.Error(), "run: sshstate generate")
	} else {
		for _, r := range rendered {
			paths := make([]string, 0, len(r.Identities))
			for _, id := range r.Identities {
				paths = append(paths, filepath.Join(d.layout.PublicDir(), r.PublicFileName(id)))
			}
			expected[r.Alias] = paths
		}
	}
	for _, h := range hosts {
		d.checkHost(ctx, h, expected[h.Alias], add)
	}
	return out, nil
}

func (d *Daemon) checkPermissions(add func(sev, check, detail, remedy string)) {
	type target struct {
		path string
		want os.FileMode
	}
	for _, t := range []target{
		{d.layout.Data, 0o700},
		{d.layout.SSH, 0o700},
		{d.layout.AgentSocket(), 0o600},
		{d.layout.ControlSocket(), 0o600},
	} {
		fi, err := os.Stat(t.path)
		if err != nil {
			continue
		}
		if got := fi.Mode().Perm(); got != t.want {
			add(sevProblem, "permissions",
				fmt.Sprintf("%s is mode %04o, expected %04o", t.path, got, t.want),
				fmt.Sprintf("run: chmod %04o %s", t.want, t.path))
		}
	}
}

func (d *Daemon) checkPendingTrust(add func(sev, check, detail, remedy string)) {
	views, err := d.mgr.KnownHosts()
	if err != nil {
		return
	}
	pending := 0
	for _, v := range views {
		if v.Status == vault.TrustPending {
			pending++
		}
	}
	if pending > 0 {
		add(sevWarn, "host key trust",
			fmt.Sprintf("%d host-key observation(s) are pending review and are not trusted", pending),
			"review them with: sshstate trust")
	}
}

func (d *Daemon) checkSystemTrustSources(add func(sev, check, detail, remedy string)) {
	for _, path := range []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"} {
		fi, err := os.Stat(path)
		if err != nil || fi.Size() == 0 {
			continue
		}
		add(sevWarn, "system host trust",
			path+" exists and still applies to managed hosts; sshstate does not manage it", "")
	}
}

func (d *Daemon) checkHost(ctx context.Context, h vault.HostView, wantIdentities []string, add func(sev, check, detail, remedy string)) {
	ctx, cancel := context.WithTimeout(ctx, effectiveConfigTimeout)
	defer cancel()

	args := append(append([]string{}, d.effectiveConfigArgs...), "-G", h.Alias)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	out, err := cmd.Output()
	if err != nil {
		add(sevProblem, "effective configuration",
			fmt.Sprintf("ssh -G %s failed: %v", h.Alias, err), "")
		return
	}
	effective := parseEffectiveConfig(string(out))

	want := map[string]string{
		"hostname":              strings.ToLower(h.HostName),
		"user":                  h.User,
		"port":                  fmt.Sprint(h.Port),
		"identitiesonly":        "yes",
		"forwardagent":          "no",
		"identityagent":         d.layout.AgentSocket(),
		"stricthostkeychecking": "ask",
		"updatehostkeys":        "false",
	}
	remedy := "a setting earlier in ~/.ssh/config is taking precedence; move the sshstate Include to the top"
	for key, expected := range want {
		got := effective[key]
		if len(got) == 0 {
			add(sevWarn, "effective configuration",
				fmt.Sprintf("host %q: ssh reported no value for %s", h.Alias, key), "")
			continue
		}
		if !strings.EqualFold(got[0], expected) {
			add(sevProblem, "effective configuration",
				fmt.Sprintf("host %q: %s is %q, the vault says %q", h.Alias, key, got[0], expected),
				remedy)
		}
	}

	jump := effective["proxyjump"]
	switch {
	case h.ProxyJump == nil && len(jump) > 0 && !strings.EqualFold(jump[0], "none"):
		add(sevProblem, "effective configuration",
			fmt.Sprintf("host %q: proxyjump is %q, the vault declares no jump host", h.Alias, jump[0]),
			remedy)
	case h.ProxyJump != nil && len(jump) == 0:
		add(sevProblem, "effective configuration",
			fmt.Sprintf("host %q: ssh resolves no proxyjump, the vault says %q", h.Alias, *h.ProxyJump),
			remedy)
	case h.ProxyJump != nil && !strings.EqualFold(jump[0], *h.ProxyJump):
		add(sevProblem, "effective configuration",
			fmt.Sprintf("host %q: proxyjump is %q, the vault says %q", h.Alias, jump[0], *h.ProxyJump),
			remedy)
	}

	wantFiles := []string{d.layout.CaptureFile(), d.layout.KnownHosts()}
	gotFiles := []string{}
	if files := effective["userknownhostsfile"]; len(files) > 0 {
		for _, f := range strings.Fields(files[0]) {
			gotFiles = append(gotFiles, expandTilde(f))
		}
	}
	if !slices.Equal(gotFiles, wantFiles) {
		add(sevProblem, "host key trust",
			fmt.Sprintf("host %q: UserKnownHostsFile is [%s], expected [%s]",
				h.Alias, strings.Join(gotFiles, " "), strings.Join(wantFiles, " ")),
			"managed host keys are read from the sshstate files; run: sshstate generate, "+
				"and check for an earlier UserKnownHostsFile in ~/.ssh/config")
	}

	var managed []string
	for _, path := range effective["identityfile"] {
		expanded := expandTilde(path)
		if strings.HasPrefix(expanded, d.layout.PublicDir()+string(filepath.Separator)) {
			managed = append(managed, expanded)
			continue
		}
		add(sevWarn, "accumulated identities",
			fmt.Sprintf("host %q also offers %s, which sshstate does not manage", h.Alias, path),
			"remove it from ~/.ssh/config, or accept that it is tried alongside managed keys")
	}
	if !slices.Equal(managed, wantIdentities) {
		add(sevProblem, "accumulated identities",
			fmt.Sprintf("host %q resolves managed identities [%s], the vault says [%s]",
				h.Alias, strings.Join(baseNames(managed), " "), strings.Join(baseNames(wantIdentities), " ")),
			"run: sshstate generate, and check for an earlier IdentityFile for this host in ~/.ssh/config")
	}
}

func baseNames(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, filepath.Base(p))
	}
	return out
}

func parseEffectiveConfig(out string) map[string][]string {
	result := map[string][]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		key = strings.ToLower(key)
		result[key] = append(result[key], value)
	}
	return result
}

func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

func (d *Daemon) checkMatchExec(add func(sev, check, detail, remedy string)) {
	body, err := os.ReadFile(d.layout.UserSSHConfig)
	if err != nil {
		return
	}
	for n, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "match") {
			continue
		}
		for _, f := range fields[1:] {
			if strings.EqualFold(f, "exec") {
				add(sevWarn, "effective configuration",
					fmt.Sprintf("%s:%d has a Match exec block, and doctor runs ssh -G, which evaluates it",
						d.layout.UserSSHConfig, n+1),
					"the command runs as you, on every doctor run and every ssh connection that matches")
				return
			}
		}
	}
}
