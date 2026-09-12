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
	if len(hosts) == 0 {
		add(sevOK, "effective configuration", "no managed hosts to check", "")
		return out, nil
	}
	if !installed {
		add(sevWarn, "effective configuration",
			"skipped: the managed Include is not active yet", "run: sshstate install")
		return out, nil
	}
	for _, h := range hosts {
		d.checkHost(ctx, h, add)
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

func (d *Daemon) checkHost(ctx context.Context, h vault.HostView, add func(sev, check, detail, remedy string)) {
	ctx, cancel := context.WithTimeout(ctx, effectiveConfigTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", "-G", h.Alias)
	out, err := cmd.Output()
	if err != nil {
		add(sevProblem, "effective configuration",
			fmt.Sprintf("ssh -G %s failed: %v", h.Alias, err), "")
		return
	}
	effective := parseEffectiveConfig(string(out))

	want := map[string]string{
		"hostname":       strings.ToLower(h.HostName),
		"user":           h.User,
		"port":           fmt.Sprint(h.Port),
		"identitiesonly": "yes",
		"forwardagent":   "no",
		"updatehostkeys": "no",
		"identityagent":  d.layout.AgentSocket(),
	}
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
				"a setting earlier in ~/.ssh/config is taking precedence; move the sshstate Include to the top")
		}
	}

	managed := map[string]bool{}
	for _, path := range effective["identityfile"] {
		expanded := expandTilde(path)
		if strings.HasPrefix(expanded, d.layout.PublicDir()+string(filepath.Separator)) {
			managed[expanded] = true
			continue
		}
		add(sevWarn, "accumulated identities",
			fmt.Sprintf("host %q also offers %s, which sshstate does not manage", h.Alias, path),
			"remove it from ~/.ssh/config, or accept that it is tried alongside managed keys")
	}
	if len(managed) != len(h.KeyIDs) {
		add(sevProblem, "accumulated identities",
			fmt.Sprintf("host %q resolves %d managed identity files, the vault lists %d keys",
				h.Alias, len(managed), len(h.KeyIDs)),
			"run: sshstate generate")
	}
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
