// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/sshconfig"
	"github.com/mouizahmed/sshstate/internal/sshkeys"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func runImport(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "import")
	dryRun := fs.Bool("dry-run", false, "report what would change and write nothing")
	withKeys := fs.Bool("with-keys", false, "also import the private keys the config's IdentityFile lines name")
	commentSource := fs.Bool("comment-source", false, "comment out the imported Host blocks in your own config, after backing it up")
	positional, rest := splitPositional(args, 1)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return usageError("import")
	}
	path := positional[0]
	if sameFile(path, env.Layout.UserSSHConfig) {
		path = env.Layout.UserSSHConfig
	}
	_, err := importConfig(ctx, env, path, importOptions{
		dryRun:        *dryRun,
		withKeys:      *withKeys,
		commentSource: *commentSource,
	})
	return err
}

type importOptions struct {
	dryRun         bool
	withKeys       bool
	commentSource  bool
	retiringSource bool
}

type importResult struct {
	imported  []sshconfig.ImportedHost
	conflicts []string
}

func importConfig(ctx context.Context, env *Env, path string, opts importOptions) (*importResult, error) {
	ownConfig := path == env.Layout.UserSSHConfig
	if opts.commentSource {
		if !ownConfig {
			return nil, fmt.Errorf("--comment-source only edits %s, and this import read %s", env.Layout.UserSSHConfig, path)
		}
		installed, err := sshconfig.IsInstalled(env.Layout)
		if err != nil {
			return nil, err
		}
		if !installed {
			return nil, errors.New("--comment-source needs the sshstate Include active first, or the hosts it comments out would stop resolving\nrun: sshstate install")
		}
	}
	body, err := readUserFile("SSH config", path)
	if err != nil {
		return nil, err
	}

	hosts, problems := sshconfig.ParseImport(string(body))
	if len(problems) > 0 {
		return nil, importRefusal(env, path, problems)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("%s declares no Host blocks", path)
	}

	if opts.withKeys && !opts.dryRun {
		if err := adoptIdentityFiles(ctx, env, hosts); err != nil {
			return nil, err
		}
	}
	keys, err := env.Client().Keys(ctx)
	if err != nil {
		return nil, env.hint(err)
	}
	byFingerprint := make(map[string]string, len(keys))
	for _, k := range keys {
		byFingerprint[k.Fingerprint] = k.RecordID
	}

	me, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("resolve the current user: %w", err)
	}

	req := control.ImportRequest{DryRun: opts.dryRun}
	var unresolved []sshconfig.ImportProblem
	missingKeys := map[string]string{}
	for _, h := range hosts {
		if err := vault.ValidateAlias(h.Alias); err != nil {
			unresolved = append(unresolved, sshconfig.ImportProblem{Line: h.Line, Text: err.Error()})
			continue
		}
		entry := control.AddHostRequest{
			Alias:     h.Alias,
			HostName:  h.HostName,
			User:      h.User,
			Port:      h.Port,
			ProxyJump: h.ProxyJump,
		}
		if entry.User == "" {
			entry.User = me.Username
		}
		for _, file := range h.IdentityFiles {
			fingerprint, err := identityFingerprint(file)
			if err != nil {
				unresolved = append(unresolved, sshconfig.ImportProblem{Line: h.Line,
					Text: fmt.Sprintf("host %q: IdentityFile %s: %v", h.Alias, file, err)})
				continue
			}
			id, ok := byFingerprint[fingerprint]
			if !ok {
				if opts.dryRun && opts.withKeys {
					missingKeys[file] = fingerprint
					continue
				}
				unresolved = append(unresolved, sshconfig.ImportProblem{Line: h.Line,
					Text: fmt.Sprintf("host %q: %s is not in the vault (%s)", h.Alias, fingerprint, file)})
				continue
			}
			entry.KeyIDs = append(entry.KeyIDs, id)
		}
		req.Hosts = append(req.Hosts, entry)
	}
	if len(unresolved) > 0 {
		if !opts.withKeys {
			env.warnf("Import those keys in the same pass with: sshstate import %s --with-keys\n\n", path)
		}
		return nil, importRefusal(env, path, unresolved)
	}

	res, err := env.Client().Import(ctx, req)
	if err != nil {
		return nil, env.hint(err)
	}
	result := &importResult{}

	for file, fingerprint := range missingKeys {
		env.printf("  key       %s  %s\n", fingerprint, file)
	}
	counts := map[string]int{}
	for _, o := range res.Outcomes {
		counts[o.Action]++
	}
	for _, o := range res.Outcomes {
		switch o.Action {
		case string(vault.ImportCreated):
			env.printf("  new       %s\n", o.Alias)
		case string(vault.ImportUnchanged):
			env.printf("  unchanged %s\n", o.Alias)
		case string(vault.ImportConflict):
			env.printf("  conflict  %s — %s\n", o.Alias, o.Detail)
			result.conflicts = append(result.conflicts, o.Alias)
		}
	}
	env.printf("\n%d new, %d unchanged, %d conflicting\n",
		counts[string(vault.ImportCreated)],
		counts[string(vault.ImportUnchanged)],
		counts[string(vault.ImportConflict)])
	retire := withoutAliases(hosts, result.conflicts)
	result.imported = retire
	if res.DryRun {
		if len(missingKeys) > 0 {
			env.printf("%s would be imported as well.\n", count(len(missingKeys), "key", "keys"))
		}
		if opts.commentSource {
			env.printf("%s in %s would be commented out.\n", count(len(retire), "block", "blocks"), path)
		}
		env.printf("\nNothing was written. Run it again without --dry-run to apply.\n")
		return result, nil
	}
	if counts[string(vault.ImportCreated)] > 0 {
		env.printf("\nConfig regenerated at %s\n", env.Layout.Config())
	}
	if counts[string(vault.ImportConflict)] > 0 {
		env.printf("Existing hosts were left as they are. See: sshstate conflicts\n")
	}
	if opts.commentSource {
		if len(result.conflicts) > 0 {
			env.printf("Left active in %s until you resolve them: %s\n", path, strings.Join(result.conflicts, ", "))
		}
		return result, commentOutSource(env, path, retire)
	}
	if ownConfig && !opts.retiringSource {
		warnStillDefined(env, path, hosts)
	}
	return result, nil
}

func withoutAliases(hosts []sshconfig.ImportedHost, aliases []string) []sshconfig.ImportedHost {
	var out []sshconfig.ImportedHost
	for _, h := range hosts {
		if !slices.Contains(aliases, h.Alias) {
			out = append(out, h)
		}
	}
	return out
}

func commentOutSource(env *Env, path string, hosts []sshconfig.ImportedHost) error {
	if len(hosts) == 0 {
		return nil
	}
	res, err := sshconfig.CommentOutBlocks(env.Layout, hosts)
	var symlink *sshconfig.SymlinkError
	if errors.As(err, &symlink) {
		aliases := make([]string, 0, len(hosts))
		for _, h := range hosts {
			aliases = append(aliases, h.Alias)
		}
		env.warnf("\n%s\nThese Host blocks are still active in %s: %s\n", err, symlink.Target, strings.Join(aliases, ", "))
		env.warnf("Comment them out there yourself so OpenSSH uses the definitions sshstate manages.\n")
		return nil
	}
	if err != nil {
		return err
	}
	env.printf("\nBacked up your SSH config to %s\n", res.BackupPath)
	env.printf("Commented out %s in %s: %s\n",
		count(len(res.Aliases), "block", "blocks"), path, strings.Join(res.Aliases, ", "))
	env.printf("Nothing was deleted. Check with: sshstate doctor\n")
	return nil
}

func warnStillDefined(env *Env, path string, hosts []sshconfig.ImportedHost) {
	var withKeys []string
	for _, h := range hosts {
		if len(h.IdentityFiles) > 0 {
			withKeys = append(withKeys, h.Alias)
		}
	}
	if len(withKeys) == 0 {
		return
	}
	env.warnf("\n%s still defined in %s with an IdentityFile: %s\n",
		plural(len(withKeys), "This host is", "These hosts are"), path, strings.Join(withKeys, ", "))
	env.warnf("OpenSSH reads both definitions and offers your own key file first, so the\n")
	env.warnf("vault's agent would not be what authenticates. Remove or comment those\n")
	env.warnf("blocks, then check with: sshstate doctor\n")
}

func importRefusal(env *Env, path string, problems []sshconfig.ImportProblem) error {
	sort.SliceStable(problems, func(i, j int) bool { return problems[i].Line < problems[j].Line })
	for _, p := range problems {
		env.warnf("%s:%d: %s\n", path, p.Line, p.Text)
	}
	env.warnf("\nNothing is imported while any line is refused. sshstate imports literal Host blocks\n")
	env.warnf("with HostName, User, Port, ProxyJump, and IdentityFile. To import the rest, copy the\n")
	env.warnf("Host blocks you want into their own file and import that file.\n")
	return fmt.Errorf("%s was not imported; %s", path, count(len(problems), "line needs attention", "lines need attention"))
}

func identityFingerprint(path string) (string, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return "", err
	}
	candidates := []string{expanded + ".pub", expanded}
	if strings.HasSuffix(expanded, ".pub") {
		candidates = []string{expanded}
	}
	for _, candidate := range candidates {
		body, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		digest, err := sshkeys.PublicKeyFingerprint(strings.TrimSpace(string(body)))
		if err != nil {
			continue
		}
		return digest, nil
	}
	return "", errors.New("no readable public key beside it")
}

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
}
