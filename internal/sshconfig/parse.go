// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package sshconfig

import (
	"fmt"
	"strconv"
	"strings"
)

type ImportedHost struct {
	Line          int
	EndLine       int
	Alias         string
	HostName      string
	User          string
	Port          int
	ProxyJump     *string
	IdentityFiles []string
}

type ImportProblem struct {
	Line int
	Text string
}

func (p ImportProblem) String() string { return fmt.Sprintf("line %d: %s", p.Line, p.Text) }

var supportedInHost = map[string]bool{
	"hostname":     true,
	"user":         true,
	"port":         true,
	"proxyjump":    true,
	"identityfile": true,
}

var executableDirectives = map[string]string{
	"proxycommand":       "runs a command",
	"localcommand":       "runs a command",
	"permitlocalcommand": "enables running commands",
	"remotecommand":      "runs a command",
	"knownhostscommand":  "runs a command",
	"match":              "can run commands through `match exec`",
}

var certificateDirectives = map[string]bool{
	"certificatefile":   true,
	"hostcertificate":   true,
	"hostbasedkeytypes": true,
}

func ParseImport(text string) ([]ImportedHost, []ImportProblem) {
	var hosts []ImportedHost
	var problems []ImportProblem
	var current *ImportedHost
	seenAlias := map[string]int{}
	set := map[string]int{}

	fail := func(line int, format string, args ...any) {
		problems = append(problems, ImportProblem{Line: line, Text: fmt.Sprintf(format, args...)})
	}
	lastContent := 0
	closeBlock := func() {
		if current != nil {
			current.EndLine = lastContent
			hosts = append(hosts, *current)
			current = nil
		}
	}

	managed := false
	for n, raw := range strings.Split(text, "\n") {
		line := n + 1
		switch strings.TrimSpace(raw) {
		case MarkerBegin:
			managed = true
			continue
		case MarkerEnd:
			managed = false
			continue
		}
		if managed {
			continue
		}
		keyword, args, err := splitDirective(raw)
		if err != nil {
			fail(line, "%s", err)
			continue
		}
		if keyword == "" {
			continue
		}
		lowered := strings.ToLower(keyword)

		if lowered == "host" {
			closeBlock()
			set = map[string]int{}
			alias, err := hostPattern(args)
			if err != nil {
				fail(line, "%s", err)
				continue
			}
			if first, dup := seenAlias[strings.ToLower(alias)]; dup {
				fail(line, "host %q is already defined on line %d", alias, first)
				continue
			}
			seenAlias[strings.ToLower(alias)] = line
			current = &ImportedHost{Line: line, EndLine: line, Alias: alias}
			continue
		}

		if why, bad := executableDirectives[lowered]; bad {
			fail(line, "%s is not imported because it %s", keyword, why)
			continue
		}
		if certificateDirectives[lowered] {
			fail(line, "%s is not imported; certificates are not in the v1 subset", keyword)
			continue
		}
		if lowered == "include" {
			fail(line, "Include is not imported; prepare a single file with the hosts you want")
			continue
		}
		if !supportedInHost[lowered] {
			fail(line, "%s is not in the v1 import subset", keyword)
			continue
		}
		if current == nil {
			fail(line, "%s appears before any Host block", keyword)
			continue
		}
		lastContent = line
		if lowered != "identityfile" {
			if first, dup := set[lowered]; dup {
				fail(line, "%s is set twice for host %q; it was already set on line %d", keyword, current.Alias, first)
				continue
			}
			set[lowered] = line
		}
		if len(args) != 1 && lowered != "identityfile" {
			fail(line, "%s takes one value, got %d", keyword, len(args))
			continue
		}

		switch lowered {
		case "hostname":
			current.HostName = args[0]
		case "user":
			current.User = args[0]
		case "port":
			port, err := strconv.Atoi(args[0])
			if err != nil || port < 1 || port > 65535 {
				fail(line, "Port %q is not a number between 1 and 65535", args[0])
				continue
			}
			current.Port = port
		case "proxyjump":
			jump, err := proxyJump(args)
			if err != nil {
				fail(line, "%s", err)
				continue
			}
			current.ProxyJump = jump
		case "identityfile":
			if len(args) != 1 {
				fail(line, "IdentityFile takes one path, got %d", len(args))
				continue
			}
			current.IdentityFiles = append(current.IdentityFiles, args[0])
		}
	}
	closeBlock()

	for i := range hosts {
		if hosts[i].HostName == "" {
			hosts[i].HostName = hosts[i].Alias
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return hosts, nil
}

func hostPattern(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("Host names no alias")
	}
	if len(args) > 1 {
		return "", fmt.Errorf("Host %s declares %d patterns; the v1 subset is one literal alias per block", strings.Join(args, " "), len(args))
	}
	alias := args[0]
	if alias == "" {
		return "", fmt.Errorf("Host names an empty alias")
	}
	if strings.ContainsAny(alias, "*?") {
		return "", fmt.Errorf("Host %q is a wildcard pattern; the v1 subset is one literal alias", alias)
	}
	if strings.HasPrefix(alias, "!") {
		return "", fmt.Errorf("Host %q is a negated pattern; the v1 subset is one literal alias", alias)
	}
	return alias, nil
}

func proxyJump(args []string) (*string, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("ProxyJump takes one alias, got %d", len(args))
	}
	value := args[0]
	if strings.EqualFold(value, "none") {
		return nil, nil
	}
	if strings.ContainsAny(value, ",") {
		return nil, fmt.Errorf("ProxyJump %q chains several hosts; the v1 subset is one alias", value)
	}
	if strings.ContainsAny(value, "@:") {
		return nil, fmt.Errorf("ProxyJump %q carries a user or port; name a managed alias instead", value)
	}
	if strings.ContainsAny(value, "*?!") {
		return nil, fmt.Errorf("ProxyJump %q is a pattern; name one managed alias", value)
	}
	return &value, nil
}

func splitDirective(raw string) (string, []string, error) {
	tokens, err := tokenize(raw)
	if err != nil {
		return "", nil, err
	}
	if len(tokens) == 0 {
		return "", nil, nil
	}
	keyword := tokens[0]
	args := tokens[1:]
	if i := strings.IndexByte(keyword, '='); i >= 0 {
		rest := keyword[i+1:]
		keyword = keyword[:i]
		if rest != "" {
			args = append([]string{rest}, args...)
		}
	} else if len(args) > 0 {
		if args[0] == "=" {
			args = args[1:]
		} else if strings.HasPrefix(args[0], "=") {
			args[0] = strings.TrimPrefix(args[0], "=")
		}
	}
	if keyword == "" {
		return "", nil, fmt.Errorf("directive begins with %q", "=")
	}
	return keyword, args, nil
}

func tokenize(raw string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	quoted, started := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '"':
			quoted = !quoted
			started = true
		case c == '#' && !quoted:
			if started {
				tokens = append(tokens, cur.String())
			}
			return tokens, nil
		case (c == ' ' || c == '\t' || c == '\r') && !quoted:
			if started {
				tokens = append(tokens, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if quoted {
		return nil, fmt.Errorf("unbalanced quote")
	}
	if started {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}
