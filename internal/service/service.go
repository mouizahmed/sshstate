// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"os"
	"sort"

	"github.com/mouizahmed/sshstate/internal/paths"
)

const Label = "io.github.mouizahmed.sshstate"

var passedEnvironment = []string{
	"SSL_CERT_FILE", "SSL_CERT_DIR",
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
	"ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
}

func Environment() map[string]string {
	env := map[string]string{}
	for _, name := range passedEnvironment {
		if value, ok := os.LookupEnv(name); ok && value != "" {
			env[name] = value
		}
	}
	return env
}

func sortedNames(env map[string]string) []string {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type Manager interface {
	Name() string
	DefinitionPath() string
	Install(binary string, l paths.Layout) error
	Uninstall(l paths.Layout) error
	Registered() (bool, error)
	Installed(l paths.Layout) (bool, error)
}

func For() Manager { return platformManager() }
