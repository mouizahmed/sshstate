// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package service

import "github.com/mouizahmed/sshstate/internal/paths"

const Label = "io.github.mouizahmed.sshstate"

type Manager interface {
	Name() string
	DefinitionPath() string
	Install(binary string, l paths.Layout) error
	Uninstall(l paths.Layout) error
	Registered() (bool, error)
	Installed(l paths.Layout) (bool, error)
}

func For() Manager { return platformManager() }
