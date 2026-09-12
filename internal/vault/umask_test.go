// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package vault

import "syscall"

func syscallUmask(mask int) int { return syscall.Umask(mask) }
