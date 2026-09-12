// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package activation

import "os"

func listenerFiles(string) ([]*os.File, error) { return nil, nil }

func available() bool { return false }
