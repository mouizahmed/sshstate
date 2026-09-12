// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package buildinfo

import "fmt"

const (
	Copyright = "Copyright (C) 2026 Mouiz Ahmed"
	License   = "AGPL-3.0-only"
	SourceURL = "https://github.com/mouizahmed/sshstate"
)

func Notice() string {
	return fmt.Sprintf(`%s
License %s: GNU Affero General Public License v3.0 only.
This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you
are welcome to redistribute it under certain conditions; see the LICENSE file.
Source: %s`, Copyright, License, SourceURL)
}
