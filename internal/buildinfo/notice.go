package buildinfo

import "fmt"

const (
	Copyright = "Copyright (C) 2026 Mouiz Ahmed"
	License   = "MIT"
	SourceURL = "https://github.com/mouizahmed/sshstate"
)

func Notice() string {
	return fmt.Sprintf(`%s
License: %s. See the LICENSE file for terms and warranty disclaimer.
Source: %s`, Copyright, License, SourceURL)
}
