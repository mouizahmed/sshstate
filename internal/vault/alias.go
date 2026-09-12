// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package vault

import "fmt"

const MaxAliasLen = 64

func ValidateAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("alias is empty")
	}
	if len(alias) > MaxAliasLen {
		return fmt.Errorf("alias %q is %d characters, limit is %d", alias, len(alias), MaxAliasLen)
	}
	for i := 0; i < len(alias); i++ {
		c := alias[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
			if i == 0 {
				return fmt.Errorf("alias %q must start with a lowercase letter or digit", alias)
			}
		case c >= 'A' && c <= 'Z':
			return fmt.Errorf("alias %q contains uppercase; aliases are lowercase (try %q)", alias, lower(alias))
		default:
			return fmt.Errorf("alias %q contains %q; allowed are a-z, 0-9, dot, underscore, hyphen", alias, string(c))
		}
	}
	return nil
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
