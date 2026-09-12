// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

var minimumVersions = map[string]string{
	"filippo.io/age":      "v1.3.2",
	"golang.org/x/crypto": "v0.52.0", // GO-2026-5018 and GO-2026-5033
}

func TestPinnedDependencyMinimums(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("build info unavailable")
	}
	seen := map[string]string{}
	for _, dep := range info.Deps {
		seen[dep.Path] = dep.Version
	}
	for path, want := range minimumVersions {
		got, ok := seen[path]
		if !ok {
			t.Errorf("%s is not in the build; decision record 0001 requires it", path)
			continue
		}
		if compareSemver(got, want) < 0 {
			t.Errorf("%s is %s, below the pinned minimum %s", path, got, want)
		}
	}
}

func compareSemver(a, b string) int {
	an, bn := parseSemver(a), parseSemver(b)
	for i := range an {
		if an[i] != bn[i] {
			if an[i] < bn[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return out
		}
		out[i] = n
	}
	return out
}
