// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package knownhosts

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	xknownhosts "golang.org/x/crypto/ssh/knownhosts"
)

const MaxFileBytes = 8 << 20

const (
	MarkerRevoked       = "@revoked"
	MarkerCertAuthority = "@cert-authority"
)

type Entry struct {
	Line        string
	LineNo      int
	Marker      string
	Patterns    []string
	Hashed      bool
	KeyType     string
	Fingerprint string
	Key         ssh.PublicKey
	Digest      [sha256.Size]byte
}

type Problem struct {
	LineNo int
	Reason string
}

func (p Problem) String() string { return fmt.Sprintf("line %d: %s", p.LineNo, p.Reason) }

func ParseFile(path string) ([]Entry, []Problem, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if fi.Size() > MaxFileBytes {
		return nil, nil, fmt.Errorf("%s is %d bytes, which exceeds the %d-byte limit", path, fi.Size(), MaxFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, nil, fmt.Errorf("%s exceeds the %d-byte limit", path, MaxFileBytes)
	}
	entries, problems := Parse(string(data))
	return entries, problems, nil
}

func Parse(text string) ([]Entry, []Problem) {
	var entries []Entry
	var problems []Problem
	for i, raw := range strings.Split(text, "\n") {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		e, err := ParseLine(line)
		if err != nil {
			problems = append(problems, Problem{LineNo: lineNo, Reason: err.Error()})
			continue
		}
		e.LineNo = lineNo
		entries = append(entries, e)
	}
	return entries, problems
}

func ParseLine(line string) (Entry, error) {
	marker, hosts, key, _, _, err := ssh.ParseKnownHosts([]byte(line))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Entry{}, errors.New("not a known_hosts entry")
		}
		return Entry{}, err
	}
	if len(hosts) == 0 {
		return Entry{}, errors.New("entry names no host")
	}
	e := Entry{
		Line:        line,
		Patterns:    hosts,
		KeyType:     key.Type(),
		Fingerprint: ssh.FingerprintSHA256(key),
		Key:         key,
		Digest:      LineDigest(line),
	}
	if marker != "" {
		e.Marker = "@" + marker
	}
	switch e.Marker {
	case "", MarkerRevoked, MarkerCertAuthority:
	default:
		return Entry{}, fmt.Errorf("unknown marker %q", e.Marker)
	}
	e.Hashed = len(hosts) == 1 && strings.HasPrefix(hosts[0], "|1|")
	return e, nil
}

func LineDigest(line string) [sha256.Size]byte {
	return sha256.Sum256([]byte(strings.Join(strings.Fields(line), " ")))
}

func Destination(hostname string, port int) string {
	if port == 0 {
		port = 22
	}
	return xknownhosts.Normalize(fmt.Sprintf("%s:%d", hostname, port))
}

func (e Entry) Matches(dest string) bool {
	if e.Hashed {
		return e.matchesHashed(dest)
	}
	matched := false
	for _, p := range e.Patterns {
		negated := strings.HasPrefix(p, "!")
		pattern := strings.TrimPrefix(p, "!")
		if !matchPattern(pattern, dest) {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

func (e Entry) matchesHashed(dest string) bool {
	parts := strings.Split(e.Patterns[0], "|")
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(dest))
	return hmac.Equal(mac.Sum(nil), want)
}

func matchPattern(pattern, s string) bool {
	return globMatch(strings.ToLower(pattern), strings.ToLower(s))
}

func globMatch(pattern, s string) bool {
	for {
		if pattern == "" {
			return s == ""
		}
		switch pattern[0] {
		case '*':
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatch(pattern, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			pattern, s = pattern[1:], s[1:]
		default:
			if s == "" || s[0] != pattern[0] {
				return false
			}
			pattern, s = pattern[1:], s[1:]
		}
	}
}
