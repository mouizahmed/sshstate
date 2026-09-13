// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package httpsig

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"
)

const (
	ComponentMethod    = "@method"
	ComponentAuthority = "@authority"
	ComponentPath      = "@path"
	ComponentQuery     = "@query"

	ComponentSignatureParams = "@signature-params"
)

type Message struct {
	Method    string
	Authority string
	Path      string
	Query     string
	HasQuery  bool
	Fields    http.Header
}

func FromRequest(r *http.Request, https bool) (*Message, error) {
	if r == nil || r.URL == nil {
		return nil, errors.New("request has no URL")
	}
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	if authority == "" {
		return nil, errors.New("request has no authority")
	}
	m := &Message{
		Method:    strings.ToUpper(r.Method),
		Authority: normalizeAuthority(authority, https),
		Path:      r.URL.EscapedPath(),
		Query:     r.URL.RawQuery,
		HasQuery:  r.URL.ForceQuery || r.URL.RawQuery != "",
		Fields:    r.Header,
	}
	if m.Path == "" {
		m.Path = "/"
	}
	return m, nil
}

func normalizeAuthority(authority string, https bool) string {
	authority = strings.ToLower(strings.TrimSpace(authority))
	defaultPort := ":80"
	if https {
		defaultPort = ":443"
	}
	if i := strings.LastIndexByte(authority, ':'); i > strings.LastIndexByte(authority, ']') {
		if authority[i:] == defaultPort {
			return authority[:i]
		}
	}
	return authority
}

func Base(m *Message, params SignatureParams) (string, error) {
	if m == nil {
		return "", errors.New("no message")
	}
	seen := make(map[string]bool, len(params.Components))
	var b strings.Builder
	for _, c := range params.Components {
		if seen[c] {
			return "", fmt.Errorf("component %q is covered twice", c)
		}
		seen[c] = true
		value, err := componentValue(m, c)
		if err != nil {
			return "", err
		}
		id, err := quoteString(c)
		if err != nil {
			return "", err
		}
		b.WriteString(id)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	value, err := params.Value()
	if err != nil {
		return "", err
	}
	b.WriteString(`"` + ComponentSignatureParams + `": `)
	b.WriteString(value)
	return b.String(), nil
}

func componentValue(m *Message, c string) (string, error) {
	if strings.HasPrefix(c, "@") {
		switch c {
		case ComponentMethod:
			return m.Method, nil
		case ComponentAuthority:
			return m.Authority, nil
		case ComponentPath:
			return m.Path, nil
		case ComponentQuery:
			return "?" + m.Query, nil
		case ComponentSignatureParams:
			return "", errors.New("@signature-params is added last and must not be listed as a covered component")
		default:
			return "", fmt.Errorf("derived component %q is not implemented", c)
		}
	}
	if c != strings.ToLower(c) {
		return "", fmt.Errorf("field component %q must be lowercase", c)
	}
	value, ok := fieldValue(m.Fields, c)
	if !ok {
		return "", fmt.Errorf("covered field %q is not present in the message", c)
	}
	return value, nil
}

func fieldValue(h http.Header, name string) (string, bool) {
	if h == nil {
		return "", false
	}
	values := h.Values(textproto.CanonicalMIMEHeaderKey(name))
	if len(values) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.ReplaceAll(v, "\r\n", " ")
		v = strings.ReplaceAll(v, "\n", " ")
		v = strings.ReplaceAll(v, "\r", " ")
		parts = append(parts, strings.TrimSpace(v))
	}
	return strings.Join(parts, ", "), true
}
