// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package httpsig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Param struct {
	Name  string
	Value any
}

type SignatureParams struct {
	Components []string
	Params     []Param
}

func (p SignatureParams) Value() (string, error) {
	var b strings.Builder
	b.WriteByte('(')
	for i, c := range p.Components {
		if i > 0 {
			b.WriteByte(' ')
		}
		s, err := quoteString(c)
		if err != nil {
			return "", fmt.Errorf("component identifier: %w", err)
		}
		b.WriteString(s)
	}
	b.WriteByte(')')
	for _, param := range p.Params {
		if err := checkParamName(param.Name); err != nil {
			return "", err
		}
		b.WriteByte(';')
		b.WriteString(param.Name)
		b.WriteByte('=')
		switch v := param.Value.(type) {
		case string:
			s, err := quoteString(v)
			if err != nil {
				return "", fmt.Errorf("parameter %q: %w", param.Name, err)
			}
			b.WriteString(s)
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		default:
			return "", fmt.Errorf("parameter %q has unsupported type %T", param.Name, param.Value)
		}
	}
	return b.String(), nil
}

func (p SignatureParams) Param(name string) (any, bool) {
	for _, param := range p.Params {
		if param.Name == name {
			return param.Value, true
		}
	}
	return nil, false
}

func ParseSignatureParams(s string) (SignatureParams, error) {
	var out SignatureParams
	if !strings.HasPrefix(s, "(") {
		return out, errors.New("signature parameters must begin with an inner list")
	}
	end := strings.IndexByte(s, ')')
	if end < 0 {
		return out, errors.New("inner list is not closed")
	}
	inner := strings.TrimSpace(s[1:end])
	if inner != "" {
		rest := inner
		for rest != "" {
			item, remainder, err := parseQuotedString(rest)
			if err != nil {
				return out, fmt.Errorf("component identifier: %w", err)
			}
			out.Components = append(out.Components, item)
			rest = strings.TrimLeft(remainder, " ")
			if rest != "" && remainder == rest {
				return out, errors.New("inner list items must be separated by a single space")
			}
		}
	}

	rest := s[end+1:]
	for rest != "" {
		if rest[0] != ';' {
			return out, fmt.Errorf("expected a parameter, found %q", rest)
		}
		rest = rest[1:]
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return out, errors.New("parameter has no value")
		}
		name := rest[:eq]
		if err := checkParamName(name); err != nil {
			return out, err
		}
		rest = rest[eq+1:]
		if rest == "" {
			return out, fmt.Errorf("parameter %q has no value", name)
		}
		if rest[0] == '"' {
			value, remainder, err := parseQuotedString(rest)
			if err != nil {
				return out, fmt.Errorf("parameter %q: %w", name, err)
			}
			out.Params = append(out.Params, Param{Name: name, Value: value})
			rest = remainder
			continue
		}
		stop := strings.IndexByte(rest, ';')
		if stop < 0 {
			stop = len(rest)
		}
		digits := rest[:stop]
		n, err := strconv.ParseInt(digits, 10, 64)
		if err != nil || digits == "" {
			return out, fmt.Errorf("parameter %q is neither a quoted string nor an integer", name)
		}
		if strconv.FormatInt(n, 10) != digits {
			return out, fmt.Errorf("parameter %q is not a canonical integer", name)
		}
		out.Params = append(out.Params, Param{Name: name, Value: n})
		rest = rest[stop:]
	}
	return out, nil
}

func quoteString(s string) (string, error) {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return "", fmt.Errorf("%q contains a character that cannot appear in a structured-field string", s)
		}
		if c == '\\' || c == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String(), nil
}

func parseQuotedString(s string) (string, string, error) {
	if s == "" || s[0] != '"' {
		return "", "", errors.New("expected a quoted string")
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			i++
			if i >= len(s) {
				return "", "", errors.New("string ends with an escape")
			}
			if s[i] != '\\' && s[i] != '"' {
				return "", "", fmt.Errorf("invalid escape %q in string", s[i])
			}
			b.WriteByte(s[i])
		case c == '"':
			return b.String(), s[i+1:], nil
		case c < 0x20 || c >= 0x7f:
			return "", "", errors.New("string contains a character outside the allowed range")
		default:
			b.WriteByte(c)
		}
	}
	return "", "", errors.New("string is not closed")
}

func checkParamName(name string) error {
	if name == "" {
		return errors.New("parameter name is empty")
	}
	if !(name[0] >= 'a' && name[0] <= 'z') {
		return fmt.Errorf("parameter name %q must start with a lowercase letter", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
		default:
			return fmt.Errorf("parameter name %q contains %q", name, c)
		}
	}
	return nil
}

func ByteSequence(b []byte) string {
	return ":" + base64.StdEncoding.EncodeToString(b) + ":"
}

func ParseByteSequence(s string) ([]byte, error) {
	if len(s) < 2 || s[0] != ':' || s[len(s)-1] != ':' {
		return nil, errors.New("byte sequence must be wrapped in colons")
	}
	body := s[1 : len(s)-1]
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("byte sequence is not base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(raw) != body {
		return nil, errors.New("byte sequence is not canonical base64")
	}
	return raw, nil
}

func DictionaryMember(label, value string) string { return label + "=" + value }

func ParseDictionaryMember(header, expectLabel string) (string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", errors.New("field is empty")
	}
	prefix := expectLabel + "="
	if !strings.HasPrefix(header, prefix) {
		return "", fmt.Errorf("field is not a single member labelled %q", expectLabel)
	}
	value := header[len(prefix):]
	if value == "" {
		return "", errors.New("dictionary member has no value")
	}
	return value, nil
}
