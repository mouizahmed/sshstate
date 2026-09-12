// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/gowebpki/jcs"
)

const MaxObjectBytes = 1 << 20

type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("binary field must be a base64url string: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("binary field is not unpadded base64url: %w", err)
	}
	*b = raw
	return nil
}

type Counter uint64

func (c Counter) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatUint(uint64(c), 10) + `"`), nil
}

func (c *Counter) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("counter must be a decimal string: %w", err)
	}
	if s == "" {
		return errors.New("counter is empty")
	}
	if len(s) > 1 && s[0] == '0' {
		return fmt.Errorf("counter %q has a leading zero", s)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return fmt.Errorf("counter %q is not decimal", s)
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("counter %q out of range: %w", s, err)
	}
	*c = Counter(v)
	return nil
}

func (c Counter) String() string { return strconv.FormatUint(uint64(c), 10) }

func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonical: transform: %w", err)
	}
	return out, nil
}

func StrictUnmarshal(data []byte, v any) error {
	if len(data) > MaxObjectBytes {
		return fmt.Errorf("object is %d bytes, limit is %d", len(data), MaxObjectBytes)
	}
	if err := checkNoDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func checkNoDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return checkValue(dec, "")
}

func checkValue(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return checkObject(dec, path)
	case '[':
		return checkArray(dec, path)
	}
	return fmt.Errorf("unexpected delimiter %q", delim)
}

func checkObject(dec *json.Decoder, path string) error {
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("object key is not a string at %q", path)
		}
		here := key
		if path != "" {
			here = path + "." + key
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON key %q", here)
		}
		seen[key] = true
		if err := checkValue(dec, here); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing '}'
	return err
}

func checkArray(dec *json.Decoder, path string) error {
	for dec.More() {
		if err := checkValue(dec, path); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing ']'
	return err
}
