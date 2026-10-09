// Package profile provides strict, bounded decoding of secret-free VPN profiles.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// maxProfileBytes bounds all input, including whitespace, to 64 KiB.
// Decode reads one extra byte solely to distinguish oversized input from exact-limit input.
const maxProfileBytes = 64 * 1024

// objectFields lists exact JSON field spellings for every schema object.
// Token validation supplements DisallowUnknownFields, which otherwise accepts case aliases.
var objectFields = map[string]map[string]bool{
	"$": {"schema_version": true, "id": true, "name": true, "backend": true, "gateway": true,
		"realm": true, "username": true, "trusted_cert": true, "mfa": true, "routes": true, "dns": true},
	"$.gateway": {"host": true, "port": true},
	"$.mfa":     {"mode": true, "digits": true, "period": true, "algorithm": true},
	"$.routes":  {"mode": true, "include": true, "exclude": true, "preserve_lan": true},
	"$.dns":     {"mode": true, "domains": true},
}

// Decode reads at most 64 KiB from r and returns a defaulted, validated profile.
// It returns nil and an error for read failures, malformed or ambiguous JSON, or invalid fields.
func Decode(r io.Reader) (*Profile, error) {
	if r == nil {
		return nil, errors.New("profile: reader must not be nil")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxProfileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	if len(data) > maxProfileBytes {
		return nil, errors.New("profile: exceeds 64 KiB limit")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("profile: invalid UTF-8")
	}
	// Walk tokens first: struct decoding alone silently accepts duplicate object keys.
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	start, err := check.Token()
	if err != nil {
		return nil, fmt.Errorf("decode profile: %w", err)
	}
	if start != json.Delim('{') {
		return nil, errors.New("profile: top level must be an object")
	}
	if err := walkObject(check, "$"); err != nil {
		return nil, err
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("profile: trailing data after object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var p Profile
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode profile: %w", err)
	}
	p.ApplyDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// walkObject consumes an already-opened object and checks exact keys at path.
// It returns syntax, unknown-field, or duplicate-key errors at any nesting depth.
func walkObject(decoder *json.Decoder, path string) error {
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("%s: expected object key", path)
		}
		if seen[key] {
			return fmt.Errorf("%s.%s: duplicate key", path, key)
		}
		seen[key] = true
		if fields, known := objectFields[path]; known && !fields[key] {
			return fmt.Errorf("%s: unknown field %q", path, key)
		}
		if err := walkValue(decoder, path+"."+key); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// walkValue consumes one value at path, recursively checking objects and arrays.
// It rejects null because the schema has no nullable fields and propagates syntax errors.
func walkValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if token == nil {
		return fmt.Errorf("%s: null is not allowed", path)
	}
	switch token {
	case json.Delim('{'):
		return walkObject(decoder, path)
	case json.Delim('['):
		for i := 0; decoder.More(); i++ {
			if err := walkValue(decoder, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}
