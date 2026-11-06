// SPDX-License-Identifier: BUSL-1.1
package bearerhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// DecodeJSON rejects duplicate/case-alias keys, excessive nesting and trailing
// objects before decoding selected public fields. Raw scratch stays byte-backed.
func DecodeJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxResponse {
		return errors.New("invalid bounded metadata JSON")
	}
	budget := 8 << 20
	if err := validateObject(raw, 0, &budget); err != nil {
		return err
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("invalid typed metadata JSON")
	}
	return nil
}
func validateObject(raw []byte, depth int, budget *int) error {
	*budget -= len(raw)
	if depth > 32 || *budget < 0 {
		return errors.New("metadata JSON complexity exceeds bound")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return errors.New("empty metadata JSON value")
	}
	if raw[0] != '{' && raw[0] != '[' {
		if !json.Valid(raw) {
			return errors.New("invalid metadata JSON value")
		}
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil {
		return errors.New("invalid metadata JSON container")
	}
	seen := map[string]bool{}
	count := 0
	for d.More() {
		count++
		if count > 20000 {
			return errors.New("metadata JSON item bound exceeded")
		}
		if start == json.Delim('{') {
			token, err := d.Token()
			key, ok := token.(string)
			if err != nil || !ok || len(key) > 256 {
				return errors.New("invalid metadata JSON field")
			}
			fold := strings.ToLower(key)
			if seen[fold] {
				return errors.New("duplicate or ambiguous metadata JSON field")
			}
			seen[fold] = true
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return errors.New("invalid metadata JSON item")
		}
		err = validateObject(value, depth+1, budget)
		secret.Wipe(value)
		if err != nil {
			return err
		}
	}
	end, err := d.Token()
	expected := json.Delim('}')
	if start == json.Delim('[') {
		expected = json.Delim(']')
	}
	if err != nil || end != expected || len(bytes.TrimSpace(raw[d.InputOffset():])) != 0 {
		return errors.New("invalid metadata JSON framing")
	}
	return nil
}
