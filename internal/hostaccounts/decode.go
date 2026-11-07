// SPDX-License-Identifier: BUSL-1.1
package hostaccounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

// DecodeInventoryReport rejects unknown fields and duplicate keys, including
// case/escape aliases, before accepting the signed native metadata.
func DecodeInventoryReport(raw []byte) (InventoryReport, error) {
	var value InventoryReport
	err := decodeInventoryJSON(raw, MaxInventoryReportBytes, &value)
	return value, err
}
func DecodeInventoryIntent(raw []byte) (InventoryIntent, error) {
	var value InventoryIntent
	if err := decodeInventoryJSON(raw, 16<<10, &value); err != nil {
		return value, err
	}
	return value, value.Validate()
}
func decodeInventoryJSON(raw []byte, limit int, out any) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || !validJSONSurrogates(raw) {
		return errors.New("host accounts: bounded JSON required")
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	tokens.UseNumber()
	count := 0
	if err := uniqueJSONValue(tokens, 0, &count); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return errors.New("host accounts: trailing data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("host accounts: invalid fields")
	}
	return nil
}
func uniqueJSONValue(decoder *json.Decoder, depth int, count *int) error {
	*count++
	if depth > 16 || *count > 200000 {
		return errors.New("host accounts: JSON structure exceeds bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("host accounts: malformed report JSON")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return errors.New("host accounts: malformed object key")
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("host accounts: invalid object key")
			}
			// Every field in this closed schema is ASCII snake_case. Refuse
			// case/Unicode aliases rather than rely on encoding/json's fold.
			for _, r := range name {
				if r != '_' && (r < 'a' || r > 'z') {
					return errors.New("host accounts: exact field spelling required")
				}
			}
			if seen[name] {
				return errors.New("host accounts: duplicate report field")
			}
			seen[name] = true
			if err := uniqueJSONValue(decoder, depth+1, count); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return errors.New("host accounts: incomplete object")
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSONValue(decoder, depth+1, count); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return errors.New("host accounts: incomplete array")
		}
	default:
		return errors.New("host accounts: unexpected JSON delimiter")
	}
	return nil
}

// encoding/json replaces unpaired UTF-16 escapes. Native identity must retain
// exact Unicode, so reject those escapes before decoding string values.
func validJSONSurrogates(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return false
		}
		if raw[i+1] != 'u' {
			i++
			continue
		}
		if i+6 > len(raw) {
			return false
		}
		unit, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
		if err != nil {
			return false
		}
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 11
		case unit >= 0xdc00 && unit <= 0xdfff:
			return false
		default:
			i += 5
		}
	}
	return true
}
