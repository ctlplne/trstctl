// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
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
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("service dependents: bounded JSON required")
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	tokens.UseNumber()
	count := 0
	if err := uniqueJSONValue(tokens, 0, &count); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return errors.New("service dependents: trailing data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("service dependents: invalid fields")
	}
	return nil
}
func uniqueJSONValue(decoder *json.Decoder, depth int, count *int) error {
	*count++
	if depth > 16 || *count > 200000 {
		return errors.New("service dependents: JSON structure exceeds bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("service dependents: malformed report JSON")
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
				return errors.New("service dependents: malformed object key")
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("service dependents: invalid object key")
			}
			normalized := strings.ToLower(name)
			if seen[normalized] {
				return errors.New("service dependents: duplicate report field")
			}
			seen[normalized] = true
			if err := uniqueJSONValue(decoder, depth+1, count); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return errors.New("service dependents: incomplete object")
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSONValue(decoder, depth+1, count); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return errors.New("service dependents: incomplete array")
		}
	default:
		return errors.New("service dependents: unexpected JSON delimiter")
	}
	return nil
}
