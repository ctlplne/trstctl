// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// RewriteStoredEnvelopeDataExact replaces only the top-level stored event
// envelope's JSON data value. Every byte before and after that one token is
// copied verbatim, including unknown future fields, actor spelling, whitespace,
// and member order. History sanitation uses this instead of re-marshaling the
// envelope because a semantic round trip is not an exact-history proof.
func RewriteStoredEnvelopeDataExact(stored, beforeData, afterData []byte) ([]byte, error) {
	spans, err := storedEnvelopeMemberSpans(stored)
	if err != nil {
		return nil, err
	}
	span, ok := spans["data"]
	if !ok {
		return nil, errors.New("events: stored envelope has no data member")
	}
	start, end := span.start, span.end
	var decoded []byte
	if err := json.Unmarshal(stored[start:end], &decoded); err != nil {
		return nil, fmt.Errorf("events: decode stored envelope data token: %w", err)
	}
	if !bytes.Equal(decoded, beforeData) {
		return nil, errors.New("events: stored envelope data token does not match decoded source event")
	}
	replacement, err := json.Marshal(afterData)
	if err != nil {
		return nil, errors.New("events: encode replacement stored envelope data token")
	}
	rewritten := make([]byte, 0, len(stored))
	rewritten = append(rewritten, stored[:start]...)
	rewritten = append(rewritten, replacement...)
	rewritten = append(rewritten, stored[end:]...)
	if !json.Valid(rewritten) {
		return nil, errors.New("events: replacement produced an invalid stored envelope")
	}
	return rewritten, nil
}

// RewriteStoredEnvelopeExact replaces only the mutable top-level tokens of a
// stored event: data, actor, and schema version. Unknown future members,
// whitespace, member order, and every immutable envelope byte remain exact.
// A privacy rewrite can therefore move one registered application-secret
// command from v2 to its closed v3 disposition without re-marshaling the rest of
// the source-of-truth record.
func RewriteStoredEnvelopeExact(stored []byte, before, after storedEvent) ([]byte, error) {
	if before.ID != after.ID || before.Type != after.Type || before.TenantID != after.TenantID ||
		!before.Time.Equal(after.Time) {
		return nil, errors.New("events: exact stored-envelope rewrite changed immutable event fields")
	}
	spans, err := storedEnvelopeMemberSpans(stored)
	if err != nil {
		return nil, err
	}
	type replacement struct {
		start, end int
		value      []byte
	}
	replacements := make([]replacement, 0, 3)
	appendReplacement := func(member string, expected, next any) error {
		span, ok := spans[member]
		if !ok {
			return fmt.Errorf("events: stored envelope has no %s member", member)
		}
		var current any
		decoder := json.NewDecoder(bytes.NewReader(stored[span.start:span.end]))
		decoder.UseNumber()
		if err := decoder.Decode(&current); err != nil {
			return fmt.Errorf("events: decode stored envelope %s token: %w", member, err)
		}
		expectedRaw, err := json.Marshal(expected)
		if err != nil {
			return fmt.Errorf("events: encode expected stored envelope %s token: %w", member, err)
		}
		var expectedValue any
		expectedDecoder := json.NewDecoder(bytes.NewReader(expectedRaw))
		expectedDecoder.UseNumber()
		if err := expectedDecoder.Decode(&expectedValue); err != nil {
			return err
		}
		if !reflect.DeepEqual(current, expectedValue) {
			return fmt.Errorf("events: stored envelope %s token does not match decoded source event", member)
		}
		nextRaw, err := json.Marshal(next)
		if err != nil {
			return fmt.Errorf("events: encode replacement stored envelope %s token: %w", member, err)
		}
		replacements = append(replacements, replacement{start: span.start, end: span.end, value: nextRaw})
		return nil
	}

	if !bytes.Equal(before.Data, after.Data) {
		if err := appendReplacement("data", before.Data, after.Data); err != nil {
			return nil, err
		}
	}
	if !actorsEqual(before.Actor, after.Actor) {
		if err := appendReplacement("actor", before.Actor, after.Actor); err != nil {
			return nil, err
		}
	}
	beforeVersion := normalizedSchemaVersion(before.SchemaVersion)
	afterVersion := normalizedSchemaVersion(after.SchemaVersion)
	if beforeVersion != afterVersion {
		// Only v1 omits the member. Registered privacy dispositions start at v2,
		// so a schema-changing rewrite must replace an existing numeric token.
		if err := appendReplacement("v", beforeVersion, afterVersion); err != nil {
			return nil, err
		}
	}
	if len(replacements) == 0 {
		return append([]byte(nil), stored...), nil
	}
	for i := 0; i < len(replacements); i++ {
		for j := i + 1; j < len(replacements); j++ {
			if replacements[j].start > replacements[i].start {
				replacements[i], replacements[j] = replacements[j], replacements[i]
			}
		}
	}
	rewritten := append([]byte(nil), stored...)
	for _, item := range replacements {
		rewritten = append(rewritten[:item.start:item.start], append(item.value, rewritten[item.end:]...)...)
	}
	if !json.Valid(rewritten) {
		return nil, errors.New("events: exact stored-envelope replacement produced invalid JSON")
	}
	return rewritten, nil
}

type storedEnvelopeMemberSpan struct {
	start int
	end   int
}

func storedEnvelopeMemberSpans(stored []byte) (map[string]storedEnvelopeMemberSpan, error) {
	if !json.Valid(stored) {
		return nil, errors.New("events: stored envelope is not valid JSON")
	}
	i := skipJSONSpace(stored, 0)
	if i >= len(stored) || stored[i] != '{' {
		return nil, errors.New("events: stored envelope is not a JSON object")
	}
	i++
	spans := make(map[string]storedEnvelopeMemberSpan)
	for {
		i = skipJSONSpace(stored, i)
		if i >= len(stored) {
			return nil, errors.New("events: stored envelope ended before object close")
		}
		if stored[i] == '}' {
			break
		}
		keyStart := i
		keyEnd, err := jsonStringEnd(stored, keyStart)
		if err != nil {
			return nil, fmt.Errorf("events: locate stored envelope member: %w", err)
		}
		var key string
		if err := json.Unmarshal(stored[keyStart:keyEnd], &key); err != nil {
			return nil, fmt.Errorf("events: decode stored envelope member: %w", err)
		}
		i = skipJSONSpace(stored, keyEnd)
		if i >= len(stored) || stored[i] != ':' {
			return nil, errors.New("events: stored envelope member has no colon")
		}
		i = skipJSONSpace(stored, i+1)
		valueStart := i
		valueEnd, err := jsonValueEnd(stored, valueStart)
		if err != nil {
			return nil, fmt.Errorf("events: locate stored envelope member %q: %w", key, err)
		}
		if _, duplicate := spans[key]; duplicate {
			return nil, fmt.Errorf("events: stored envelope has duplicate %s members", key)
		}
		spans[key] = storedEnvelopeMemberSpan{start: valueStart, end: valueEnd}
		i = skipJSONSpace(stored, valueEnd)
		if i >= len(stored) {
			return nil, errors.New("events: stored envelope ended after member value")
		}
		switch stored[i] {
		case ',':
			i++
		case '}':
			return spans, nil
		default:
			return nil, errors.New("events: stored envelope member has no comma or object close")
		}
	}
	return spans, nil
}

func skipJSONSpace(raw []byte, at int) int {
	for at < len(raw) {
		switch raw[at] {
		case ' ', '\t', '\n', '\r':
			at++
		default:
			return at
		}
	}
	return at
}

func jsonStringEnd(raw []byte, start int) (int, error) {
	if start >= len(raw) || raw[start] != '"' {
		return 0, errors.New("JSON string does not start with a quote")
	}
	escaped := false
	for i := start + 1; i < len(raw); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch raw[i] {
		case '\\':
			escaped = true
		case '"':
			return i + 1, nil
		}
	}
	return 0, errors.New("unterminated JSON string")
}

func jsonValueEnd(raw []byte, start int) (int, error) {
	if start >= len(raw) {
		return 0, errors.New("missing JSON value")
	}
	if raw[start] == '"' {
		return jsonStringEnd(raw, start)
	}
	if raw[start] != '{' && raw[start] != '[' {
		i := start
		for i < len(raw) {
			switch raw[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				if i == start {
					return 0, errors.New("empty JSON value")
				}
				return i, nil
			default:
				i++
			}
		}
		return i, nil
	}

	stack := []byte{raw[start]}
	for i := start + 1; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			end, err := jsonStringEnd(raw, i)
			if err != nil {
				return 0, err
			}
			i = end - 1
		case '{', '[':
			stack = append(stack, raw[i])
		case '}', ']':
			open := stack[len(stack)-1]
			if (open == '{' && raw[i] != '}') || (open == '[' && raw[i] != ']') {
				return 0, errors.New("mismatched JSON container")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1, nil
			}
		}
	}
	return 0, errors.New("unterminated JSON container")
}
