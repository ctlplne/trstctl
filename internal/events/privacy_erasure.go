// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/privacyref"
)

// PseudonymizeSubject replaces exact occurrences of an erased subject in stored
// event payloads and actor subjects with the tenant-bound erasure placeholder. It
// uses the same generation switch, frozen cutover, continuity receipt, and secure
// source scrub as RewriteTenantData; it never deletes and republishes the active
// stream in place.
//
// This is intentionally narrow: it is the storage-level companion to the
// privacy.subject.erased event. Cold archives and backups created before this
// rewrite need their own operator retention/deletion process, documented under
// privacy retention. The proof options are mandatory. The variadic form keeps
// existing callers source-compatible while making unwired callers fail closed
// before any history mutation.
func (l *Log) PseudonymizeSubject(
	ctx context.Context,
	tenantID, subject string,
	options ...TenantDataRewriteOption,
) error {
	return l.PseudonymizeSubjectWithCompletion(ctx, tenantID, subject, nil, options...)
}

// PseudonymizeSubjectWithCompletion performs the generation rewrite and then
// invokes completion before releasing the same deployment-wide rewrite-operation
// lock. The completion callback runs after the cutover lock has been released, so
// it may use normal history reads/append/projection paths without inverting the
// operation -> cutover -> backup lock order. This narrow seam lets the served
// erasure command re-check durable state and append its deterministic completion
// event without another replica starting the same long-window rewrite in between.
func (l *Log) PseudonymizeSubjectWithCompletion(
	ctx context.Context,
	tenantID, subject string,
	completion func(context.Context) error,
	options ...TenantDataRewriteOption,
) error {
	if tenantID == "" {
		return errors.New("events: subject pseudonymization requires tenant_id (AN-1)")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return errors.New("events: subject pseudonymization requires subject")
	}

	if err := ValidateTenantDataRewriteOptions(options...); err != nil {
		return fmt.Errorf("events: subject pseudonymization proof wall: %w", err)
	}
	if err := l.HistoryRewriteReady(); err != nil {
		return fmt.Errorf("events: subject pseudonymization readiness: %w", err)
	}
	opts := parseTenantDataRewriteOptions(options)

	transform := func(before storedEvent) (storedEvent, bool, error) {
		if before.TenantID != tenantID {
			return before, false, nil
		}
		after := cloneStoredEvent(before)
		if !pseudonymizeStoredSubject(&after, subject) {
			return before, false, nil
		}
		return after, true, nil
	}
	validate := func(before, after storedEvent) error {
		if before.TenantID != tenantID {
			return errors.New("subject pseudonymization changed a non-target tenant")
		}
		expected := cloneStoredEvent(before)
		if !pseudonymizeStoredSubject(&expected, subject) {
			return errors.New("subject pseudonymization changed an event without the erased subject")
		}
		expectedCanonical, err := json.Marshal(expected)
		if err != nil {
			return fmt.Errorf("encode expected pseudonymized event: %w", err)
		}
		afterCanonical, err := json.Marshal(after)
		if err != nil {
			return fmt.Errorf("encode actual pseudonymized event: %w", err)
		}
		if !bytes.Equal(expectedCanonical, afterCanonical) {
			return errors.New("subject pseudonymization changed fields outside the exact actor/data replacement")
		}
		return nil
	}

	return l.withRewriteOperation(ctx, func(ctx context.Context) error {
		_, err := l.rewriteStoredGeneration(ctx, tenantID, transform, validate, opts)
		if err != nil {
			return err
		}
		if completion != nil {
			if err := completion(ctx); err != nil {
				return fmt.Errorf("events: subject pseudonymization completion: %w", err)
			}
		}
		return nil
	})
}

func cloneStoredEvent(event storedEvent) storedEvent {
	clone := event
	clone.Data = append([]byte(nil), event.Data...)
	if event.Actor != nil {
		actor := *event.Actor
		actor.Roles = append([]string(nil), event.Actor.Roles...)
		clone.Actor = &actor
	}
	return clone
}

func pseudonymizeStoredSubject(s *storedEvent, subject string) bool {
	ref := privacyref.SubjectRef(s.TenantID, subject)
	placeholder := privacyref.Placeholder(ref)
	var changed bool
	if s.Actor != nil {
		actor := *s.Actor
		if next := strings.ReplaceAll(actor.Subject, subject, placeholder); next != actor.Subject {
			actor.Subject = next
			s.Actor = &actor
			changed = true
		}
	}
	if len(s.Data) > 0 {
		if next, ok := pseudonymizeDataBytes(s.Data, subject, placeholder); ok {
			s.Data = next
			changed = true
		}
	}
	return changed
}

func pseudonymizeDataBytes(data []byte, subject, placeholder string) ([]byte, bool) {
	if json.Valid(data) {
		next, changed, err := pseudonymizeJSONStringValues(data, subject, placeholder)
		if err == nil {
			return next, changed
		}
	}
	next := bytes.ReplaceAll(data, []byte(subject), []byte(placeholder))
	return next, !bytes.Equal(next, data)
}

// pseudonymizeJSONStringValues rewrites semantic JSON strings, including object
// keys because dynamic keys can carry subject PII. It copies every byte outside
// the matched subject spans verbatim, so object ordering, whitespace, and even
// unrelated escapes in a changed token do not move. json.Valid is checked by the
// caller before this scanner runs.
func pseudonymizeJSONStringValues(data []byte, subject, placeholder string) ([]byte, bool, error) {
	var (
		out     []byte
		last    int
		changed bool
	)
	for cursor := 0; cursor < len(data); {
		if data[cursor] != '"' {
			cursor++
			continue
		}

		start := cursor
		cursor++
		for cursor < len(data) {
			switch data[cursor] {
			case '\\':
				cursor += 2
			case '"':
				cursor++
				goto stringComplete
			default:
				cursor++
			}
		}
		return nil, false, errors.New("unterminated JSON string")

	stringComplete:
		end := cursor
		rewritten, tokenChanged, err := pseudonymizeJSONStringToken(data[start:end], subject, placeholder)
		if err != nil {
			return nil, false, err
		}
		if !tokenChanged {
			continue
		}
		out = append(out, data[last:start]...)
		out = append(out, rewritten...)
		last = end
		changed = true
	}
	if !changed {
		return data, false, nil
	}
	out = append(out, data[last:]...)
	return out, true, nil
}

func pseudonymizeJSONStringToken(token []byte, subject, placeholder string) ([]byte, bool, error) {
	if subject == "" {
		return token, false, nil
	}
	decoded, rawBoundary, err := decodeJSONStringTokenSpans(token)
	if err != nil {
		return nil, false, err
	}

	type rawMatch struct {
		start int
		end   int
	}
	var matches []rawMatch
	for search := 0; search < len(decoded); {
		relative := strings.Index(decoded[search:], subject)
		if relative < 0 {
			break
		}
		semanticStart := search + relative
		semanticEnd := semanticStart + len(subject)
		rawStart, startOK := rawBoundary[semanticStart]
		rawEnd, endOK := rawBoundary[semanticEnd]
		if !startOK || !endOK {
			return nil, false, errors.New("subject match splits a JSON Unicode character")
		}
		matches = append(matches, rawMatch{start: rawStart, end: rawEnd})
		search = semanticEnd
	}
	if len(matches) == 0 {
		return token, false, nil
	}

	encodedPlaceholder, err := json.Marshal(placeholder)
	if err != nil {
		return nil, false, fmt.Errorf("encode subject placeholder: %w", err)
	}
	encodedPlaceholder = encodedPlaceholder[1 : len(encodedPlaceholder)-1]

	out := make([]byte, 0, len(token))
	rawCursor := 0
	for _, match := range matches {
		out = append(out, token[rawCursor:match.start]...)
		out = append(out, encodedPlaceholder...)
		rawCursor = match.end
	}
	out = append(out, token[rawCursor:]...)
	return out, true, nil
}

// decodeJSONStringTokenSpans decodes a valid quoted JSON string and records
// which raw offsets surround each complete decoded Unicode character. The map
// lets the caller replace a semantic substring without normalizing unrelated
// escapes elsewhere in the same token.
func decodeJSONStringTokenSpans(token []byte) (string, map[int]int, error) {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return "", nil, errors.New("JSON string token is not quoted")
	}

	decoded := make([]byte, 0, len(token)-2)
	rawBoundary := map[int]int{0: 1}
	for rawCursor := 1; rawCursor < len(token)-1; {
		rawStart := rawCursor
		var semantic rune
		if token[rawCursor] != '\\' {
			var rawSize int
			semantic, rawSize = utf8.DecodeRune(token[rawCursor : len(token)-1])
			rawCursor += rawSize
		} else {
			if rawCursor+1 >= len(token)-1 {
				return "", nil, errors.New("truncated JSON escape")
			}
			switch token[rawCursor+1] {
			case '"', '\\', '/':
				semantic = rune(token[rawCursor+1])
				rawCursor += 2
			case 'b':
				semantic = '\b'
				rawCursor += 2
			case 'f':
				semantic = '\f'
				rawCursor += 2
			case 'n':
				semantic = '\n'
				rawCursor += 2
			case 'r':
				semantic = '\r'
				rawCursor += 2
			case 't':
				semantic = '\t'
				rawCursor += 2
			case 'u':
				first, ok := decodeJSONHexQuad(token[rawCursor+2:])
				if !ok {
					return "", nil, errors.New("invalid JSON Unicode escape")
				}
				semantic = rune(first)
				rawCursor += 6
				if 0xD800 <= first && first <= 0xDBFF &&
					rawCursor+6 <= len(token)-1 &&
					token[rawCursor] == '\\' && token[rawCursor+1] == 'u' {
					second, secondOK := decodeJSONHexQuad(token[rawCursor+2:])
					if secondOK && 0xDC00 <= second && second <= 0xDFFF {
						semantic = utf16.DecodeRune(rune(first), rune(second))
						rawCursor += 6
					}
				}
				if utf16.IsSurrogate(semantic) {
					semantic = utf8.RuneError
				}
			default:
				return "", nil, errors.New("invalid JSON escape")
			}
		}

		semanticStart := len(decoded)
		decoded = utf8.AppendRune(decoded, semantic)
		rawBoundary[semanticStart] = rawStart
		rawBoundary[len(decoded)] = rawCursor
	}
	return string(decoded), rawBoundary, nil
}

func decodeJSONHexQuad(encoded []byte) (uint16, bool) {
	if len(encoded) < 4 {
		return 0, false
	}
	var value uint16
	for _, digit := range encoded[:4] {
		value <<= 4
		switch {
		case '0' <= digit && digit <= '9':
			value |= uint16(digit - '0')
		case 'a' <= digit && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case 'A' <= digit && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
