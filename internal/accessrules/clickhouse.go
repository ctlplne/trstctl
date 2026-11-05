// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"unicode/utf8"
)

var clickhouseOperationNames = []string{"ALTER", "ATTACH", "BACKUP", "CHECK", "CREATE", "DELETE", "DESCRIBE", "DETACH", "DROP", "EXCHANGE", "EXISTS", "EXPLAIN", "GRANT", "INSERT", "KILL", "MOVE", "OPTIMIZE", "RENAME", "RESTORE", "REVOKE", "SELECT", "SET", "SHOW", "SYSTEM", "TRUNCATE", "UNDROP", "UPDATE", "USE", "WITH"}
var clickhouseClassifierNames = append(slices.Clone(clickhouseOperationNames), "FORMAT", "EXECUTE")

// ClickHouseOperations excludes values, identifiers and comments. It recognizes
// public SQL operation classes, not semantic equivalence or effects of functions.
func ClickHouseOperations(raw []byte) ([]string, error) {
	if len(raw) > MaxStatementBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrUninspectable
	}
	var seen [64]bool
	for i := 0; i < len(raw); {
		switch {
		case raw[i] == '-' && i+1 < len(raw) && raw[i+1] == '-' || raw[i] == '/' && i+1 < len(raw) && raw[i+1] == '/' || raw[i] == '#' && i+1 < len(raw) && (raw[i+1] == '!' || raw[i+1] == ' '):
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
		case raw[i] == '/' && i+1 < len(raw) && raw[i+1] == '*':
			i += 2
			depth := 1
			for i < len(raw) && depth > 0 {
				switch {
				case i+1 < len(raw) && raw[i] == '/' && raw[i+1] == '*':
					depth++
					i += 2
				case i+1 < len(raw) && raw[i] == '*' && raw[i+1] == '/':
					depth--
					i += 2
				default:
					i++
				}
				if depth > 64 {
					return nil, ErrUninspectable
				}
			}
			if depth != 0 {
				return nil, ErrUninspectable
			}
		case raw[i] == '\'' || raw[i] == '"' || raw[i] == '`':
			next, ok := pgQuotedEnd(raw, i+1, raw[i], true)
			if !ok {
				return nil, ErrUninspectable
			}
			i = next
		case raw[i] == '$':
			end := i + 1
			for end < len(raw) && end-i <= 256 && pgDollarTag(raw[end]) {
				end++
			}
			if end < len(raw) && raw[end] == '$' && (end == i+1 || !pgDigit(raw[i+1])) {
				delimiter := raw[i : end+1]
				n := bytes.Index(raw[end+1:], delimiter)
				if n < 0 {
					return nil, ErrUninspectable
				}
				i = end + 1 + n + len(delimiter)
			} else {
				if end-i > 256 {
					return nil, ErrUninspectable
				}
				i++
			}
		case pgWordStart(raw[i]):
			start := i
			i++
			for i < len(raw) && pgWord(raw[i]) {
				i++
			}
			if i-start <= 32 {
				var word [32]byte
				for n, c := range raw[start:i] {
					if c >= 'a' && c <= 'z' {
						c -= 'a' - 'A'
					}
					word[n] = c
				}
				for n, name := range clickhouseClassifierNames {
					if bytes.Equal(word[:i-start], []byte(name)) {
						seen[n] = true
						break
					}
				}
			}
		default:
			i++
		}
	}
	out := []string{}
	for i, name := range clickhouseClassifierNames {
		if seen[i] {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Encoded data after FORMAT is not SQL. EXECUTE AS could change the identity.
func UnsupportedClickHouseControl(ops []string) bool {
	return slices.Contains(ops, "FORMAT") || slices.Contains(ops, "EXECUTE")
}
