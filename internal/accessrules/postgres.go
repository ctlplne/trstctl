// SPDX-License-Identifier: BUSL-1.1

package accessrules

import (
	"bytes"
	"errors"
	"slices"
	"unicode/utf8"
)

var ErrUninspectable = errors.New("command rules: statement framing cannot be inspected safely")

// PostgresOperations returns known keywords outside values, quoted identifiers,
// dollar-quoted bodies and comments. It is a lexical guardrail, not a SQL parser
// or containment boundary: a stored program can execute hidden dynamic SQL.
// Considering both ordinary-string escape modes prevents a setting change from
// hiding a direct keyword. A malformed interpretation cannot execute upstream;
// when both interpretations fail, the guarded relay refuses the statement.
func PostgresOperations(sql []byte) ([]string, error) {
	if len(sql) > MaxStatementBytes || !utf8.Valid(sql) || bytes.IndexByte(sql, 0) >= 0 {
		return nil, ErrUninspectable
	}
	a, ea := postgresOperations(sql, false)
	b, eb := postgresOperations(sql, true)
	if ea != nil && eb != nil {
		return nil, ErrUninspectable
	}
	if ea != nil {
		a = nil
	}
	if eb != nil {
		b = nil
	}
	out := append(a, b...)
	slices.Sort(out)
	return slices.Compact(out), nil
}

func postgresOperations(sql []byte, backslash bool) ([]string, error) {
	var out []string
	var seen [32]bool
	for i := 0; i < len(sql); {
		switch {
		case sql[i] == '-' && i+1 < len(sql) && sql[i+1] == '-':
			i += 2
			for i < len(sql) && sql[i] != '\n' && sql[i] != '\r' {
				i++
			}
		case sql[i] == '/' && i+1 < len(sql) && sql[i+1] == '*':
			i += 2
			depth := 1
			for i < len(sql) && depth > 0 {
				switch {
				case i+1 < len(sql) && sql[i] == '/' && sql[i+1] == '*':
					depth++
					i += 2
				case i+1 < len(sql) && sql[i] == '*' && sql[i+1] == '/':
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
		case sql[i] == '\'' || sql[i] == '"':
			quote := sql[i]
			escaped := backslash && quote == '\''
			if quote == '\'' && i > 0 && (sql[i-1] == 'e' || sql[i-1] == 'E') && (i == 1 || !pgWord(sql[i-2])) {
				escaped = true
			}
			next, ok := pgQuotedEnd(sql, i+1, quote, escaped)
			if !ok {
				return nil, ErrUninspectable
			}
			i = next
		case sql[i] == '$':
			end := i + 1
			for end < len(sql) && end-i <= 256 && pgDollarTag(sql[end]) {
				end++
			}
			if end < len(sql) && sql[end] == '$' && (end == i+1 || !pgDigit(sql[i+1])) {
				delimiter := sql[i : end+1]
				n := bytes.Index(sql[end+1:], delimiter)
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
		case pgWordStart(sql[i]):
			start := i
			i++
			for i < len(sql) && pgWord(sql[i]) {
				i++
			}
			if i-start <= 32 {
				var word [32]byte
				ascii := true
				for j, c := range sql[start:i] {
					if c >= 128 {
						ascii = false
						break
					}
					if c >= 'a' && c <= 'z' {
						c -= 'a' - 'A'
					}
					word[j] = c
				}
				if ascii {
					index := postgresOperationIndex(string(word[:i-start]))
					if index >= 0 && !seen[index] {
						seen[index] = true
						out = append(out, postgresOperationNames[index])
					}
				}
			}
		default:
			i++
		}
	}
	return out, nil
}

func pgQuotedEnd(sql []byte, i int, quote byte, escaped bool) (int, bool) {
	for i < len(sql) {
		if escaped && sql[i] == '\\' {
			if i+1 >= len(sql) {
				return 0, false
			}
			i += 2
			continue
		}
		if sql[i] == quote {
			if i+1 < len(sql) && sql[i+1] == quote {
				i += 2
				continue
			}
			return i + 1, true
		}
		i++
	}
	return 0, false
}
func pgDigit(c byte) bool { return c >= '0' && c <= '9' }
func pgWordStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 128
}
func pgWord(c byte) bool      { return pgWordStart(c) || pgDigit(c) || c == '$' }
func pgDollarTag(c byte) bool { return pgWordStart(c) && c < 128 || pgDigit(c) }

// UnsupportedPostgresControl identifies direct SQL-level prepared execution.
// The guarded relay tracks the wire Parse/Bind/Execute protocol; it cannot bind
// an SQL EXECUTE to a reviewed wire statement. It refuses these direct forms.
func UnsupportedPostgresControl(operations []string) bool {
	return slices.Contains(operations, "PREPARE") || slices.Contains(operations, "EXECUTE")
}
