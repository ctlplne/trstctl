// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"unicode/utf8"
)

var mysqlClassifierNames = append(slices.Clone(mysqlOperationNames), "PREPARE", "EXECUTE", "DEALLOCATE", "LOAD")

// MySQLOperations inspects both ordinary-string escape modes and executable
// version comments. It keeps only public operation classes, never quoted values.
// Stored programs and dynamically constructed SQL remain lexical bypasses.
func MySQLOperations(raw []byte) ([]string, error) {
	if len(raw) > MaxStatementBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrUninspectable
	}
	var a, b [64]bool
	ea := mysqlOperations(raw, false, 0, &a)
	eb := mysqlOperations(raw, true, 0, &b)
	if ea != nil && eb != nil {
		return nil, ErrUninspectable
	}
	out := []string{}
	for i, name := range mysqlClassifierNames {
		if ea == nil && a[i] || eb == nil && b[i] {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}

func mysqlOperations(raw []byte, backslash bool, depth int, seen *[64]bool) error {
	if depth > 8 {
		return ErrUninspectable
	}
	for i := 0; i < len(raw); {
		switch {
		case raw[i] == '#' || raw[i] == '-' && i+2 < len(raw) && raw[i+1] == '-' && raw[i+2] <= 32:
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
		case raw[i] == '/' && i+1 < len(raw) && raw[i+1] == '*':
			start := i + 2
			end := bytes.Index(raw[start:], []byte("*/"))
			if end < 0 {
				return ErrUninspectable
			}
			end += start
			if start < end && raw[start] == '!' {
				start++
				for start < end && raw[start] >= '0' && raw[start] <= '9' {
					start++
				}
				if err := mysqlOperations(raw[start:end], backslash, depth+1, seen); err != nil {
					return err
				}
			}
			i = end + 2
		case raw[i] == '\'' || raw[i] == '"' || raw[i] == '`':
			quote := raw[i]
			i++
			closed := false
			for i < len(raw) {
				if raw[i] == quote {
					i++
					if i < len(raw) && raw[i] == quote {
						i++
						continue
					}
					closed = true
					break
				}
				if backslash && quote != '`' && raw[i] == '\\' {
					i++
					if i >= len(raw) {
						return ErrUninspectable
					}
				}
				i++
			}
			if !closed {
				return ErrUninspectable
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
				for n, name := range mysqlClassifierNames {
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
	return nil
}

func UnsupportedMySQLControl(ops []string) bool {
	for _, op := range ops {
		if op == "PREPARE" || op == "EXECUTE" || op == "DEALLOCATE" || op == "LOAD" {
			return true
		}
	}
	return false
}
