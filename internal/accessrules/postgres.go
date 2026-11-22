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
// hiding a direct keyword. Both interpretations must complete: a lexer limit
// is ours, not PostgreSQL's, and the server may execute that interpretation.
func PostgresOperations(sql []byte) ([]string, error) {
	if len(sql) > MaxStatementBytes || !utf8.Valid(sql) || bytes.IndexByte(sql, 0) >= 0 {
		return nil, ErrUninspectable
	}
	a, ea := postgresOperations(sql, false)
	b, eb := postgresOperations(sql, true)
	if ea != nil || eb != nil {
		return nil, ErrUninspectable
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
func pgDollarTag(c byte) bool { return pgWordStart(c) || pgDigit(c) }

// UnsupportedPostgresControl identifies SQL-level operations whose execution
// state can outlive one reviewed wire message. PREPARE/EXECUTE bypass the wire
// Parse/Bind digest; SET/RESET/DISCARD can change the session's SQL encoding.
// The guarded relay records a control decision for simple-query forms and
// refuses both simple-query and extended Parse forms.
func UnsupportedPostgresControl(operations []string) bool {
	for _, operation := range []string{"PREPARE", "EXECUTE", "SET", "RESET", "DISCARD"} {
		if slices.Contains(operations, operation) {
			return true
		}
	}
	return false
}

// UnsupportedPostgresControlStatement keeps the session-control fence while
// distinguishing a top-level SET command from UPDATE's required SET clause.
// Both PostgreSQL string-escape modes must parse cleanly, and either mode may
// reveal a control command. Other fenced keywords retain their broad refusal.
func UnsupportedPostgresControlStatement(sql []byte, operations []string) bool {
	if len(sql) > MaxStatementBytes || !utf8.Valid(sql) || bytes.IndexByte(sql, 0) >= 0 {
		return true
	}
	for _, operation := range []string{"PREPARE", "EXECUTE", "RESET", "DISCARD"} {
		if slices.Contains(operations, operation) {
			return true
		}
	}
	auditedLogSetting := PostgresAuditedLogSetting(sql, operations)
	for _, backslash := range []bool{false, true} {
		var tokens []sqlToken
		if err := sqlRiskTokens(sql, false, backslash, 0, &tokens); err != nil {
			return true
		}
		firstWord := ""
		for _, token := range tokens {
			if token.kind == 'p' && token.text == ";" {
				firstWord = ""
				continue
			}
			if token.kind != 'w' {
				continue
			}
			if firstWord == "" {
				firstWord = token.text
			}
			if token.text == "set" && firstWord != "update" && !auditedLogSetting {
				return true
			}
		}
	}
	return false
}

// PostgresAuditedLogSetting recognizes only one complete SET log_statement
// command. It may pass the control fence only when the gateway has a matching
// command rule; the independent gateway recording then remains authoritative
// even if PostgreSQL logging is disabled. Encoding and other SET commands stay
// inside the unconditional control fence.
func PostgresAuditedLogSetting(sql []byte, operations []string) bool {
	if !slices.Contains(operations, "SET") || !slices.Contains(operations, RiskAuditTampering) {
		return false
	}
	for _, backslash := range []bool{false, true} {
		var tokens []sqlToken
		if err := sqlRiskTokens(sql, false, backslash, 0, &tokens); err != nil {
			return false
		}
		if n := len(tokens); n > 0 && tokens[n-1].kind == 'p' && tokens[n-1].text == ";" {
			tokens = tokens[:n-1]
		}
		if len(tokens) != 4 {
			return false
		}
		assignment := tokens[2].kind == 'p' && tokens[2].text == "=" || tokens[2].kind == 'w' && tokens[2].text == "to"
		if tokens[0].kind != 'w' || tokens[0].text != "set" ||
			tokens[1].kind != 'w' || tokens[1].text != "log_statement" ||
			!assignment ||
			(tokens[3].kind != 'w' && tokens[3].kind != 's') {
			return false
		}
	}
	return true
}
