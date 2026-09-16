// SPDX-License-Identifier: MPL-2.0

package upsertarbiter

import (
	"regexp"
	"strings"
)

var (
	reSingleValues = regexp.MustCompile(`(?is)^\s*INSERT\s+INTO\s+"?\w+"?\s*\(([^)]*)\)\s+VALUES\s*\((.*)\)\s+ON\s+CONFLICT\b`)
	reColumnName   = regexp.MustCompile(`^(?:[a-zA-Z_][a-zA-Z_0-9]*|"[a-zA-Z_][a-zA-Z_0-9]*")$`)
	reFreshUUID    = regexp.MustCompile(`(?i)^gen_random_uuid\s*\(\s*\)$`)
	reUpdateSet    = regexp.MustCompile(`(?is)\bDO\s+UPDATE\s+SET\s+`)
	reAssignedCol  = regexp.MustCompile(`(?is)(?:^|,)\s*"?(\w+)"?\s*=`)
	reTupleSet     = regexp.MustCompile(`(?is)(?:^|,)\s*\(`)
)

// freshInsertColumns recognizes only a single VALUES row with an explicit
// PostgreSQL UUID generator. Two identical natural-key inserts then have
// independent secondary keys: ON CONFLICT still handles their shared arbiter.
// This is not a general uniqueness proof or a blanket exemption for UUID
// columns. Bound IDs, defaults, SELECT, fallback expressions, multiple rows,
// and any subsequent assignment to that column remain unproved.
func freshInsertColumns(sql string) map[string]bool {
	m := reSingleValues.FindStringSubmatchIndex(sql)
	if m == nil {
		return nil
	}
	columns, ok := splitSQLTerms(sql[m[2]:m[3]])
	if !ok {
		return nil
	}
	values, ok := splitSQLTerms(sql[m[4]:m[5]])
	if !ok || len(columns) != len(values) {
		return nil
	}
	fresh := map[string]bool{}
	for i, column := range columns {
		if !reColumnName.MatchString(column) {
			return nil
		}
		if reFreshUUID.MatchString(values[i]) {
			fresh[strings.ToLower(strings.Trim(column, `"`))] = true
		}
	}
	tail := sql[m[1]:]
	if update := reUpdateSet.FindStringIndex(tail); update != nil {
		assignments := tail[update[1]:]
		// Tuple SET syntax needs a fuller parser; keep that statement subject
		// to the normal lock/retry rule instead of guessing column ownership.
		if reTupleSet.MatchString(assignments) {
			return nil
		}
		for _, assignment := range reAssignedCol.FindAllStringSubmatch(assignments, -1) {
			delete(fresh, strings.ToLower(assignment[1]))
		}
	}
	return fresh
}

// splitSQLTerms preserves quoted strings and nested expressions. Unsupported
// quoting/comments fail closed; a misleading comma must never move a generated
// UUID expression onto a different column in the analysis.
func splitSQLTerms(sql string) ([]string, bool) {
	var terms []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(sql); i++ {
		ch := sql[i]
		if quote != 0 {
			if ch == '\\' {
				return nil, false
			}
			if ch == quote {
				if i+1 < len(sql) && sql[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, false
			}
		case ',':
			if depth == 0 {
				terms = append(terms, strings.TrimSpace(sql[start:i]))
				start = i + 1
			}
		case '-', '/':
			if i+1 < len(sql) && ((ch == '-' && sql[i+1] == '-') || (ch == '/' && sql[i+1] == '*')) {
				return nil, false
			}
		case '$':
			// Numeric bind parameters are supported; dollar-quoted SQL is not.
			if i+1 == len(sql) || sql[i+1] < '0' || sql[i+1] > '9' {
				return nil, false
			}
		}
	}
	if depth != 0 || quote != 0 {
		return nil, false
	}
	terms = append(terms, strings.TrimSpace(sql[start:]))
	return terms, true
}

func hasFreshColumn(columns colset, fresh map[string]bool) bool {
	for _, column := range columns {
		if fresh[column] {
			return true
		}
	}
	return false
}
