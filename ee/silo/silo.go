// Package silo implements Provider-tier per-tenant physical isolation targets.
package silo

import (
	"strings"
	"unicode"
)

func SchemaName(tenantID string) string {
	clean := identifierPart(strings.ReplaceAll(tenantID, "-", ""), "_")
	if clean == "" {
		clean = "tenant"
	}
	out := "t_" + clean
	if len(out) > 63 {
		return out[:63]
	}
	return out
}

func SubjectLane(slug string) string {
	clean := identifierPart(slug, "-")
	if clean == "" {
		clean = "tenant"
	}
	return "t-" + clean
}

func ObjectPrefix(tenantID string) string {
	return "silo/" + strings.ToLower(strings.Trim(tenantID, "/")) + "/"
}

func identifierPart(raw, sep string) string {
	var b strings.Builder
	lastSep := false
	for _, r := range strings.ToLower(raw) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastSep = false
		case r == '-' || r == '_' || r == '.':
			if !lastSep {
				b.WriteString(sep)
				lastSep = true
			}
		}
	}
	return strings.Trim(b.String(), sep)
}
