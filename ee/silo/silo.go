// SPDX-License-Identifier: LicenseRef-trstctl-EE

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

// SubjectLane is a tenant's JetStream subject lane. It is keyed on the tenant
// ID — the unique, immutable identity — with the slug carried only as a
// readable prefix.
//
// It MUST be keyed on the ID, not the slug alone, because the slug is
// operator-supplied free text with no charset validation, and identifierPart
// normalizes it lossily: "acme-corp", "acme_corp" and "acme.corp" all collapse
// to "acme-corp". Two distinct tenants with those slugs would then share ONE
// event lane — a cross-tenant isolation breach, one customer's events landing
// in another's stream. SchemaName and ObjectPrefix already key on the ID for
// exactly this reason; the lane was the odd one out, and an isolation guarantee
// that holds for storage and object keys but not for the event stream is not an
// isolation guarantee. The ID suffix makes distinct tenants produce distinct
// lanes however their slugs normalize.
func SubjectLane(tenantID, slug string) string {
	id := identifierPart(strings.ReplaceAll(tenantID, "-", ""), "-")
	if id == "" {
		id = "tenant"
	}
	if slugPart := identifierPart(slug, "-"); slugPart != "" {
		return "t-" + slugPart + "-" + id
	}
	return "t-" + id
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
