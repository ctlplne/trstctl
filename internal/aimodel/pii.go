package aimodel

import (
	"regexp"
	"strings"
)

// PRIVACY-005: the boundary redactor (DefaultRedactor) is a secret/key shield, and
// it DELIBERATELY preserves personal/identifying data — dotted hostnames, owner
// identifiers, certificate subjects — because they carry no high entropy and are
// useful context for an in-house RCA. But when an OPTIONAL cloud model is
// configured, that same personal data egresses to a third party: an owner's email,
// a workload's SPIFFE ID, a federated OIDC subject, a raw IP, a certificate's CN.
// This file adds a SECOND, PII-aware egress boundary that is default-private:
// unless an operator explicitly consents in config (AllowPII), emails, IPs,
// OIDC/SPIFFE subjects, FQDN hostnames, and obvious person names are redacted (or,
// in Block mode, the send is refused) BEFORE any prompt reaches a cloud model.
//
// Posture: default-private. The zero-value PIIPolicy redacts. Cloud egress of
// personal data is therefore an explicit, inspectable choice (config AllowPII),
// never a silent default — mirroring the AN-8 "nothing phones home unless you said
// so" stance the secret boundary already takes.

// PIIPolicy controls how personal/identifying data is handled before model egress.
// The zero value is the safe default: redact PII (AllowPII=false), do not block the
// whole send (Block=false). This package never persists or logs the raw matched
// values; it only rewrites the prompt string in place.
type PIIPolicy struct {
	// AllowPII, when true, preserves personal/identifying data in the prompt: an
	// operator has consented (in config) to send it to the configured model. The
	// default (false) redacts PII so a cloud model never receives it.
	AllowPII bool
	// Block, when true, refuses the entire send if any PII is detected rather than
	// egressing a partially-redacted prompt. The default (false) redacts in place
	// and proceeds. Block has no effect when AllowPII is true.
	Block bool
}

// piiActive reports whether the policy redacts/blocks PII (i.e. not consented).
func (p PIIPolicy) piiActive() bool { return !p.AllowPII }

var (
	// Email addresses. Local-part and domain are intentionally permissive; the
	// domain must have a dotted TLD so a bare "user@host" word is still caught but
	// ordinary "@mention" prose without a dot is not.
	piiEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

	// SPIFFE workload identities (spiffe://trust-domain/path). Caught before the
	// generic URL/hostname sweeps so the whole SPIFFE ID is labeled as such.
	piiSPIFFE = regexp.MustCompile(`(?i)\bspiffe://[a-z0-9.\-]+(?:/[^\s]*)?`)

	// HTTP(S) URLs used as OIDC issuer/subject identifiers (and any other URL that
	// would carry a host + path of identifying value).
	piiURL = regexp.MustCompile(`(?i)\bhttps?://[a-z0-9.\-]+(?::\d+)?(?:/[^\s]*)?`)

	// IPv4 dotted-quad. The octet bound (0-255) keeps it from matching an arbitrary
	// four-group dotted number that is really a version string.
	piiIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)

	// IPv6, including the :: compressed form. Requires at least one colon-group run
	// with a hex group so a single "::" or a lone word does not match.
	piiIPv6 = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:`)

	// FQDN hostnames: at least two dot-separated labels ending in a non-numeric TLD
	// (so an IPv4 already handled above is excluded). This catches certificate
	// subjects/SANs like svc-api.payments.prod.internal and graph node names that
	// are hostnames. It is the last network-identifier sweep.
	piiFQDN = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,}\b`)

	// Person names: two or more consecutive Capitalized words (First Last, First
	// Middle Last). This is heuristic by nature; it is gated behind a stop-list of
	// product/technical TitleCase phrases (issuing CA names, state words, headers)
	// so ordinary trstctl vocabulary is not mangled. Over-redaction of a real
	// person's name is the safe failure mode here.
	piiPersonName = regexp.MustCompile(`\b([A-Z][a-z]+)(?: [A-Z][a-z]+){1,2}\b`)
)

// piiNameStoplist is the set of capitalized multi-word phrases that look like a
// person name to the heuristic but are product/technical vocabulary an RCA prompt
// legitimately contains. Matching is case-insensitive on the whole phrase.
var piiNameStoplist = map[string]struct{}{
	"issuing ca":      {},
	"root ca":         {},
	"intermediate ca": {},
	"not before":      {},
	"not after":       {},
	"access denied":   {},
	"blast radius":    {},
	"control plane":   {},
	"signing service": {},
	"event log":       {},
}

// PIIRedactor returns a Redactor that, when the policy redacts PII, strips
// personal/identifying data (emails, SPIFFE/OIDC subjects, URLs, IPv4/IPv6, FQDN
// hostnames, and person names) from a prompt, replacing each with a descriptive
// [REDACTED-*] marker. When the policy consents to PII (AllowPII=true) it is the
// identity function. Patterns run most-specific-first so a SPIFFE ID or email is
// labeled precisely before the broad hostname sweep. It is intentionally
// over-eager: a redacted-but-useless prompt is the safe failure mode; egressing a
// data subject's identity to a third-party model is not.
func PIIRedactor(policy PIIPolicy) Redactor {
	if !policy.piiActive() {
		return func(prompt string) string { return prompt }
	}
	return RedactPII
}

// RedactPII strips personal/identifying data from a prompt unconditionally (the
// engine behind PIIRedactor's default-private path). It is exported so callers that
// assemble prompts elsewhere can apply the same boundary.
func RedactPII(prompt string) string {
	out := piiEmail.ReplaceAllString(prompt, "[REDACTED-EMAIL]")
	out = piiSPIFFE.ReplaceAllString(out, "[REDACTED-SPIFFE]")
	out = piiURL.ReplaceAllString(out, "[REDACTED-URL]")
	out = piiIPv6.ReplaceAllString(out, "[REDACTED-IP]")
	out = piiIPv4.ReplaceAllString(out, "[REDACTED-IP]")
	out = piiFQDN.ReplaceAllString(out, "[REDACTED-HOST]")
	out = piiPersonName.ReplaceAllStringFunc(out, func(m string) string {
		if _, stop := piiNameStoplist[strings.ToLower(m)]; stop {
			return m
		}
		return "[REDACTED-NAME]"
	})
	return out
}

// ContainsPII reports whether a prompt still carries personal/identifying data.
// It is the block-mode gate: in Block mode the Adapter refuses the send when this
// is true rather than egressing a partially-redacted prompt. It is a superset
// detector over the same shapes RedactPII rewrites.
func ContainsPII(prompt string) bool {
	if piiEmail.MatchString(prompt) ||
		piiSPIFFE.MatchString(prompt) ||
		piiURL.MatchString(prompt) ||
		piiIPv6.MatchString(prompt) ||
		piiIPv4.MatchString(prompt) ||
		piiFQDN.MatchString(prompt) {
		return true
	}
	for _, m := range piiPersonName.FindAllString(prompt, -1) {
		if _, stop := piiNameStoplist[strings.ToLower(m)]; !stop {
			return true
		}
	}
	return false
}
