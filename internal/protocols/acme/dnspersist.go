// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// dns-persist-01 (P1): persistent DNS validation, allowed by CA/Browser Forum
// Ballot SC-088v3 and specified by the IETF ACME draft
// draft-ietf-acme-dns-persist. The applicant publishes one standing TXT record
// naming the CA and its ACME account, and every later order validates against
// that record with no DNS change and no DNS API key:
//
//	_validation-persist.<domain> TXT "<issuer-domain-name>; accounturi=<account URL>[; policy=wildcard][; persistUntil=<Unix seconds>]"
//
// The draft can still change; this follows it as the reference test CA
// (Pebble 2.10) implements it. Each order validates against the record again,
// so deleting the record, or naming another account in it, makes the next
// order fail.

// ChallengeDNSPersist01 is the persistent DNS validation challenge type.
const ChallengeDNSPersist01 = "dns-persist-01"

// DNSPersistRecordName is where the standing record lives. A wildcard
// identifier validates at its base domain.
func DNSPersistRecordName(domain string) string {
	return "_validation-persist." + strings.TrimSuffix(strings.TrimPrefix(domain, "*."), ".")
}

// DNSPersistRecordValue is the record an applicant publishes for an issuer
// and an account; a wildcard identifier needs policy=wildcard.
func DNSPersistRecordValue(issuerDomainName, accountURI string, wildcard bool) string {
	value := normalizeIssuerDomainName(issuerDomainName) + "; accounturi=" + strings.TrimSpace(accountURI)
	if wildcard {
		value += "; policy=wildcard"
	}
	return value
}

// DNSPersistRecord is one parsed standing record.
type DNSPersistRecord struct {
	IssuerDomainName string
	AccountURI       string
	// Policy is "wildcard" or empty; an unknown value reads as empty.
	Policy string
	// PersistUntil is zero when the record sets no end.
	PersistUntil time.Time
}

// ParseDNSPersistRecord reads one TXT value. The issuer domain name is set
// even when a parameter is malformed, so a validator can tell a broken record
// for this CA from a record for another CA.
func ParseDNSPersistRecord(txt string) (DNSPersistRecord, error) {
	parts := strings.Split(txt, ";")
	rec := DNSPersistRecord{IssuerDomainName: normalizeIssuerDomainName(parts[0])}
	if rec.IssuerDomainName == "" || strings.Contains(rec.IssuerDomainName, "=") {
		return DNSPersistRecord{}, errors.New("the record does not start with an issuer domain name")
	}
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return rec, fmt.Errorf("parameter %q has no value", part)
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "accounturi":
			rec.AccountURI = value
		case "policy":
			if strings.EqualFold(value, "wildcard") {
				rec.Policy = "wildcard"
			}
		case "persistuntil":
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err != nil || seconds <= 0 {
				return rec, fmt.Errorf("persistUntil %q is not a Unix time", value)
			}
			rec.PersistUntil = time.Unix(seconds, 0).UTC()
		}
	}
	if rec.AccountURI == "" {
		return rec, errors.New("the record has no accounturi")
	}
	return rec, nil
}

func normalizeIssuerDomainName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// DNSPersistValidator checks the standing record. It fails closed: a lookup
// error, no record for this CA, another account, a wildcard without
// policy=wildcard or a passed persistUntil each refuse, naming why.
type DNSPersistValidator struct {
	Resolver Resolver
	Now      func() time.Time
}

// ValidatePersist proves that the account at accountURI controls domain
// through a standing record that names one of issuers.
func (v DNSPersistValidator) ValidatePersist(ctx context.Context, domain, accountURI string, issuers []string) error {
	ours := map[string]bool{}
	for _, name := range issuers {
		if name = normalizeIssuerDomainName(name); name != "" {
			ours[name] = true
		}
	}
	if len(ours) == 0 {
		return errors.New("acme: dns-persist-01 has no issuer domain name configured (fail closed)")
	}
	if strings.TrimSpace(accountURI) == "" {
		return errors.New("acme: dns-persist-01 needs the requesting account (fail closed)")
	}
	resolver := v.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	name := DNSPersistRecordName(domain)
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return fmt.Errorf("acme: dns-persist-01 lookup %s: %w", name, err)
	}
	wildcard := strings.HasPrefix(domain, "*.")
	var reasons []string
	seen := map[string]bool{}
	reason := func(r string) {
		if !seen[r] {
			seen[r] = true
			reasons = append(reasons, r)
		}
	}
	for _, txt := range records {
		rec, err := ParseDNSPersistRecord(txt)
		if !ours[rec.IssuerDomainName] {
			continue // a record for another CA
		}
		switch {
		case err != nil:
			reason(err.Error())
		case rec.AccountURI != accountURI:
			reason("it names a different ACME account")
		case wildcard && rec.Policy != "wildcard":
			reason("it does not allow wildcard issuance (policy=wildcard)")
		case !rec.PersistUntil.IsZero() && now().After(rec.PersistUntil):
			reason("it ended at " + rec.PersistUntil.Format(time.RFC3339) + " (persistUntil)")
		default:
			return nil
		}
	}
	if len(reasons) == 0 {
		return fmt.Errorf("acme: dns-persist-01: no TXT record at %s names this CA", name)
	}
	return fmt.Errorf("acme: dns-persist-01: the record at %s names this CA, but %s", name, strings.Join(reasons, "; "))
}

// dnsPersistConfig is this server's dns-persist-01 offer.
type dnsPersistConfig struct {
	issuers   []string
	validator DNSPersistValidator
}

// WithDNSPersist offers dns-persist-01 for standing records that name any of
// issuers, this CA's issuer domain names, checked with v. With no names the
// challenge is not offered.
func (s *Server) WithDNSPersist(issuers []string, v DNSPersistValidator) *Server {
	var names []string
	for _, name := range issuers {
		if name = normalizeIssuerDomainName(name); name != "" {
			names = append(names, name)
		}
	}
	s.dnsPersist = nil
	if len(names) > 0 {
		s.dnsPersist = &dnsPersistConfig{issuers: names, validator: v}
	}
	return s
}

// offeredChallengeTypes is what this server offers before any validation
// policy: the three DV methods, and dns-persist-01 when it is configured.
func (s *Server) offeredChallengeTypes() []string {
	types := defaultChallengeTypes()
	if s.dnsPersist != nil {
		types = append(types, ChallengeDNSPersist01)
	}
	return types
}

// validateDNSPersist checks the standing record for the requesting account.
func (s *Server) validateDNSPersist(ctx context.Context, domain string, acct *account) error {
	if s.dnsPersist == nil {
		return errors.New("acme: dns-persist-01 is not offered by this server")
	}
	return s.dnsPersist.validator.ValidatePersist(ctx, domain, acct.url, s.dnsPersist.issuers)
}

// challengeJSON is a challenge object; dns-persist-01 names the issuer domain
// names a record may use.
func (s *Server) challengeJSON(base string, ch *challenge) map[string]any {
	out := map[string]any{"type": ch.typ, "url": base + "/acme/chal/" + ch.id, "token": ch.token, "status": ch.status}
	if ch.typ == ChallengeDNSPersist01 && s.dnsPersist != nil {
		out["issuer-domain-names"] = append([]string(nil), s.dnsPersist.issuers...)
	}
	return out
}
