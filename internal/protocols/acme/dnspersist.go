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

	"golang.org/x/net/publicsuffix"

	"trstctl.com/trstctl/internal/crypto"
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
//
// A record with policy=wildcard also authorizes every subdomain of its domain
// (P1-L2, draft-ietf-acme-dns-persist-02 §5.1 and §6): the validator reads the
// name's own record first, then its parent domains nearest first, never above
// the registrable domain, and a parent's record counts only with
// policy=wildcard. Without it a record authorizes its own name only.

// ChallengeDNSPersist01 is the persistent DNS validation challenge type.
const ChallengeDNSPersist01 = "dns-persist-01"

// DNSPersistRecordName is where the standing record lives. A wildcard
// identifier validates at its base domain.
func DNSPersistRecordName(domain string) string {
	return "_validation-persist." + strings.TrimSuffix(strings.TrimPrefix(domain, "*."), ".")
}

// DNSPersistAccountHashAlgorithm is the hash a hashed accounturi names
// (draft-ietf-acme-dns-persist-02 §4.1: the RFC 6920 registry name).
const DNSPersistAccountHashAlgorithm = "sha-256"

// DNSPersistAccountHashPrefix is the accountHashPrefix this server advertises
// in its directory's meta when it takes the hashed accounturi form: a path
// under the server's base, so appending the algorithm and the hash yields a
// URI, and stable while the base and its account URLs are.
func DNSPersistAccountHashPrefix(base string) string {
	return strings.TrimSuffix(base, "/") + "/acme/account-hash/"
}

// DNSPersistHashedAccountURI is draft-ietf-acme-dns-persist-02's accounturi
// (P1-ACCOUNTURI, §4.1): prefix (the authority's directory meta
// accountHashPrefix), "sha-256/", and the unpadded base64url SHA-256 of one
// octet holding len(domain), domain, the account key's RFC 7638 thumbprint
// (43 unpadded base64url characters) and the account URL. domain is the name
// the record stands at, lowercase without a trailing dot, or "*" for a record
// bound to no name.
func DNSPersistHashedAccountURI(prefix, domain, thumbprint, accountURL string) (string, error) {
	if domain != "*" {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	}
	if prefix == "" || domain == "" || len(domain) > 255 || thumbprint == "" || accountURL == "" {
		return "", errors.New("acme: a hashed accounturi needs the prefix, a domain of at most 255 octets, the key thumbprint and the account URL")
	}
	input := make([]byte, 0, 1+len(domain)+len(thumbprint)+len(accountURL))
	input = append(input, byte(len(domain))) // #nosec G115 -- bounded to 255 above (CWE-190)
	input = append(input, domain...)
	input = append(input, thumbprint...)
	input = append(input, accountURL...)
	return prefix + DNSPersistAccountHashAlgorithm + "/" + crypto.SHA256Base64URL(input), nil
}

// DNSPersistAccount is the account a standing record must name: its URL and,
// for the hashed form, the thumbprints of every key the account has held,
// the current one first (draft-ietf-acme-dns-persist-02 §4.2).
type DNSPersistAccount struct {
	URL            string
	KeyThumbprints []string
}

// DNSPersistRecordValue is the record an applicant publishes for an issuer
// and an account; a wildcard identifier needs policy=wildcard. accountURI is
// the account URL or, for an authority that advertises accountHashPrefix,
// its hashed accounturi (DNSPersistHashedAccountURI).
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

// MaxDNSPersistLookups bounds the TXT lookups one validation makes: the
// name's own record, then at most this many names in all up its parents.
const MaxDNSPersistLookups = 16

// DNSPersistValidator checks the standing record. It fails closed: a lookup
// error, no record for this CA, another account, a wildcard or a subdomain
// without policy=wildcard or a passed persistUntil each refuse, naming why.
type DNSPersistValidator struct {
	Resolver Resolver
	Now      func() time.Time
	// ExactNameOnly reads the name's own record only. The upstream client
	// sets it: whether another CA honors a parent's policy=wildcard is that
	// CA's choice (the draft makes it a MAY), so the record trstctl relies
	// on there must stand at the name itself.
	ExactNameOnly bool
	// AccountHashPrefix, when set, takes the hashed accounturi of
	// draft-ietf-acme-dns-persist-02 (P1-ACCOUNTURI): a record names the
	// account by the hash under this prefix of the domain the record stands
	// at (or "*"), one of the account's key thumbprints and its URL, and an
	// account URL in its place is refused. Empty takes the account URL, as
	// Pebble 2.10 does.
	AccountHashPrefix string
}

// namesAccount reports whether a record standing at recordName names acct.
func (v DNSPersistValidator) namesAccount(recordName, accountURI string, acct DNSPersistAccount) (bool, string) {
	if v.AccountHashPrefix == "" {
		return accountURI == acct.URL, "it names a different ACME account"
	}
	if accountURI == acct.URL {
		return false, "it names the account by its URL, and this CA takes the hashed accounturi (draft-ietf-acme-dns-persist-02)"
	}
	domain := strings.TrimPrefix(recordName, "_validation-persist.")
	for _, thumbprint := range acct.KeyThumbprints {
		for _, d := range []string{domain, "*"} {
			if want, err := DNSPersistHashedAccountURI(v.AccountHashPrefix, d, thumbprint, acct.URL); err == nil && accountURI == want {
				return true, ""
			}
		}
	}
	return false, "it names a different ACME account"
}

// dnsPersistParents lists the parent domains whose policy=wildcard record
// may authorize name (the record's domain is a proper suffix of the name,
// draft-ietf-acme-dns-persist-02 §6.1), nearest first, down to the
// registrable domain and never above it: a record at a public suffix
// authorizes nothing.
func dnsPersistParents(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(name, "*."), "."))
	apex, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil || apex == name || !strings.HasSuffix(name, "."+apex) {
		return nil
	}
	var parents []string
	for rest := name; rest != apex; {
		_, after, ok := strings.Cut(rest, ".")
		if !ok {
			break
		}
		rest = after
		parents = append(parents, rest)
	}
	return parents
}

// ValidatePersist proves that the account at accountURI controls domain
// through a standing record that names one of issuers.
func (v DNSPersistValidator) ValidatePersist(ctx context.Context, domain, accountURI string, issuers []string) error {
	return v.ValidatePersistAccount(ctx, domain, DNSPersistAccount{URL: accountURI}, issuers)
}

// ValidatePersistAccount is ValidatePersist for an account named by its URL
// and key thumbprints, as the hashed accounturi needs.
func (v DNSPersistValidator) ValidatePersistAccount(ctx context.Context, domain string, acct DNSPersistAccount, issuers []string) error {
	accountURI := acct.URL
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
	exact := DNSPersistRecordName(domain)
	names := []string{exact}
	if !v.ExactNameOnly {
		for _, parent := range dnsPersistParents(domain) {
			if len(names) == MaxDNSPersistLookups {
				break
			}
			names = append(names, "_validation-persist."+parent)
		}
	}
	wildcard := strings.HasPrefix(domain, "*.")
	type refusal struct {
		name    string
		reasons []string
	}
	var refusals []refusal
	reason := func(name, r string) {
		if n := len(refusals); n == 0 || refusals[n-1].name != name {
			refusals = append(refusals, refusal{name: name})
		}
		last := &refusals[len(refusals)-1]
		for _, seen := range last.reasons {
			if seen == r {
				return
			}
		}
		last.reasons = append(last.reasons, r)
	}
	for i, name := range names {
		records, err := resolver.LookupTXT(ctx, name)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue // no record at this name
			}
			return fmt.Errorf("acme: dns-persist-01 lookup %s: %w", name, err)
		}
		subdomain := i > 0
		for _, txt := range records {
			rec, err := ParseDNSPersistRecord(txt)
			if !ours[rec.IssuerDomainName] {
				continue // a record for another CA
			}
			named, why := v.namesAccount(name, rec.AccountURI, acct)
			switch {
			case err != nil:
				reason(name, err.Error())
			case !named:
				reason(name, why)
			case subdomain && rec.Policy != "wildcard":
				reason(name, "it does not allow subdomains (policy=wildcard)")
			case wildcard && rec.Policy != "wildcard":
				reason(name, "it does not allow wildcard issuance (policy=wildcard)")
			case !rec.PersistUntil.IsZero() && now().After(rec.PersistUntil):
				reason(name, "it ended at "+rec.PersistUntil.Format(time.RFC3339)+" (persistUntil)")
			default:
				return nil
			}
		}
	}
	if len(refusals) == 0 {
		if len(names) > 1 {
			return fmt.Errorf("acme: dns-persist-01: no TXT record at %s names this CA, nor at a parent domain up to %s",
				exact, names[len(names)-1])
		}
		return fmt.Errorf("acme: dns-persist-01: no TXT record at %s names this CA", exact)
	}
	parts := make([]string, 0, len(refusals))
	for _, r := range refusals {
		parts = append(parts, "the record at "+r.name+" names this CA, but "+strings.Join(r.reasons, "; "))
	}
	return errors.New("acme: dns-persist-01: " + strings.Join(parts, "; "))
}

// dnsPersistConfig is this server's dns-persist-01 offer.
type dnsPersistConfig struct {
	issuers   []string
	validator DNSPersistValidator
	// hashed takes draft-ietf-acme-dns-persist-02's hashed accounturi: the
	// directory advertises accountHashPrefix under the request's base, and a
	// record is checked against the prefix under its account's URL base.
	hashed bool
}

// maxPriorKeyThumbprints bounds the earlier key thumbprints an account keeps
// for hashed dns-persist-01 records.
const maxPriorKeyThumbprints = 16

// withPriorThumbprint records old as the account's newest earlier key, unless
// it is the current one or already kept.
func withPriorThumbprint(prior []string, old, current string) []string {
	if old == "" || old == current {
		return prior
	}
	out := []string{old}
	for _, t := range prior {
		if t != old && t != current && len(out) < maxPriorKeyThumbprints {
			out = append(out, t)
		}
	}
	return out
}

// WithDNSPersistHashedAccountURI takes the hashed accounturi form of
// draft-ietf-acme-dns-persist-02 (P1-ACCOUNTURI) for the dns-persist-01 offer
// WithDNSPersist made; off takes the account URL, as Pebble 2.10 does.
func (s *Server) WithDNSPersistHashedAccountURI(on bool) *Server {
	if s.dnsPersist != nil {
		s.dnsPersist.hashed = on
	}
	return s
}

// dnsPersistAccountBase is the base an account URL was made under
// (<base>/acme/acct/<id>).
func dnsPersistAccountBase(accountURL string) string {
	if i := strings.LastIndex(accountURL, "/acme/acct/"); i > 0 {
		return accountURL[:i]
	}
	return ""
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
	v := s.dnsPersist.validator
	who := DNSPersistAccount{URL: acct.url}
	if s.dnsPersist.hashed {
		base := dnsPersistAccountBase(acct.url)
		if base == "" || acct.key == nil {
			return errors.New("acme: dns-persist-01 cannot derive this account's hashed accounturi (fail closed)")
		}
		v.AccountHashPrefix = DNSPersistAccountHashPrefix(base)
		who.KeyThumbprints = append([]string{acct.key.Thumbprint()}, acct.priorThumbprints...)
	}
	return v.ValidatePersistAccount(ctx, domain, who, s.dnsPersist.issuers)
}

// challengeJSON is a challenge object; dns-persist-01 names the issuer domain
// names a record may use.
func (s *Server) challengeJSON(base string, ch *challenge) map[string]any {
	out := map[string]any{"type": ch.typ, "url": base + "/acme/chal/" + ch.id, "token": ch.token, "status": ch.status}
	if ch.typ == ChallengeDNSPersist01 && s.dnsPersist != nil {
		out["issuer-domain-names"] = append([]string(nil), s.dnsPersist.issuers...)
	}
	if ch.typ == ChallengeEmailReply00 && s.email != nil {
		out["from"] = s.email.from // RFC 8823 §3 step 3
	}
	return out
}
