// SPDX-License-Identifier: BUSL-1.1

// Package spf evaluates a Sender Policy Framework record (RFC 7208) for a
// message's envelope sender and the address that delivered it (P15-L6). It
// implements check_host() (§4) with the mechanisms all, include, a, mx,
// ip4, ip6 and exists, the redirect modifier, the §7 macros a domain-spec may
// use, and the §4.6.4 limits: at most ten terms that query DNS and two void
// lookups. ptr is never matched (§5.5 says it SHOULD NOT be used), and exp is
// read past, since the result's explanation is not shown to anyone.
package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Result is an SPF result (RFC 7208 §2.6).
type Result string

// The SPF results.
const (
	None      Result = "none"
	Neutral   Result = "neutral"
	Pass      Result = "pass"
	Fail      Result = "fail"
	SoftFail  Result = "softfail"
	TempError Result = "temperror"
	PermError Result = "permerror"
)

// Resolver is the DNS an SPF check reads.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Checker checks SPF. Pinned answers the TXT query for its domains, for
// networks whose mail domains are not in DNS; other names go to Resolver.
type Checker struct {
	Resolver Resolver
	Pinned   map[string]string
}

const (
	maxDNSTerms   = 10
	maxVoids      = 2
	maxAddrsPerMX = 10
	maxDepth      = 20
)

// Check evaluates check_host() for ip delivering mail from sender (the
// envelope MAIL FROM; when it is empty, postmaster at helo) and returns the
// result with a reason a refusal can name.
func (c Checker) Check(ctx context.Context, ip net.IP, sender, helo string) (Result, string) {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	sender = strings.TrimSpace(sender)
	if sender == "" {
		sender = "postmaster@" + helo
	}
	at := strings.LastIndexByte(sender, '@')
	if at <= 0 {
		sender = "postmaster@" + sender
		at = strings.LastIndexByte(sender, '@')
	}
	domain := strings.ToLower(strings.TrimSuffix(sender[at+1:], "."))
	e := &eval{c: c, ctx: ctx, ip: ip, sender: sender, helo: helo}
	result := e.checkHost(domain, 0)
	return result, e.reason
}

type eval struct {
	c      Checker
	ctx    context.Context
	ip     net.IP
	sender string
	helo   string
	terms  int
	voids  int
	reason string
}

func (e *eval) fail(result Result, format string, args ...any) Result {
	if e.reason == "" {
		e.reason = fmt.Sprintf(format, args...)
	}
	return result
}

func validDomain(d string) bool {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// record returns the domain's one SPF record, or a result when there is
// none, more than one, or DNS failed.
func (e *eval) record(domain string) (string, Result) {
	var txts []string
	if pinned, ok := e.c.Pinned[domain]; ok {
		txts = []string{pinned}
	} else if e.c.Resolver != nil {
		var err error
		if txts, err = e.c.Resolver.LookupTXT(e.ctx, domain); err != nil {
			if isNotFound(err) {
				return "", None
			}
			return "", e.fail(TempError, "the SPF lookup for %s failed", domain)
		}
	}
	var found []string
	for _, txt := range txts {
		lower := strings.ToLower(txt)
		if lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ") {
			found = append(found, txt)
		}
	}
	switch len(found) {
	case 0:
		return "", None
	case 1:
		return found[0], ""
	default:
		return "", e.fail(PermError, "%s publishes more than one SPF record", domain)
	}
}

func (e *eval) checkHost(domain string, depth int) Result {
	if depth > maxDepth {
		return e.fail(PermError, "the SPF records nest too deep")
	}
	if !validDomain(domain) {
		return None
	}
	record, result := e.record(domain)
	if result != "" {
		return result
	}
	redirect := ""
	for _, term := range strings.Fields(record)[1:] {
		if name, value, ok := modifier(term); ok {
			if name == "redirect" {
				if redirect != "" {
					return e.fail(PermError, "%s's record has two redirects", domain)
				}
				redirect = value
			}
			continue
		}
		qualifier := Pass
		switch term[0] {
		case '+':
			term = term[1:]
		case '-':
			qualifier, term = Fail, term[1:]
		case '~':
			qualifier, term = SoftFail, term[1:]
		case '?':
			qualifier, term = Neutral, term[1:]
		}
		match, result := e.mechanism(term, domain, depth)
		if result != "" {
			return result
		}
		if match {
			if qualifier != Pass {
				e.fail(qualifier, "%s's SPF record says %s for this host (%s)", domain, qualifier, term)
			}
			return qualifier
		}
	}
	if redirect != "" {
		if e.terms++; e.terms > maxDNSTerms {
			return e.fail(PermError, "the SPF records use more than %d DNS lookups", maxDNSTerms)
		}
		target, err := e.expand(redirect, domain)
		if err != nil {
			return e.fail(PermError, "%s's redirect: %v", domain, err)
		}
		result := e.checkHost(target, depth+1)
		if result == None {
			return e.fail(PermError, "%s redirects to %s, which has no SPF record", domain, target)
		}
		return result
	}
	return e.fail(Neutral, "%s's SPF record matches nothing for this host", domain)
}

// modifier splits a name=value term; a mechanism is not one.
func modifier(term string) (string, string, bool) {
	name, value, ok := strings.Cut(term, "=")
	if !ok || name == "" || strings.ContainsAny(name, ":/") {
		return "", "", false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		nameByte := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !nameByte {
			return "", "", false
		}
	}
	return strings.ToLower(name), value, true
}

// mechanism reports whether a mechanism matches, or a result that ends the
// evaluation.
func (e *eval) mechanism(term, domain string, depth int) (bool, Result) {
	name, arg, _ := strings.Cut(term, ":")
	name = strings.ToLower(name)
	cidr4, cidr6 := 32, 128
	if name == "a" || name == "mx" {
		// a and mx take an optional domain-spec and dual CIDR lengths:
		// a, a/24, a:example.com/24//64.
		rest := strings.TrimPrefix(term[len(name):], ":")
		spec, lengths, _ := strings.Cut(rest, "/")
		arg = spec
		if lengths != "" || strings.Contains(rest, "/") {
			l4, l6, _ := strings.Cut(lengths, "/")
			var err error
			if l4 != "" {
				if cidr4, err = strconv.Atoi(l4); err != nil || cidr4 < 0 || cidr4 > 32 {
					return false, e.fail(PermError, "%s's record has a bad CIDR length in %s", domain, term)
				}
			}
			if l6 != "" {
				if cidr6, err = strconv.Atoi(l6); err != nil || cidr6 < 0 || cidr6 > 128 {
					return false, e.fail(PermError, "%s's record has a bad CIDR length in %s", domain, term)
				}
			}
		}
	}
	switch name {
	case "all":
		return true, ""
	case "ip4", "ip6":
		network := arg
		if !strings.Contains(network, "/") {
			if name == "ip4" {
				network += "/32"
			} else {
				network += "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil || (name == "ip4") != (ipnet.IP.To4() != nil) {
			return false, e.fail(PermError, "%s's record has a bad %s", domain, term)
		}
		return ipnet.Contains(e.ip) && (e.ip.To4() != nil) == (name == "ip4"), ""
	case "include", "a", "mx", "exists", "ptr":
		if e.terms++; e.terms > maxDNSTerms {
			return false, e.fail(PermError, "the SPF records use more than %d DNS lookups", maxDNSTerms)
		}
	default:
		return false, e.fail(PermError, "%s's record has an unknown mechanism %s", domain, term)
	}
	target := domain
	if arg != "" {
		var err error
		if target, err = e.expand(arg, domain); err != nil {
			return false, e.fail(PermError, "%s's %s: %v", domain, name, err)
		}
	} else if name == "include" || name == "exists" {
		return false, e.fail(PermError, "%s's record has %s with no domain", domain, name)
	}
	switch name {
	case "include":
		switch result := e.checkHost(target, depth+1); result {
		case Pass:
			return true, ""
		case Fail, SoftFail, Neutral:
			return false, ""
		case TempError:
			return false, TempError
		default:
			return false, e.fail(PermError, "%s includes %s, which has no usable SPF record", domain, target)
		}
	case "a":
		return e.addressesMatch(target, cidr4, cidr6)
	case "mx":
		if e.c.Resolver == nil {
			return false, e.void(target)
		}
		mxs, err := e.c.Resolver.LookupMX(e.ctx, target)
		if err != nil && !isNotFound(err) {
			return false, e.fail(TempError, "the MX lookup for %s failed", target)
		}
		if len(mxs) == 0 {
			return false, e.void(target)
		}
		if len(mxs) > maxAddrsPerMX {
			return false, e.fail(PermError, "%s has more than %d MX records", target, maxAddrsPerMX)
		}
		for _, mx := range mxs {
			if match, result := e.addressesMatch(strings.TrimSuffix(mx.Host, "."), cidr4, cidr6); match || result != "" {
				return match, result
			}
		}
		return false, ""
	case "exists":
		if e.c.Resolver == nil {
			return false, e.void(target)
		}
		addrs, err := e.c.Resolver.LookupIPAddr(e.ctx, target)
		if err != nil && !isNotFound(err) {
			return false, e.fail(TempError, "the exists lookup for %s failed", target)
		}
		for _, a := range addrs {
			if a.IP.To4() != nil {
				return true, ""
			}
		}
		return false, e.void(target)
	default: // ptr: never matched (RFC 7208 §5.5).
		return false, ""
	}
}

// void counts a lookup that found nothing (§4.6.4).
func (e *eval) void(name string) Result {
	if e.voids++; e.voids > maxVoids {
		return e.fail(PermError, "the SPF records make more than %d lookups that find nothing (last %s)", maxVoids, name)
	}
	return ""
}

func (e *eval) addressesMatch(host string, cidr4, cidr6 int) (bool, Result) {
	if e.c.Resolver == nil {
		return false, ""
	}
	addrs, err := e.c.Resolver.LookupIPAddr(e.ctx, host)
	if err != nil && !isNotFound(err) {
		return false, e.fail(TempError, "the address lookup for %s failed", host)
	}
	if len(addrs) == 0 {
		return false, e.void(host)
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil && e.ip.To4() != nil {
			if (&net.IPNet{IP: v4.Mask(net.CIDRMask(cidr4, 32)), Mask: net.CIDRMask(cidr4, 32)}).Contains(e.ip) {
				return true, ""
			}
		} else if a.IP.To4() == nil && e.ip.To4() == nil {
			if (&net.IPNet{IP: a.IP.Mask(net.CIDRMask(cidr6, 128)), Mask: net.CIDRMask(cidr6, 128)}).Contains(e.ip) {
				return true, ""
			}
		}
	}
	return false, ""
}

// expand expands a domain-spec's macros (§7) and keeps it within 253
// characters by dropping labels from the left (§7.3).
func (e *eval) expand(spec, domain string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		if c != '%' {
			if c < 0x21 || c > 0x7e {
				return "", errors.New("a domain-spec holds a character outside visible ASCII")
			}
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(spec) {
			return "", errors.New("a domain-spec ends with %")
		}
		i++
		switch spec[i] {
		case '%':
			b.WriteByte('%')
		case '_':
			b.WriteByte(' ')
		case '-':
			b.WriteString("%20")
		case '{':
			end := strings.IndexByte(spec[i:], '}')
			if end < 0 {
				return "", errors.New("a macro is not closed")
			}
			value, err := e.macro(spec[i+1:i+end], domain)
			if err != nil {
				return "", err
			}
			b.WriteString(value)
			i += end
		default:
			return "", fmt.Errorf("%%%c is not a macro", spec[i])
		}
	}
	out := strings.TrimSuffix(b.String(), ".")
	for len(out) > 253 {
		_, rest, ok := strings.Cut(out, ".")
		if !ok {
			return "", errors.New("an expanded domain-spec is longer than 253 characters")
		}
		out = rest
	}
	return strings.ToLower(out), nil
}

func (e *eval) macro(body, domain string) (string, error) {
	if body == "" {
		return "", errors.New("an empty macro")
	}
	letter := body[0] | 0x20
	rest := body[1:]
	digits := 0
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		digits = digits*10 + int(rest[0]-'0')
		rest = rest[1:]
	}
	reverse := false
	if len(rest) > 0 && (rest[0]|0x20) == 'r' {
		reverse, rest = true, rest[1:]
	}
	delimiters := rest
	for i := 0; i < len(delimiters); i++ {
		if !strings.ContainsRune(".-+,/_=", rune(delimiters[i])) {
			return "", fmt.Errorf("%q is not a macro delimiter", delimiters[i])
		}
	}
	if delimiters == "" {
		delimiters = "."
	}
	at := strings.LastIndexByte(e.sender, '@')
	var value string
	switch letter {
	case 's':
		value = e.sender
	case 'l':
		value = e.sender[:at]
	case 'o':
		value = e.sender[at+1:]
	case 'd':
		value = domain
	case 'h':
		value = e.helo
	case 'i':
		if v4 := e.ip.To4(); v4 != nil {
			value = v4.String()
		} else {
			hexDigits := fmt.Sprintf("%032x", []byte(e.ip.To16()))
			value = strings.Join(strings.Split(hexDigits, ""), ".")
		}
	case 'v':
		value = "in-addr"
		if e.ip.To4() == nil {
			value = "ip6"
		}
	case 'p':
		value = "unknown"
	default:
		return "", fmt.Errorf("%%{%c} is not a domain-spec macro", letter)
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune(delimiters, r) })
	if reverse {
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
	}
	if digits > 0 && digits < len(parts) {
		parts = parts[len(parts)-digits:]
	}
	return strings.Join(parts, "."), nil
}
