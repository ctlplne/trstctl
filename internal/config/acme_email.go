// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net"
	"strings"
)

// ACMEEmail offers S/MIME certificates over ACME (RFC 8823, P15): email
// identifiers proved by the email-reply-00 challenge. From is the challenge
// mail's sender and the address replies go to; Domains are the mail domains
// this server issues for; Profile is the certificate profile S/MIME
// certificates are issued under (its allowed_ekus should be
// ["emailProtection"]). Challenge mail goes out through the SMTP relay at
// RelayAddr, which must DKIM-sign it for From's domain (RFC 8823 §3.1); the
// relay password is a secret reference resolved for each send. An empty From
// keeps the offer off.
type ACMEEmail struct {
	From             string   `json:"from,omitempty"`
	Domains          []string `json:"domains,omitempty"`
	Profile          string   `json:"profile,omitempty"`
	RelayAddr        string   `json:"relay_addr,omitempty"`
	RelayUsername    string   `json:"relay_username,omitempty"`
	RelayPasswordRef string   `json:"relay_password_ref,omitempty"`
	// SMTPListen is the address of the reply intake, an SMTP receiver for the
	// from address only; the mail system routes replies to it. Empty keeps it
	// off.
	SMTPListen string `json:"smtp_listen,omitempty"`
	// DKIMKeys pins DKIM key records ("v=DKIM1; k=rsa; p=...") by name
	// ("<selector>._domainkey.<domain>") for mail domains whose keys are not
	// in DNS; other keys are read from DNS.
	DKIMKeys map[string]string `json:"dkim_keys,omitempty"`
}

func validateACMEEmail(p ACMEEmail) []error {
	if p.From == "" && len(p.Domains) == 0 && p.Profile == "" && p.RelayAddr == "" && p.RelayUsername == "" && p.RelayPasswordRef == "" {
		return nil
	}
	var errs []error
	from := strings.TrimSpace(p.From)
	at := strings.LastIndexByte(from, '@')
	if at <= 0 || at == len(from)-1 || strings.ContainsAny(from, " <>\t\r\n") || !issuerDomainNamePattern.MatchString(strings.ToLower(from[at+1:])) {
		errs = append(errs, fmt.Errorf("protocols.acme_email.from %q is not a plain email address", p.From))
	}
	if len(p.Domains) == 0 {
		errs = append(errs, fmt.Errorf("protocols.acme_email.domains names no mail domain"))
	}
	seen := map[string]bool{}
	for i, d := range p.Domains {
		d = strings.TrimSpace(d)
		switch {
		case len(d) > 253 || !issuerDomainNamePattern.MatchString(d):
			errs = append(errs, fmt.Errorf("protocols.acme_email.domains[%d] %q is not a lowercase DNS name", i, d))
		case seen[d]:
			errs = append(errs, fmt.Errorf("protocols.acme_email.domains[%d] %q is duplicated", i, d))
		}
		seen[d] = true
	}
	if strings.TrimSpace(p.Profile) == "" {
		errs = append(errs, fmt.Errorf("protocols.acme_email.profile names no certificate profile"))
	}
	if _, port, err := net.SplitHostPort(strings.TrimSpace(p.RelayAddr)); err != nil || port == "" {
		errs = append(errs, fmt.Errorf("protocols.acme_email.relay_addr %q is not host:port", p.RelayAddr))
	}
	if (p.RelayUsername == "") != (p.RelayPasswordRef == "") {
		errs = append(errs, fmt.Errorf("protocols.acme_email.relay_username and relay_password_ref are set together"))
	}
	if listen := strings.TrimSpace(p.SMTPListen); listen != "" {
		if _, port, err := net.SplitHostPort(listen); err != nil || port == "" {
			errs = append(errs, fmt.Errorf("protocols.acme_email.smtp_listen %q is not host:port", p.SMTPListen))
		}
	}
	for name, record := range p.DKIMKeys {
		selector, domain, ok := strings.Cut(name, "._domainkey.")
		if !ok || selector == "" || !issuerDomainNamePattern.MatchString(domain) {
			errs = append(errs, fmt.Errorf("protocols.acme_email.dkim_keys name %q is not <selector>._domainkey.<domain>", name))
		}
		if !strings.Contains(record, "p=") {
			errs = append(errs, fmt.Errorf("protocols.acme_email.dkim_keys[%q] has no p= key", name))
		}
	}
	return errs
}
