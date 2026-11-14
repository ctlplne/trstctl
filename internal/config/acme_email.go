// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net"
	"regexp"
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
	// DKIMSelector and DKIMKeyRef make trstctl DKIM-sign its own challenge
	// mail (P15-L2): rsa-sha256, relaxed/relaxed, d= the from address's
	// domain, s= the selector, with the RSA private key the reference holds
	// (file: or secret://, one unencrypted PEM block), read for each mail.
	// Empty leaves signing to the relay.
	DKIMSelector string `json:"dkim_selector,omitempty"`
	DKIMKeyRef   string `json:"dkim_key_ref,omitempty"`
	// RequireSPF refuses a reply unless SPF (RFC 7208) passes for its
	// envelope sender and the address that delivered it (P15-L6). RFC 8823
	// asks only for DKIM, and forwarding breaks SPF, so it is off unless set.
	RequireSPF bool `json:"require_spf,omitempty"`
	// SPFRecords pins SPF records ("v=spf1 ...") by domain for mail domains
	// whose records are not in DNS; other domains are read from DNS.
	SPFRecords map[string]string `json:"spf_records,omitempty"`
}

// dkimSelectorPattern is a DKIM selector: dot-separated DNS labels.
var dkimSelectorPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

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
	if (strings.TrimSpace(p.DKIMSelector) == "") != (strings.TrimSpace(p.DKIMKeyRef) == "") {
		errs = append(errs, fmt.Errorf("protocols.acme_email.dkim_selector and dkim_key_ref are set together"))
	} else if sel := strings.TrimSpace(p.DKIMSelector); sel != "" {
		if len(sel) > 253 || !dkimSelectorPattern.MatchString(sel) {
			errs = append(errs, fmt.Errorf("protocols.acme_email.dkim_selector %q is not a lowercase DKIM selector", p.DKIMSelector))
		}
		if ref := strings.TrimSpace(p.DKIMKeyRef); !strings.HasPrefix(ref, "file:") && !strings.HasPrefix(ref, "secret://") {
			errs = append(errs, fmt.Errorf("protocols.acme_email.dkim_key_ref must be a file: or secret:// reference"))
		}
	}
	for domain, record := range p.SPFRecords {
		lower := strings.ToLower(strings.TrimSpace(record))
		if !issuerDomainNamePattern.MatchString(domain) {
			errs = append(errs, fmt.Errorf("protocols.acme_email.spf_records name %q is not a lowercase DNS name", domain))
		}
		if lower != "v=spf1" && !strings.HasPrefix(lower, "v=spf1 ") {
			errs = append(errs, fmt.Errorf("protocols.acme_email.spf_records[%q] is not an SPF record (v=spf1 ...)", domain))
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
