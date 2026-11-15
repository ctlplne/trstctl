// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"regexp"
	"strings"
)

// ACMEDNSPersist configures persistent DNS validation (dns-persist-01, P1)
// on the built-in ACME server: the issuer domain names that identify this CA
// in an applicant's standing _validation-persist TXT record. Empty keeps the
// challenge off.
type ACMEDNSPersist struct {
	IssuerDomainNames []string `json:"issuer_domain_names,omitempty"`
	// AccountURIForm is how a standing record names its ACME account
	// (P1-ACCOUNTURI): "account_url" (the default) takes the account URL, as
	// Pebble 2.10 and draft-ietf-acme-dns-persist-01 do; "hashed" takes
	// draft-ietf-acme-dns-persist-02's hashed accounturi, advertises
	// accountHashPrefix in the directory, and refuses an account URL.
	AccountURIForm string `json:"accounturi_form,omitempty"`
}

// Hashed reports whether records take the hashed accounturi form.
func (p ACMEDNSPersist) Hashed() bool { return p.AccountURIForm == "hashed" }

var issuerDomainNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validateACMEDNSPersist(p ACMEDNSPersist) []error {
	var errs []error
	switch p.AccountURIForm {
	case "", "account_url", "hashed":
	default:
		errs = append(errs, fmt.Errorf("protocols.acme_dns_persist.accounturi_form %q is not account_url or hashed", p.AccountURIForm))
	}
	seen := map[string]bool{}
	for i, name := range p.IssuerDomainNames {
		name = strings.TrimSpace(name)
		switch {
		case len(name) > 253 || !issuerDomainNamePattern.MatchString(name):
			errs = append(errs, fmt.Errorf("protocols.acme_dns_persist.issuer_domain_names[%d] %q is not a lowercase DNS name", i, name))
		case seen[name]:
			errs = append(errs, fmt.Errorf("protocols.acme_dns_persist.issuer_domain_names[%d] %q is duplicated", i, name))
		}
		seen[name] = true
	}
	return errs
}
