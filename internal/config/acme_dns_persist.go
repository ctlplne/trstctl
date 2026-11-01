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
}

var issuerDomainNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validateACMEDNSPersist(p ACMEDNSPersist) []error {
	var errs []error
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
