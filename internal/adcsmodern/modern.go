// SPDX-License-Identifier: BUSL-1.1

// Package adcsmodern turns an inventoried AD CS certificate template into a
// trstctl certificate profile with the template's risky properties removed
// (A160, "modernize this template"). It is a pure mapping: the discovery
// package reports what the directory holds and never authorizes issuance;
// this package proposes the profile, and the profile API creates it under the
// usual review.
package adcsmodern

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/profile"
)

// DefaultMaxValidity is the modernized profile's validity ceiling: short-lived
// certificates renewed by protocol replace AD CS's typical one- or two-year
// templates.
const DefaultMaxValidity = 90 * 24 * time.Hour

const (
	ekuServerAuth = "1.3.6.1.5.5.7.3.1"
)

// Change is one property of the template that the profile does not carry over,
// or carries over differently, with the reason an operator reads.
type Change struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Modernization is the proposed profile and what it changed.
type Modernization struct {
	Profile profile.CertificateProfile `json:"profile"`
	Changes []Change                   `json:"changes"`
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Modernize proposes the trstctl profile an observed template becomes in the
// given DNS domain. The requester no longer supplies the subject: names must be
// DNS names under the domain, which the enrollment protocol validates, and
// email, URI and IP names are refused by the profile's name policy.
func Modernize(t adcs.Template, domain string) (Modernization, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if !domainPattern.MatchString(domain) {
		return Modernization{}, fmt.Errorf("adcsmodern: %q is not a DNS domain the profile can confine names to", domain)
	}
	if strings.TrimSpace(t.Name) == "" {
		return Modernization{}, fmt.Errorf("adcsmodern: the template has no name")
	}
	var changes []Change
	p := profile.CertificateProfile{
		AllowedKeyAlgorithms: []string{"ECDSA", "RSA"},
		MaxValidity:          profile.Duration(DefaultMaxValidity),
		AllowedProtocols:     []string{"acme", "est", "api"},
		AllowedDNSSuffixes:   []string{domain},
		RequiresApproval:     t.RequiresManagerApproval,
	}
	if t.EnrolleeSuppliesSubject || t.EnrolleeSuppliesSAN {
		changes = append(changes, Change{Code: "requester_supplied_subject_removed",
			Detail: "The requester no longer supplies the subject: names must be DNS names under " + domain +
				", validated by the enrollment protocol; email, URI and IP names are refused."})
	} else {
		changes = append(changes, Change{Code: "names_confined_to_domain",
			Detail: "Names must be DNS names under " + domain + "; email, URI and IP names are refused."})
	}
	ekus, removed := modernEKUs(t.EKUs)
	p.AllowedEKUs = ekus
	for _, oid := range removed {
		changes = append(changes, Change{Code: "eku_removed", Detail: removedEKUDetail(oid)})
	}
	if len(t.EKUs) == 0 {
		changes = append(changes, Change{Code: "any_purpose_narrowed",
			Detail: "The template set no extended key usage, which AD CS treats as any purpose; the profile allows serverAuth only."})
	}
	if t.RequiresManagerApproval {
		changes = append(changes, Change{Code: "manager_approval_kept",
			Detail: "Manager approval becomes the profile's dual control: issuance under it needs an approver."})
	}
	if t.ExportableKey {
		changes = append(changes, Change{Code: "exportable_key_dropped",
			Detail: "Key export does not apply: ACME and EST requesters generate and keep their own key, and trstctl never holds it."})
	}
	if len(t.EnrollmentPrincipals) > 0 {
		principals := append([]string(nil), t.EnrollmentPrincipals...)
		sort.Strings(principals)
		changes = append(changes, Change{Code: "enrollment_rights_replaced",
			Detail: "Directory enrollment rights (" + strings.Join(principals, ", ") + ") are replaced by trstctl roles and protocol authentication."})
	}
	changes = append(changes, Change{Code: "validity_shortened",
		Detail: "Certificates are valid for at most 90 days and renew by protocol."})
	return Modernization{Profile: p, Changes: changes}, nil
}

// modernEKUs keeps server and client authentication and removes the usages
// that authenticate to the domain itself or enroll on behalf of others.
func modernEKUs(oids []string) (kept []string, removed []string) {
	if len(oids) == 0 {
		return []string{"serverAuth"}, nil
	}
	seen := map[string]bool{}
	for _, oid := range oids {
		switch oid {
		case ekuServerAuth:
			if !seen["serverAuth"] {
				kept = append(kept, "serverAuth")
				seen["serverAuth"] = true
			}
		case adcs.EKUClientAuth:
			if !seen["clientAuth"] {
				kept = append(kept, "clientAuth")
				seen["clientAuth"] = true
			}
		default:
			removed = append(removed, oid)
		}
	}
	if len(kept) == 0 {
		kept = []string{"serverAuth"}
	}
	sort.Strings(kept)
	sort.Strings(removed)
	return kept, removed
}

func removedEKUDetail(oid string) string {
	switch oid {
	case adcs.EKUAnyPurpose:
		return "Removed Any Purpose (" + oid + "): a certificate may only be used for what the profile names."
	case adcs.EKUCertificateRequestAgent:
		return "Removed Certificate Request Agent (" + oid + "): no certificate from this profile can enroll on behalf of others."
	case adcs.EKUSmartcardLogon:
		return "Removed Smart Card Logon (" + oid + "): certificates from this profile cannot log on to the domain."
	case adcs.EKUPKINITClientAuth:
		return "Removed PKINIT client authentication (" + oid + "): certificates from this profile cannot obtain Kerberos tickets."
	default:
		return "Removed extended key usage " + oid + ": the profile allows server and client authentication only."
	}
}

// ProfileName proposes a profile name for a template: lower case, letters,
// digits and dashes, prefixed so it reads as derived.
func ProfileName(template string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(template) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > 48 {
		name = strings.Trim(name[:48], "-")
	}
	if name == "" {
		name = "template"
	}
	return "adcs-" + name + "-modern"
}
