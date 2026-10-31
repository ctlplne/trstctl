// SPDX-License-Identifier: BUSL-1.1

package adcsmodern_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/adcsmodern"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/profile"
)

// A160 Done-when, at the mapping: an ESC1-prone template (the requester
// supplies the subject, client authentication, Domain Users may enroll)
// becomes a profile that confines names to the domain, so a request naming
// someone else is refused while a request for an in-domain host passes.
func TestAnESC1TemplateBecomesAProfileWithoutTheRequesterSuppliedSubject(t *testing.T) {
	esc1 := adcs.Template{
		Name: "VulnerableUser", SchemaVersion: 2, EnrolleeSuppliesSubject: true,
		EKUs:                 []string{adcs.EKUClientAuth, adcs.EKUSmartcardLogon, adcs.EKUAnyPurpose},
		EnrollmentPrincipals: []string{`CORP\Domain Users`},
	}
	m, err := adcsmodern.Modernize(esc1, "Corp.Example.")
	if err != nil {
		t.Fatal(err)
	}
	p := m.Profile
	if strings.Join(p.AllowedDNSSuffixes, ",") != "corp.example" || strings.Join(p.AllowedEKUs, ",") != "clientAuth" {
		t.Fatalf("profile = %+v; want names confined to corp.example and clientAuth only", p)
	}
	codes := map[string]int{}
	for _, c := range m.Changes {
		codes[c.Code]++
	}
	if codes["requester_supplied_subject_removed"] != 1 || codes["eku_removed"] != 2 || codes["enrollment_rights_replaced"] != 1 {
		t.Fatalf("changes = %+v", m.Changes)
	}
	p.Name, p.Version = adcsmodern.ProfileName(esc1.Name), 1
	if err := p.ValidateDefinition(); err != nil {
		t.Fatalf("the modernized profile is not a valid definition: %v", err)
	}
	inDomain := profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: []string{"clientAuth"}, TTL: 24 * time.Hour,
		DNSNames: []string{"laptop-17.corp.example"}, Protocol: "acme"}
	if err := p.Validate(inDomain); err != nil {
		t.Fatalf("an in-domain host request was refused: %v", err)
	}
	for name, impersonation := range map[string]profile.Request{
		"another account's email": {KeyAlgorithm: "ECDSA", KeyBits: 256, TTL: 24 * time.Hour, Protocol: "acme",
			DNSNames: []string{"laptop-17.corp.example"}, EmailAddresses: []string{"administrator@corp.example"}},
		"a name outside the domain": {KeyAlgorithm: "ECDSA", KeyBits: 256, TTL: 24 * time.Hour, Protocol: "acme",
			DNSNames: []string{"dc01.other.example"}},
		"a URI identity": {KeyAlgorithm: "ECDSA", KeyBits: 256, TTL: 24 * time.Hour, Protocol: "acme",
			DNSNames: []string{"laptop-17.corp.example"}, URIs: []string{"spiffe://corp.example/admin"}},
	} {
		if err := p.Validate(impersonation); err == nil {
			t.Errorf("%s was accepted under the modernized profile", name)
		}
	}
}

func TestModernizeNarrowsAnyPurposeAndRefusesANonDomain(t *testing.T) {
	m, err := adcsmodern.Modernize(adcs.Template{Name: "Legacy Web", RequiresManagerApproval: true, ExportableKey: true}, "corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.Profile.AllowedEKUs, ",") != "serverAuth" || !m.Profile.RequiresApproval {
		t.Fatalf("profile = %+v; want serverAuth only and dual control", m.Profile)
	}
	if adcsmodern.ProfileName("Legacy Web") != "adcs-legacy-web-modern" {
		t.Fatalf("name = %q", adcsmodern.ProfileName("Legacy Web"))
	}
	for _, domain := range []string{"", "localhost", "corp_example.test", "*.corp.example"} {
		if _, err := adcsmodern.Modernize(adcs.Template{Name: "Web"}, domain); err == nil {
			t.Errorf("domain %q accepted", domain)
		}
	}
}
