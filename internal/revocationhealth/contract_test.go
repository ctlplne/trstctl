// SPDX-License-Identifier: BUSL-1.1

package revocationhealth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateObservedRejectsUnverifiedAuthorityAndContradictoryEvidence(t *testing.T) {
	next := time.Now().UTC().Add(time.Hour)
	target := Target{
		Key:                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Protocol:               ProtocolCRL,
		Endpoint:               "https://pki.example.test/root.crl",
		IssuerSubject:          "CN=Root CA",
		CertificateID:          "certificate-1",
		CertificateSubject:     "CN=service.example.test",
		CertificateFingerprint: "leaf-fingerprint",
		CertificateSerial:      "01",
	}
	observed := Observed{
		ProbeID: uuid.NewString(), Bucket: "2026-08-12T10:00:00Z", BatchIndex: 1, BatchCount: 1,
		AgentID: uuid.NewString(), AgentName: "relay-1",
		EvidenceDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Targets:        []Target{target},
		Findings: []Finding{{
			TargetKey: target.Key, Protocol: target.Protocol, Endpoint: target.Endpoint,
			Status: StatusFresh, DetailCode: "fresh", SignatureVerified: true, NextUpdate: &next,
		}},
	}
	if err := ValidateObserved(observed); err != nil {
		t.Fatalf("valid signed observation rejected: %v", err)
	}

	missingAuthority := observed
	missingAuthority.AgentID = ""
	if err := ValidateObserved(missingAuthority); err == nil {
		t.Fatal("observation without verified agent authority accepted")
	}

	contradictory := observed
	contradictory.Findings = append([]Finding(nil), observed.Findings...)
	contradictory.Findings[0].SignatureVerified = false
	if err := ValidateObserved(contradictory); err == nil {
		t.Fatal("fresh observation without a verified signature accepted")
	}
}

// A107: an AD CS LDAP distribution point (often with no host) is a valid CRL
// target; a bound batch names one directory, a secret:// bind credential and
// only entries under its configuration DN.
func TestLDAPDistributionPointsAndBindings(t *testing.T) {
	const config = "CN=Configuration,DC=lab,DC=test"
	target := Target{
		Key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Protocol: ProtocolCRL,
		Endpoint:      "ldap:///CN=Lab%20CA,CN=dc1,CN=CDP,CN=Public%20Key%20Services,CN=Services," + config + "?certificateRevocationList?base?objectClass=cRLDistributionPoint",
		IssuerSubject: "CN=Lab CA", CertificateID: "certificate-1", CertificateSubject: "CN=web.lab.test",
		CertificateFingerprint: "leaf", CertificateSerial: "0a",
	}
	if err := ValidateTarget(target); err != nil {
		t.Fatalf("hostless LDAP CRL distribution point refused: %v", err)
	}
	if dn, err := LDAPEndpointDN(target.Endpoint); err != nil || dn != "CN=Lab CA,CN=dc1,CN=CDP,CN=Public Key Services,CN=Services,"+config {
		t.Fatalf("LDAP DN = %q (%v)", dn, err)
	}
	ocsp := target
	ocsp.Protocol = ProtocolOCSP
	if err := ValidateTarget(ocsp); err == nil {
		t.Fatal("an LDAP OCSP endpoint was accepted")
	}
	noDN := target
	noDN.Endpoint = "ldap:///"
	if err := ValidateTarget(noDN); err == nil {
		t.Fatal("an LDAP distribution point naming no entry was accepted")
	}
	for dn, want := range map[string]bool{
		"CN=X,CN=CDP," + config:                           true,
		"cn=x, cn=cdp, cn=configuration, dc=lab, dc=test": true,
		config:                                   true,
		"CN=X,CN=Configuration,DC=other,DC=test": false,
		"CN=X,DC=lab,DC=test":                    false,
	} {
		if got := LDAPDNWithin(dn, config); got != want {
			t.Errorf("LDAPDNWithin(%q) = %v, want %v", dn, got, want)
		}
	}
	intent := Intent{ID: uuid.NewString(), Bucket: "b", BatchIndex: 1, BatchCount: 1, Targets: []Target{target},
		RequiredAgentRole: RequiredRoleNetwork, LDAPBinding: &LDAPBinding{SourceID: uuid.NewString(), URL: "ldaps://dc1.lab.test", // #nosec G101 -- a non-secret secret:// reference fixture, not secret material (CWE-798).
			ConfigurationDN: config, BindDN: "CN=svc", PasswordRef: "secret://adcs/bind"}}
	if err := ValidateIntent(intent); err != nil {
		t.Fatalf("bound LDAP batch refused: %v", err)
	}
	for name, mutate := range map[string]func(*Intent){
		"plain credential":    func(i *Intent) { i.LDAPBinding.PasswordRef = "hunter2" },
		"https directory":     func(i *Intent) { i.LDAPBinding.URL = "https://dc1.lab.test" },
		"directory with path": func(i *Intent) { i.LDAPBinding.URL = "ldaps://dc1.lab.test/CN=x" },
		"target in another forest": func(i *Intent) {
			i.LDAPBinding.ConfigurationDN = "CN=Configuration,DC=other,DC=test"
		},
	} {
		bad := intent
		binding := *intent.LDAPBinding
		bad.LDAPBinding = &binding
		mutate(&bad)
		if err := ValidateIntent(bad); err == nil {
			t.Errorf("%s: bound batch accepted", name)
		}
	}
}
