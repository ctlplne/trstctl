// SPDX-License-Identifier: BUSL-1.1

package profile_test

import (
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/profile"
)

// CR-052: a profile that lists no extended key usages allows TLS server and
// client authentication only (it used to allow any usage the CSR asked for),
// and no profile ever allows ocspSigning or anyExtendedKeyUsage. Those are
// refused when a profile is written and, for a profile stored before this
// check, at issuance.
func TestProfileEKUsDefaultToTLSAndNeverAllowOCSPSigningOrAny(t *testing.T) {
	req := func(ekus ...string) profile.Request {
		return profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: ekus, Protocol: "acme"}
	}
	empty := profile.CertificateProfile{Name: "internal", Version: 1}
	for _, eku := range []string{"serverAuth", "clientAuth"} {
		if err := empty.Validate(req(eku)); err != nil {
			t.Errorf("a profile listing no extended key usages refused %q: %v", eku, err)
		}
	}
	for _, eku := range []string{"codeSigning", "emailProtection", "timeStamping", "ocspSigning", "any", "1.3.6.1.5.5.7.3.9"} {
		if err := empty.Validate(req(eku)); err == nil {
			t.Errorf("a profile listing no extended key usages allowed %q", eku)
		}
	}
	if !empty.AllowsServerAuth() {
		t.Error("a profile listing no extended key usages does not allow serverAuth")
	}

	for _, forbidden := range []string{"ocspSigning", "any", "OCSPSigning", "1.3.6.1.5.5.7.3.9", "oid:2.5.29.37.0"} {
		listed := profile.CertificateProfile{Name: "listed", Version: 1, AllowedEKUs: []string{"serverAuth", forbidden}}
		if err := listed.ValidateDefinition(); err == nil {
			t.Errorf("a profile listing %q was accepted", forbidden)
		}
		spec, err := json.Marshal(listed)
		if err != nil {
			t.Fatal(err)
		}
		if err := profile.ValidateSpec(spec); err == nil {
			t.Errorf("a stored spec listing %q was accepted", forbidden)
		}
		// A profile stored before this check refuses issuance outright.
		if err := listed.Validate(req("serverAuth")); err == nil {
			t.Errorf("a stored profile listing %q still issued", forbidden)
		}
		if err := listed.Validate(req(forbidden)); err == nil {
			t.Errorf("a stored profile issued %q", forbidden)
		}
	}

	smime := profile.CertificateProfile{Name: "smime", Version: 1, AllowedEKUs: []string{"emailProtection"}}
	if err := smime.ValidateDefinition(); err != nil {
		t.Fatalf("an emailProtection profile was refused: %v", err)
	}
	if err := smime.Validate(req("emailProtection")); err != nil {
		t.Fatalf("an emailProtection request was refused under its profile: %v", err)
	}
	if err := smime.Validate(req("serverAuth")); err == nil {
		t.Fatal("an emailProtection profile allowed serverAuth")
	}
}

// CR-052: the platform issuing CA signs no timeStamping leaf (its own TSA
// certificate anchors the audit trail). The profile decision refuses it before
// signing, as a profile refusal; a tenant-managed CA may issue it.
func TestPlatformCAProfileDecisionRefusesTimeStamping(t *testing.T) {
	stamp := profile.CertificateProfile{Name: "stamp", Version: 1, AllowedEKUs: []string{"timeStamping"}}
	if err := stamp.ValidateDefinition(); err != nil {
		t.Fatalf("a timeStamping profile (for a tenant-managed CA) was refused: %v", err)
	}
	for _, eku := range []string{"timeStamping", "TimeStamping", "1.3.6.1.5.5.7.3.8", "oid:1.3.6.1.5.5.7.3.8"} {
		withEKU := profile.CertificateProfile{Name: "stamp", Version: 1, AllowedEKUs: []string{eku}}
		err := withEKU.Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: []string{eku}, PlatformCA: true})
		var refusal *profile.Refusal
		if !errors.As(err, &refusal) {
			t.Errorf("the platform CA's decision on %q = %v, want a profile refusal", eku, err)
		}
		if err := withEKU.Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: []string{eku}}); err != nil {
			t.Errorf("a tenant-managed CA's decision on %q refused it: %v", eku, err)
		}
	}
}
