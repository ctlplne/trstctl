// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestFIPSRegulatedDeploymentProfilePinsModuleAndFencesCoreNonApprovedAlgorithms(t *testing.T) {
	profile := RegulatedFIPSDeploymentProfile(crypto.FIPSStatus{
		ModuleActive:   true,
		SelfTestPassed: true,
	})
	if err := ValidateFIPSRegulatedDeploymentProfile(profile); err != nil {
		t.Fatalf("regulated FIPS profile did not validate: %v", err)
	}
	if profile.GoFIPSModuleSelector != DefaultFIPSGoModuleSelector {
		t.Fatalf("go_fips_module_selector=%q, want %q", profile.GoFIPSModuleSelector, DefaultFIPSGoModuleSelector)
	}
	if profile.GoFIPSModuleSelector == "latest" {
		t.Fatal("regulated FIPS profile must pin a concrete Go FIPS module selector, not latest")
	}
	for _, alg := range []crypto.Algorithm{crypto.ECDSAP256, crypto.ECDSAP384, crypto.RSA2048, crypto.RSA4096} {
		if !FIPSApprovedUnderRegulatedProfile(alg) {
			t.Fatalf("%s should be approved under the regulated FIPS profile", alg)
		}
	}
	for _, alg := range []crypto.Algorithm{crypto.Ed25519} {
		if FIPSApprovedUnderRegulatedProfile(alg) {
			t.Fatalf("%s should be fenced out of approved-mode FIPS issuance", alg)
		}
	}
	for _, family := range []string{"Ed25519"} {
		if !profileFenceContains(profile, family) {
			t.Fatalf("regulated FIPS profile is missing a non-FIPS fence for %s: %+v", family, profile.NonFIPSFences)
		}
	}
}

func TestFIPSRegulatedDeploymentProfileRecordsHSMKMSValidationCertificates(t *testing.T) {
	profile := RegulatedFIPSDeploymentProfile(crypto.FIPSStatus{SelfTestPassed: true})
	for _, provider := range []string{
		"Go Cryptographic Module",
		"AWS KMS / AWS CloudHSM",
		"Azure Key Vault Managed HSM",
		"Google Cloud KMS / Cloud HSM",
		"PKCS#11 HSM",
	} {
		cert, ok := profileCertificateForProvider(profile, provider)
		if !ok {
			t.Fatalf("regulated FIPS profile missing certificate requirement for %s: %+v", provider, profile.HSMKMSValidationCertificates)
		}
		if cert.CertificateRef == "" || cert.ValidationScope == "" || !cert.RequiredForApprovedMode {
			t.Fatalf("certificate requirement for %s is not auditor-usable: %+v", provider, cert)
		}
		if cert.Status == "" || !strings.Contains(cert.Status, "operator_required") {
			t.Fatalf("certificate requirement for %s must make the operator residual explicit: %+v", provider, cert)
		}
	}
}

func TestFIPSRegulatedDeploymentProfileRejectsFloatingLatestSelector(t *testing.T) {
	profile := RegulatedFIPSDeploymentProfile(crypto.FIPSStatus{SelfTestPassed: true})
	profile.GoFIPSModuleSelector = "latest"
	if err := ValidateFIPSRegulatedDeploymentProfile(profile); err == nil {
		t.Fatal("ValidateFIPSRegulatedDeploymentProfile accepted a floating latest selector")
	}
}

func profileFenceContains(profile FIPSRegulatedDeploymentProfile, want string) bool {
	for _, fence := range profile.NonFIPSFences {
		for _, alg := range fence.Algorithms {
			if strings.Contains(alg, want) {
				return true
			}
		}
	}
	return false
}

func profileCertificateForProvider(profile FIPSRegulatedDeploymentProfile, provider string) (FIPSCustodyValidationCertificate, bool) {
	for _, cert := range profile.HSMKMSValidationCertificates {
		if cert.Provider == provider {
			return cert, true
		}
	}
	return FIPSCustodyValidationCertificate{}, false
}
