// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	FIPSRegulatedProfileID       = "trstctl.fips-regulated-deployment.v1"
	DefaultFIPSGoModuleSelector  = "v1.0.0"
	FIPSRegulatedCapabilityID    = "CAP-KEY-03"
	FIPSRegulatedDeploymentBuild = "make fips-build"
)

// FIPSRegulatedDeploymentProfile is the machine-readable package an auditor
// expects for an approved-mode deployment. It is evidence, not certification:
// operator/lab artifacts still decide the final CMVP claim.
type FIPSRegulatedDeploymentProfile struct {
	ProfileID                    string                             `json:"profile_id"`
	CapabilityID                 string                             `json:"capability_id"`
	Standard                     string                             `json:"standard"`
	GoFIPSModule                 string                             `json:"go_fips_module"`
	GoFIPSModuleSelector         string                             `json:"go_fips_module_selector"`
	BuildTarget                  string                             `json:"build_target"`
	RuntimeAssertions            []string                           `json:"runtime_assertions"`
	ModuleActive                 bool                               `json:"module_active"`
	SelfTestPassed               bool                               `json:"self_test_passed"`
	CryptoBoundary               string                             `json:"crypto_boundary"`
	ProductCertificationStatus   string                             `json:"product_certification_status"`
	ProductCertificationResidual string                             `json:"product_certification_residual"`
	ApprovedAlgorithms           []FIPSAlgorithmMode                `json:"approved_algorithms"`
	NonFIPSFences                []FIPSNonFIPSFence                 `json:"non_fips_fences"`
	HSMKMSValidationCertificates []FIPSCustodyValidationCertificate `json:"hsm_kms_validation_certificates"`
	OperatorRequiredArtifacts    []string                           `json:"operator_required_artifacts"`
	EvidenceRefs                 []string                           `json:"evidence_refs"`
}

type FIPSAlgorithmMode struct {
	Algorithm      string `json:"algorithm"`
	Mode           string `json:"mode"`
	Use            string `json:"use"`
	ModuleBoundary string `json:"module_boundary"`
	Approved       bool   `json:"approved"`
}

type FIPSNonFIPSFence struct {
	Surface         string   `json:"surface"`
	Algorithms      []string `json:"algorithms"`
	StatusUnderFIPS string   `json:"status_under_fips"`
	Reason          string   `json:"reason"`
	Action          string   `json:"action"`
	EvidenceRef     string   `json:"evidence_ref"`
}

type FIPSCustodyValidationCertificate struct {
	Provider                string `json:"provider"`
	Boundary                string `json:"boundary"`
	CertificateRef          string `json:"certificate_ref"`
	ValidationScope         string `json:"validation_scope"`
	Status                  string `json:"status"`
	RequiredForApprovedMode bool   `json:"required_for_approved_mode"`
}

func RegulatedFIPSDeploymentProfile(status crypto.FIPSStatus) FIPSRegulatedDeploymentProfile {
	return FIPSRegulatedDeploymentProfile{
		ProfileID:            FIPSRegulatedProfileID,
		CapabilityID:         FIPSRegulatedCapabilityID,
		Standard:             "FIPS 140-3",
		GoFIPSModule:         "Go Cryptographic Module",
		GoFIPSModuleSelector: DefaultFIPSGoModuleSelector,
		BuildTarget:          FIPSRegulatedDeploymentBuild,
		RuntimeAssertions: []string{
			"GOFIPS140=" + DefaultFIPSGoModuleSelector,
			"GODEBUG=fips140=on",
			"--fips / TRSTCTL_FIPS=1 fail-closed startup assertion",
			"ca.require_fips=true for regulated CA governance",
		},
		ModuleActive:                 status.ModuleActive,
		SelfTestPassed:               status.SelfTestPassed,
		CryptoBoundary:               "internal/crypto (AN-3) is the only package that imports crypto/*; control-plane, signer, and protocol code call it through boundary interfaces",
		ProductCertificationStatus:   "fips-capable module path; product CMVP certification external",
		ProductCertificationResidual: "The trstctl product NIST CMVP certificate, approved deployment configuration, and lab validation scope remain external artifacts until obtained.",
		ApprovedAlgorithms:           FIPSApprovedAlgorithmModes(),
		NonFIPSFences:                FIPSNonFIPSFences(),
		HSMKMSValidationCertificates: FIPSCustodyValidationCertificates(),
		OperatorRequiredArtifacts: []string{
			"NIST CMVP certificate reference for the deployed Go Cryptographic Module selector",
			"approved configuration guide for the exact trstctl artifact, flags, and operating environment",
			"HSM/KMS vendor CMVP certificate references for any external key-custody boundary",
			"signed /api/v1/compliance/evidence-packs/fips-140 export for the tenant",
			"release manifest proving make fips-build and the FIPS POST gate passed for the deployed artifact",
		},
		EvidenceRefs: []string{
			"api:GET /api/v1/editions",
			"api:GET /api/v1/compliance/evidence-packs/fips-140",
			"make:fips-build",
			"ci:fips-capable build (GOFIPS140)",
			"code:internal/crypto/fips.go",
		},
	}
}

func FIPSApprovedAlgorithmModes() []FIPSAlgorithmMode {
	return []FIPSAlgorithmMode{
		{Algorithm: "ECDSA", Mode: "P-256/SHA-256, P-384/SHA-384, P-521/SHA-512", Use: "certificate, audit, and evidence signatures", ModuleBoundary: "Go Cryptographic Module", Approved: true},
		{Algorithm: "RSA", Mode: "2048/3072/4096-bit with RSASSA-PSS or RSASSA-PKCS1-v1_5 and SHA-256/384/512", Use: "legacy protocol and JOSE/CMS signatures", ModuleBoundary: "Go Cryptographic Module", Approved: true},
		{Algorithm: "AES", Mode: "AES-256-GCM", Use: "envelope encryption, local seal, and authenticated data protection", ModuleBoundary: "Go Cryptographic Module", Approved: true},
		{Algorithm: "SHA-2", Mode: "SHA-256, SHA-384, SHA-512", Use: "digests, signatures, audit hashes, and evidence pack integrity", ModuleBoundary: "Go Cryptographic Module", Approved: true},
	}
}

func FIPSNonFIPSFences() []FIPSNonFIPSFence {
	return []FIPSNonFIPSFence{
		{
			Surface:         "internal/crypto",
			Algorithms:      []string{string(crypto.Ed25519)},
			StatusUnderFIPS: "fenced: inventory/reporting only for approved-mode deployments",
			Reason:          "Ed25519 is not an approved algorithm inside the pinned Go FIPS module boundary.",
			Action:          "Use ECDSA/RSA approved-mode profiles for FIPS issuance; keep Ed25519 credentials outside the FIPS claim.",
			EvidenceRef:     "internal/crypto/crypto.go",
		},
	}
}

func FIPSCustodyValidationCertificates() []FIPSCustodyValidationCertificate {
	return []FIPSCustodyValidationCertificate{
		{
			Provider:                "Go Cryptographic Module",
			Boundary:                "software cryptographic module",
			CertificateRef:          "operator-attached NIST CMVP certificate for selector " + DefaultFIPSGoModuleSelector,
			ValidationScope:         "standard-library crypto/* operations routed through the active Go FIPS module",
			Status:                  "operator_required",
			RequiredForApprovedMode: true,
		},
		{
			Provider:                "AWS KMS / AWS CloudHSM",
			Boundary:                "external key-custody module",
			CertificateRef:          "operator-attached AWS service or CloudHSM CMVP certificate matching the deployed region, service, and key policy",
			ValidationScope:         "non-extractable key generation, signing, and wrapping performed by the external module",
			Status:                  "operator_required_when_configured",
			RequiredForApprovedMode: true,
		},
		{
			Provider:                "Azure Key Vault Managed HSM",
			Boundary:                "external key-custody module",
			CertificateRef:          "operator-attached Azure Managed HSM CMVP certificate matching the deployed region, firmware, and policy",
			ValidationScope:         "non-extractable key generation, signing, and wrapping performed by the external module",
			Status:                  "operator_required_when_configured",
			RequiredForApprovedMode: true,
		},
		{
			Provider:                "Google Cloud KMS / Cloud HSM",
			Boundary:                "external key-custody module",
			CertificateRef:          "operator-attached Google Cloud KMS or Cloud HSM CMVP certificate matching the deployed location and key ring",
			ValidationScope:         "non-extractable key generation, signing, and wrapping performed by the external module",
			Status:                  "operator_required_when_configured",
			RequiredForApprovedMode: true,
		},
		{
			Provider:                "PKCS#11 HSM",
			Boundary:                "external key-custody module",
			CertificateRef:          "operator-attached vendor CMVP certificate matching the exact hardware, firmware, slot policy, and mechanism set",
			ValidationScope:         "non-extractable key generation, signing, and wrapping performed by the external module",
			Status:                  "operator_required_when_configured",
			RequiredForApprovedMode: true,
		},
	}
}

func FIPSApprovedUnderRegulatedProfile(algorithm crypto.Algorithm) bool {
	switch algorithm {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096, crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521:
		return true
	default:
		return false
	}
}

func ValidateFIPSRegulatedDeploymentProfile(profile FIPSRegulatedDeploymentProfile) error {
	var errs []string
	if profile.ProfileID != FIPSRegulatedProfileID {
		errs = append(errs, fmt.Sprintf("profile_id=%q, want %q", profile.ProfileID, FIPSRegulatedProfileID))
	}
	if profile.GoFIPSModuleSelector == "" || profile.GoFIPSModuleSelector == "latest" || !strings.HasPrefix(profile.GoFIPSModuleSelector, "v") {
		errs = append(errs, "go_fips_module_selector must pin a concrete vX.Y.Z module selector for the regulated profile")
	}
	if len(profile.ApprovedAlgorithms) < 4 {
		errs = append(errs, "approved algorithm/mode allowlist is incomplete")
	}
	fenced := strings.Join(fenceAlgorithmNames(profile.NonFIPSFences), " ")
	for _, family := range []string{"Ed25519"} {
		if !strings.Contains(fenced, family) {
			errs = append(errs, "non-FIPS fence missing "+family)
		}
	}
	if len(profile.HSMKMSValidationCertificates) < 5 {
		errs = append(errs, "HSM/KMS validation certificate requirements are incomplete")
	}
	for _, cert := range profile.HSMKMSValidationCertificates {
		if cert.Provider == "" || cert.CertificateRef == "" || cert.ValidationScope == "" {
			errs = append(errs, "HSM/KMS validation certificate record is missing provider, certificate_ref, or validation_scope")
			break
		}
	}
	residual := strings.ToLower(profile.ProductCertificationResidual)
	if !strings.Contains(residual, "cmvp") || !strings.Contains(residual, "external") {
		errs = append(errs, "product CMVP residual must remain explicit and external")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func fenceAlgorithmNames(fences []FIPSNonFIPSFence) []string {
	var out []string
	for _, fence := range fences {
		out = append(out, fence.Algorithms...)
	}
	return out
}
