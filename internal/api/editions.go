package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/usage"
)

type editionsResponse struct {
	license.Info
	FIPS      fipsPostureResponse      `json:"fips"`
	Packaging editionPackagingResponse `json:"packaging"`
}

type fipsPostureResponse struct {
	crypto.FIPSStatus
	CapabilityID                 string                                    `json:"capability_id"`
	ValidatedModulePath          bool                                      `json:"validated_module_path"`
	Standard                     string                                    `json:"standard"`
	Module                       string                                    `json:"module"`
	BuildTarget                  string                                    `json:"build_target"`
	RuntimeActivation            []string                                  `json:"runtime_activation"`
	CIGate                       string                                    `json:"ci_gate"`
	CryptoBoundary               string                                    `json:"crypto_boundary"`
	ProductCertificationResidual string                                    `json:"product_certification_residual"`
	RegulatedDeploymentProfile   compliance.FIPSRegulatedDeploymentProfile `json:"regulated_deployment_profile"`
}

type editionPackagingResponse struct {
	CategoryLabel                     string                  `json:"category_label"`
	Positioning                       string                  `json:"positioning"`
	BillableUnit                      string                  `json:"billable_unit"`
	ProviderBillingUnit               string                  `json:"provider_billing_unit"`
	NoPerCertificateBilling           bool                    `json:"no_per_certificate_billing"`
	NoEphemeralIdentityBilling        bool                    `json:"no_ephemeral_identity_billing"`
	CertificateCountersClassification string                  `json:"certificate_counters_classification"`
	ManagedBoundary                   string                  `json:"managed_boundary"`
	PricingPosture                    string                  `json:"pricing_posture"`
	EvidenceRail                      []string                `json:"evidence_rail"`
	Editions                          []editionPackagingEntry `json:"editions"`
	Meters                            []usage.MeterDefinition `json:"meters"`
}

type editionPackagingEntry struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Column          string   `json:"column"`
	BuyerFit        string   `json:"buyer_fit"`
	LicenseBoundary string   `json:"license_boundary"`
	Billing         string   `json:"billing"`
	Included        []string `json:"included"`
}

func (a *API) licenseManager() *license.Manager {
	if a != nil && a.license != nil {
		return a.license
	}
	return license.Community()
}

func (a *API) getEditions(w http.ResponseWriter, _ *http.Request) {
	fips, err := crypto.PowerOnSelfTest(false)
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "crypto power-on self-test failed"))
		return
	}
	a.writeJSON(w, http.StatusOK, editionsResponse{
		Info:      a.licenseManager().Info(),
		FIPS:      fipsPosture(fips),
		Packaging: editionPackaging(),
	})
}

func fipsPosture(status crypto.FIPSStatus) fipsPostureResponse {
	return fipsPostureResponse{
		FIPSStatus:          status,
		CapabilityID:        "CAP-KEY-03",
		ValidatedModulePath: true,
		Standard:            "FIPS 140-3",
		Module:              "Go Cryptographic Module",
		BuildTarget:         "make fips-build",
		RuntimeActivation: []string{
			"GOFIPS140=" + compliance.DefaultFIPSGoModuleSelector,
			"GOFIPS140=latest override for compatibility testing only",
			"GODEBUG=fips140=on",
			"--fips / TRSTCTL_FIPS=1 fail-closed startup assertion",
		},
		CIGate:                       "fips-capable build (GOFIPS140)",
		CryptoBoundary:               "internal/crypto (AN-3) is the only package that imports crypto/*; control-plane and signer code call it through boundary interfaces",
		ProductCertificationResidual: "The trstctl product NIST CMVP certificate and deployment-specific approved configuration remain an external residual.",
		RegulatedDeploymentProfile:   compliance.RegulatedFIPSDeploymentProfile(status),
	}
}

func editionPackaging() editionPackagingResponse {
	return editionPackagingResponse{
		CategoryLabel:                     "self-hosted non-human identity management / Machine IAM control plane",
		Positioning:                       "One control plane for machine credentials, secrets, SSH certificates, X.509, API tokens, and SPIFFE workload identities.",
		BillableUnit:                      usage.BillingUnitControlPlane,
		ProviderBillingUnit:               usage.BillingUnitManagedTenantBand,
		NoPerCertificateBilling:           true,
		NoEphemeralIdentityBilling:        true,
		CertificateCountersClassification: usage.MeterOperationalTelemetry,
		ManagedBoundary:                   "Managed is first-party operated; Provider is MSP or self-hosted provider-plane operation.",
		PricingPosture:                    "Community self-host is free to run under the source-available production grant; Enterprise, Provider, and Managed package by deployment or managed-tenant band, never by issued certificate.",
		EvidenceRail: []string{
			"live eval receipts",
			"served NHI route coverage",
			"OWASP NHI mapping",
			"current limitations",
		},
		Editions: []editionPackagingEntry{
			{
				ID:              "community",
				Name:            "Community self-host",
				Column:          "Community",
				BuyerFit:        "single organization operating its own credential control plane",
				LicenseBoundary: "source-available production self-host grant",
				Billing:         "no license meter; no per-certificate or ephemeral-identity billing",
				Included:        []string{"core protocols", "event spine", "PostgreSQL RLS tenancy", "audit/export", "offline license verifier"},
			},
			{
				ID:              "enterprise",
				Name:            "Enterprise self-host",
				Column:          "Enterprise",
				BuyerFit:        "regulated or scaled operators that need assurance, governance, BYOK, and support",
				LicenseBoundary: "offline signed Enterprise license",
				Billing:         "control-plane deployment and contracted capacity band",
				Included:        []string{"FIPS-capable artifact posture", "BYOK", "governance", "remediation", "enterprise support"},
			},
			{
				ID:              "provider",
				Name:            "Provider",
				Column:          "Provider",
				BuyerFit:        "MSPs or platform teams running isolated tenants for customers or business units",
				LicenseBoundary: "offline signed Provider license",
				Billing:         "managed tenant band; certificate counters remain operational telemetry",
				Included:        []string{"provider plane", "metering", "white label", "siloed isolation"},
			},
			{
				ID:              "managed",
				Name:            "Managed",
				Column:          "Managed",
				BuyerFit:        "buyers that want trstctl operated for them with the same core control-plane lineage",
				LicenseBoundary: "first-party operated packaging, backed by the Provider control-plane path",
				Billing:         "managed tenant band with support, residency, and operating-responsibility terms",
				Included:        []string{"hosted tenant provisioning", "support boundary", "data-residency boundary", "operator responsibility split"},
			},
		},
		Meters: usage.MeterDefinitions(),
	}
}
