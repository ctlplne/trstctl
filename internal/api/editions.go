// SPDX-License-Identifier: BUSL-1.1

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
	CommercialPosture                 string                  `json:"commercial_posture"`
	BundledNonProductionDeployments   int                     `json:"bundled_non_production_deployments"`
	NonProductionSupportPosture       string                  `json:"non_production_support_posture"`
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

func (a *API) getEditions(w http.ResponseWriter, r *http.Request) {
	// Public route, and an unusually expensive one: it runs a cryptographic
	// power-on self-test per request. Unauthenticated callers must not be able to
	// drive that at line rate, so the abuse check runs before the self-test rather
	// than after it.
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
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
		CategoryLabel:                     "Machine Identity Security Control Plane",
		Positioning:                       "One control plane for machine credentials, secrets, SSH certificates, X.509, API tokens, and SPIFFE workload identities.",
		BillableUnit:                      usage.BillingUnitControlPlane,
		ProviderBillingUnit:               usage.BillingUnitManagedCustomerBand,
		NoPerCertificateBilling:           true,
		NoEphemeralIdentityBilling:        true,
		CertificateCountersClassification: usage.MeterOperationalTelemetry,
		ManagedBoundary:                   "Provider/MSP normally runs one shared control plane with multiple customer tenants, with dedicated customer deployments available when its security posture requires them.",
		CommercialPosture:                 "Free is the self-hosted BUSL-1.1 core; no signed license is needed. Enterprise and Provider are commercial: their terms are not published yet and are agreed per customer, and a Provider sets its own downstream terms.",
		BundledNonProductionDeployments:   license.BundledNonProductionDeployments,
		NonProductionSupportPosture:       "Each Enterprise or Provider entitlement bundles three explicitly bound non-production control planes with the full licensed feature set and no production SLA.",
		EvidenceRail: []string{
			"live eval receipts",
			"served NHI route coverage",
			"OWASP NHI mapping",
			"current limitations",
		},
		Editions: []editionPackagingEntry{
			{
				ID:              "community",
				Name:            "Free",
				Column:          "Free",
				BuyerFit:        "single organization operating its own credential control plane",
				LicenseBoundary: "free core; no commercial license file required",
				Billing:         "no license meter; no per-certificate or ephemeral-identity billing",
				Included:        []string{"core protocols", "event spine", "PostgreSQL RLS tenancy", "audit/export", "remediation", "PQC", "offline license verifier"},
			},
			{
				ID:              "enterprise",
				Name:            "Enterprise self-host",
				Column:          "Enterprise",
				BuyerFit:        "regulated or scaled operators that need assurance, governance, BYOK, and support",
				LicenseBoundary: "offline signed Enterprise license",
				Billing:         "one production control-plane deployment; three explicitly bound non-production deployments included",
				Included:        []string{"FIPS-capable artifact posture", "BYOK", "governance", "tenant SAML/LDAP/SCIM (Enterprise SSO)", "audit anchoring, retention, and compliance packaging", "enterprise support"},
			},
			{
				ID:              "provider",
				Name:            "Provider / MSP",
				Column:          "Provider / MSP",
				BuyerFit:        "MSPs operating trstctl for customers from a shared control plane or dedicated deployments",
				LicenseBoundary: "offline signed Provider license",
				Billing:         "managed-customer band; the MSP sets its own downstream hosting, support, and terms",
				Included:        []string{"all Enterprise features", "provider plane", "metering", "white label", "siloed isolation", "managed-service rights", "resale rights"},
			},
		},
		Meters: usage.MeterDefinitions(),
	}
}
