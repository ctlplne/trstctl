// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

type editionsTestResponse struct {
	license.Info
	FIPS struct {
		ModuleActive                 bool                                      `json:"module_active"`
		Required                     bool                                      `json:"required"`
		SelfTestPassed               bool                                      `json:"self_test_passed"`
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
	} `json:"fips"`
	Packaging struct {
		CategoryLabel                     string `json:"category_label"`
		BillableUnit                      string `json:"billable_unit"`
		ProviderBillingUnit               string `json:"provider_billing_unit"`
		NoPerCertificateBilling           bool   `json:"no_per_certificate_billing"`
		NoEphemeralIdentityBilling        bool   `json:"no_ephemeral_identity_billing"`
		CertificateCountersClassification string `json:"certificate_counters_classification"`
		ManagedBoundary                   string `json:"managed_boundary"`
		CommercialPosture                 string `json:"commercial_posture"`
		BundledNonProductionDeployments   int    `json:"bundled_non_production_deployments"`
		NonProductionSupportPosture       string `json:"non_production_support_posture"`
		Editions                          []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"editions"`
		Meters []struct {
			Name            string `json:"name"`
			Classification  string `json:"classification"`
			PrimaryBillable bool   `json:"primary_billable"`
		} `json:"meters"`
	} `json:"packaging"`
}

func TestEditionsEndpointReturnsCommunityAndFIPSPosture(t *testing.T) {
	var got editionsTestResponse
	getEditions(t, api.New(nil, nil, nil), &got)

	if got.Tier != license.TierCommunity || got.State != license.StateCommunity {
		t.Fatalf("community editions header = tier %s state %s", got.Tier, got.State)
	}
	assertEditionsFeature(t, got.Features, license.FeatureFIPS, license.TierEnterprise, false, license.ModeOff)
	for _, f := range got.Features {
		if f.Name == "pqc" {
			t.Fatal("editions advertise pqc as a license feature; PQC ships in the core")
		}
	}
	if got.FIPS.ModuleActive != crypto.FIPSEnabled() {
		t.Fatalf("fips.module_active=%t, want crypto.FIPSEnabled()=%t", got.FIPS.ModuleActive, crypto.FIPSEnabled())
	}
	if got.FIPS.Required {
		t.Fatal("editions posture must not turn FIPS into a runtime license requirement")
	}
	if !got.FIPS.SelfTestPassed {
		t.Fatal("editions posture must report the crypto power-on self-test result")
	}
}

func TestEditionsEndpointServesRED006PackagingDecisions(t *testing.T) {
	var got editionsTestResponse
	getCanonicalEditions(t, api.New(nil, nil, nil), &got)

	if got.Packaging.CategoryLabel != "Machine Identity Security Control Plane" {
		t.Fatalf("category label = %q", got.Packaging.CategoryLabel)
	}
	if got.Packaging.BillableUnit != "control_plane_deployment" || got.Packaging.ProviderBillingUnit != "managed_customer_band" {
		t.Fatalf("unexpected billable units: %+v", got.Packaging)
	}
	if !got.Packaging.NoPerCertificateBilling || !got.Packaging.NoEphemeralIdentityBilling {
		t.Fatalf("RED-006 no-per-cert/no-ephemeral policy not served: %+v", got.Packaging)
	}
	if got.Packaging.CertificateCountersClassification != "operational_telemetry" {
		t.Fatalf("certificate counter classification = %q", got.Packaging.CertificateCountersClassification)
	}
	if !strings.Contains(strings.ToLower(got.Packaging.ManagedBoundary), "shared control plane") ||
		!strings.Contains(strings.ToLower(got.Packaging.ManagedBoundary), "dedicated") {
		t.Fatalf("provider deployment flexibility is not published: %q", got.Packaging.ManagedBoundary)
	}
	if !strings.Contains(strings.ToLower(got.Packaging.CommercialPosture), "not published") ||
		!strings.Contains(strings.ToLower(got.Packaging.CommercialPosture), "downstream") {
		t.Fatalf("commercial posture must say terms are unpublished and downstream terms are the MSP's: %q", got.Packaging.CommercialPosture)
	}
	if strings.Contains(got.Packaging.CommercialPosture, "USD") || strings.Contains(got.Packaging.CommercialPosture, "$") {
		t.Fatalf("no prices are published; got %q", got.Packaging.CommercialPosture)
	}
	if len(got.Packaging.Editions) != 3 {
		t.Fatalf("license packaging must have exactly Free, Enterprise, and Provider/MSP, got %+v", got.Packaging.Editions)
	}
	for _, want := range []string{"community", "enterprise", "provider"} {
		if !hasEditionID(got.Packaging.Editions, want) {
			t.Fatalf("packaging editions missing %q: %+v", want, got.Packaging.Editions)
		}
	}
	for _, meter := range got.Packaging.Meters {
		if strings.Contains(meter.Name, "certificates_") && (meter.PrimaryBillable || meter.Classification != "operational_telemetry") {
			t.Fatalf("certificate meter must be operational telemetry, not primary billable: %+v", meter)
		}
	}
}

func TestEditionsEndpointServesCAPKEY03ValidatedModulePath(t *testing.T) {
	var got editionsTestResponse
	getCanonicalEditions(t, api.New(nil, nil, nil), &got)

	if got.FIPS.CapabilityID != "CAP-KEY-03" {
		t.Fatalf("fips.capability_id=%q, want CAP-KEY-03", got.FIPS.CapabilityID)
	}
	if !got.FIPS.ValidatedModulePath {
		t.Fatalf("fips.validated_module_path=false; FIPS validated-module path is not served: %+v", got.FIPS)
	}
	for _, want := range []string{
		"FIPS 140-3",
		"Go Cryptographic Module",
		"make fips-build",
		"GOFIPS140=" + compliance.DefaultFIPSGoModuleSelector,
		"fips-capable build (GOFIPS140)",
	} {
		if !fipsPostureContains(got.FIPS, want) {
			t.Fatalf("served FIPS posture missing %q: %+v", want, got.FIPS)
		}
	}
	if !fipsPostureContains(got.FIPS, "internal/crypto") {
		t.Fatalf("served FIPS posture must identify the AN-3 crypto boundary: %+v", got.FIPS)
	}
	residual := strings.ToLower(got.FIPS.ProductCertificationResidual)
	if !strings.Contains(residual, "product nist cmvp certificate") || !strings.Contains(residual, "external residual") {
		t.Fatalf("served FIPS posture must keep product CMVP certification as an external residual, got %q", got.FIPS.ProductCertificationResidual)
	}
	if err := compliance.ValidateFIPSRegulatedDeploymentProfile(got.FIPS.RegulatedDeploymentProfile); err != nil {
		t.Fatalf("served FIPS regulated deployment profile is not auditor-usable: %v", err)
	}
	if got.FIPS.RegulatedDeploymentProfile.GoFIPSModuleSelector != compliance.DefaultFIPSGoModuleSelector {
		t.Fatalf("served FIPS profile selector=%q, want %q", got.FIPS.RegulatedDeploymentProfile.GoFIPSModuleSelector, compliance.DefaultFIPSGoModuleSelector)
	}
	for _, alg := range []crypto.Algorithm{crypto.Ed25519} {
		if compliance.FIPSApprovedUnderRegulatedProfile(alg) {
			t.Fatalf("%s must be fenced out of the served regulated FIPS profile", alg)
		}
	}
}

func TestEditionsEndpointReturnsLoadedLicense(t *testing.T) {
	mgr := testLicenseManager(t, license.TierEnterprise)
	var got editionsTestResponse
	getEditions(t, api.New(nil, nil, nil, api.WithLicense(mgr)), &got)

	if got.Tier != license.TierEnterprise || got.State != license.StateActive {
		t.Fatalf("licensed editions header = tier %s state %s", got.Tier, got.State)
	}
	if got.Customer != "Acme Robotics" || got.LicenseID != "lic_test_editions" {
		t.Fatalf("licensed identity fields missing: %+v", got.Info)
	}
	assertEditionsFeature(t, got.Features, license.FeatureFIPS, license.TierEnterprise, true, license.ModeEnabled)
}

func TestAUD56EditionsEndpointServesEffectiveNonProductionEntitlementAndPriceBands(t *testing.T) {
	mgr := testBoundLicenseManager(t, license.EnvironmentNonProduction, "acme-stage")
	var got editionsTestResponse
	getCanonicalEditions(t, api.New(nil, nil, nil, api.WithLicense(mgr)), &got)

	posture := got.DeploymentEntitlement
	if posture == nil {
		t.Fatal("deployment_entitlement is absent")
	}
	if posture.Environment != license.EnvironmentNonProduction || posture.DeploymentID != "acme-stage" {
		t.Fatalf("effective deployment identity = %+v", posture)
	}
	if posture.ProductionUnitsConsumed != 0 || posture.BundledNonProductionDeployments != 3 || posture.NonProductionSlotsRemaining != 2 {
		t.Fatalf("non-production consumption posture = %+v", posture)
	}
	if got.Packaging.BundledNonProductionDeployments != 3 || !strings.Contains(strings.ToLower(got.Packaging.NonProductionSupportPosture), "no production sla") {
		t.Fatalf("packaging non-production promise = %+v", got.Packaging)
	}
}

func getEditions(t *testing.T, h http.Handler, out *editionsTestResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/editions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/editions = %d, body %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode editions response: %v", err)
	}
}

func getCanonicalEditions(t *testing.T, h http.Handler, out *editionsTestResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/editions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/editions = %d, body %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode editions response: %v", err)
	}
}

func fipsPostureContains(fips struct {
	ModuleActive                 bool                                      `json:"module_active"`
	Required                     bool                                      `json:"required"`
	SelfTestPassed               bool                                      `json:"self_test_passed"`
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
}, want string) bool {
	lowWant := strings.ToLower(want)
	for _, candidate := range append([]string{
		fips.Standard,
		fips.Module,
		fips.BuildTarget,
		fips.CIGate,
		fips.CryptoBoundary,
		fips.ProductCertificationResidual,
	}, fips.RuntimeActivation...) {
		if strings.Contains(strings.ToLower(candidate), lowWant) {
			return true
		}
	}
	return false
}

func testLicenseManager(t *testing.T, tier license.Tier) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V:         1,
		ID:        "lic_test_editions",
		Customer:  "Acme Robotics",
		Tier:      tier,
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func testBoundLicenseManager(t *testing.T, environment license.Environment, deploymentID string) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V: 2, ID: "lic_aud56", Customer: "Acme Robotics", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		DeploymentEntitlement: &license.DeploymentEntitlement{
			ProductionDeploymentID:     "acme-prod",
			NonProductionDeploymentIDs: []string{"acme-stage"},
			NonProductionAllowance:     license.BundledNonProductionDeployments,
		},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := license.LoadForDeployment(path, [][]byte{pub}, license.DeploymentIdentity{ID: deploymentID, Environment: environment})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func assertEditionsFeature(t *testing.T, features []license.FeatureInfo, name license.Feature, tier license.Tier, licensed bool, mode license.Mode) {
	t.Helper()
	for _, f := range features {
		if f.Name == name {
			if f.Tier != tier || f.Licensed != licensed || f.Mode != mode {
				t.Fatalf("feature %s row = %+v, want tier=%s licensed=%t mode=%s", name, f, tier, licensed, mode)
			}
			return
		}
	}
	t.Fatalf("feature %s row missing from %+v", name, features)
}

func hasEditionID(editions []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}, want string) bool {
	for _, edition := range editions {
		if edition.ID == want {
			return true
		}
	}
	return false
}
