package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

func TestServedEnterpriseSupportCAPMODEL04EndToEnd(t *testing.T) {
	community := newServedHarness(t, config.Protocols{})
	communityToken := seedScopedToken(t, community.store, community.tenant, "access:read")
	status, body := doBearer(t, community.ts, http.MethodGet, "/api/v1/support/enterprise", communityToken, "", nil)
	if status != http.StatusOK {
		t.Fatalf("community enterprise support status = %d body %s", status, body)
	}
	var communityStatus struct {
		Served       bool   `json:"served"`
		Capability   string `json:"capability"`
		Tier         string `json:"tier"`
		SupportMode  string `json:"support_mode"`
		SupportTiers []struct {
			ID          string `json:"id"`
			LicenseMode string `json:"license_mode"`
		} `json:"support_tiers"`
	}
	if err := json.Unmarshal(body, &communityStatus); err != nil {
		t.Fatalf("decode community enterprise support status: %v", err)
	}
	if !communityStatus.Served || communityStatus.Capability != "CAP-MODEL-04" ||
		communityStatus.Tier != string(license.TierCommunity) || communityStatus.SupportMode != string(license.ModeOff) ||
		len(communityStatus.SupportTiers) != 2 {
		t.Fatalf("community enterprise support status = %+v", communityStatus)
	}
	for _, tier := range communityStatus.SupportTiers {
		if tier.LicenseMode != string(license.ModeOff) {
			t.Fatalf("community support tier %s license_mode = %q, want off", tier.ID, tier.LicenseMode)
		}
	}

	enterprise := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.License = testEnterpriseSupportLicenseManager(t)
	})
	enterpriseToken := seedScopedToken(t, enterprise.store, enterprise.tenant, "access:read")
	status, body = doBearer(t, enterprise.ts, http.MethodGet, "/api/v1/support/enterprise", enterpriseToken, "", nil)
	if status != http.StatusOK {
		t.Fatalf("enterprise support status = %d body %s", status, body)
	}
	var served struct {
		Served           bool     `json:"served"`
		Capability       string   `json:"capability"`
		Tier             string   `json:"tier"`
		LicenseState     string   `json:"license_state"`
		SupportMode      string   `json:"support_mode"`
		LicenseFeature   string   `json:"license_feature"`
		ContractBoundary string   `json:"contract_boundary"`
		EvidenceRefs     []string `json:"evidence_refs"`
		SupportTiers     []struct {
			ID                 string `json:"id"`
			Name               string `json:"name"`
			Coverage           string `json:"coverage"`
			InitialResponseSLA string `json:"initial_response_sla"`
			UpdateCadenceSLA   string `json:"update_cadence_sla"`
			Escalation         string `json:"escalation"`
			LicenseMode        string `json:"license_mode"`
			ContractBoundary   string `json:"contract_boundary"`
		} `json:"support_tiers"`
		SLATargets []struct {
			Severity           string `json:"severity"`
			AppliesTo          string `json:"applies_to"`
			InitialResponseSLA string `json:"initial_response_sla"`
			UpdateCadenceSLA   string `json:"update_cadence_sla"`
			TargetRestore      string `json:"target_restore"`
			Escalation         string `json:"escalation"`
		} `json:"sla_targets"`
		ProfessionalServices []struct {
			ID              string   `json:"id"`
			Name            string   `json:"name"`
			EngagementModel string   `json:"engagement_model"`
			Deliverables    []string `json:"deliverables"`
		} `json:"professional_services"`
	}
	if err := json.Unmarshal(body, &served); err != nil {
		t.Fatalf("decode enterprise support status: %v", err)
	}
	if !served.Served || served.Capability != "CAP-MODEL-04" || served.Tier != string(license.TierEnterprise) ||
		served.LicenseState != string(license.StateActive) || served.SupportMode != string(license.ModeEnabled) ||
		served.LicenseFeature != string(license.FeatureHASupport) {
		t.Fatalf("enterprise support status = %+v", served)
	}
	if served.ContractBoundary == "" || len(served.EvidenceRefs) < 4 {
		t.Fatalf("enterprise support contract/evidence missing: %+v", served)
	}
	assertEnterpriseSupportTier(t, served.SupportTiers, "business-hours")
	assertEnterpriseSupportTier(t, served.SupportTiers, "24x7-production")
	assertEnterpriseSLATarget(t, served.SLATargets, "P1")
	assertEnterpriseSLATarget(t, served.SLATargets, "P2")
	assertEnterpriseSLATarget(t, served.SLATargets, "P3")
	assertProfessionalService(t, served.ProfessionalServices, "deployment-architecture")
	assertProfessionalService(t, served.ProfessionalServices, "migration-readiness")
	assertProfessionalService(t, served.ProfessionalServices, "incident-retainer")
}

func assertEnterpriseSupportTier(t *testing.T, tiers []struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Coverage           string `json:"coverage"`
	InitialResponseSLA string `json:"initial_response_sla"`
	UpdateCadenceSLA   string `json:"update_cadence_sla"`
	Escalation         string `json:"escalation"`
	LicenseMode        string `json:"license_mode"`
	ContractBoundary   string `json:"contract_boundary"`
}, id string) {
	t.Helper()
	for _, tier := range tiers {
		if tier.ID != id {
			continue
		}
		if tier.Name == "" || tier.Coverage == "" || tier.InitialResponseSLA == "" || tier.UpdateCadenceSLA == "" ||
			tier.Escalation == "" || tier.LicenseMode != string(license.ModeEnabled) || tier.ContractBoundary == "" {
			t.Fatalf("support tier %s incomplete: %+v", id, tier)
		}
		return
	}
	t.Fatalf("support tier %s missing from %+v", id, tiers)
}

func assertEnterpriseSLATarget(t *testing.T, targets []struct {
	Severity           string `json:"severity"`
	AppliesTo          string `json:"applies_to"`
	InitialResponseSLA string `json:"initial_response_sla"`
	UpdateCadenceSLA   string `json:"update_cadence_sla"`
	TargetRestore      string `json:"target_restore"`
	Escalation         string `json:"escalation"`
}, severity string) {
	t.Helper()
	for _, target := range targets {
		if target.Severity != severity {
			continue
		}
		if target.AppliesTo == "" || target.InitialResponseSLA == "" || target.UpdateCadenceSLA == "" ||
			target.TargetRestore == "" || target.Escalation == "" {
			t.Fatalf("SLA target %s incomplete: %+v", severity, target)
		}
		return
	}
	t.Fatalf("SLA target %s missing from %+v", severity, targets)
}

func assertProfessionalService(t *testing.T, services []struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	EngagementModel string   `json:"engagement_model"`
	Deliverables    []string `json:"deliverables"`
}, id string) {
	t.Helper()
	for _, service := range services {
		if service.ID != id {
			continue
		}
		if service.Name == "" || service.EngagementModel == "" || len(service.Deliverables) < 3 {
			t.Fatalf("professional service %s incomplete: %+v", id, service)
		}
		return
	}
	t.Fatalf("professional service %s missing from %+v", id, services)
}

func testEnterpriseSupportLicenseManager(t *testing.T) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate license key: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V:         1,
		ID:        "lic_test_enterprise_support",
		Customer:  "Enterprise Support Customer",
		Tier:      license.TierEnterprise,
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatalf("sign enterprise support license: %v", err)
	}
	path := filepath.Join(t.TempDir(), "enterprise-support-license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write enterprise support license: %v", err)
	}
	mgr, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatalf("load enterprise support license: %v", err)
	}
	return mgr
}
