package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/license"
)

const enterpriseSupportCapability = "CAP-MODEL-04"

type enterpriseSupportStatus struct {
	Served               bool                            `json:"served"`
	Capability           string                          `json:"capability"`
	Tier                 license.Tier                    `json:"tier"`
	LicenseState         license.State                   `json:"license_state"`
	SupportMode          license.Mode                    `json:"support_mode"`
	LicenseFeature       license.Feature                 `json:"license_feature"`
	ContractBoundary     string                          `json:"contract_boundary"`
	SupportTiers         []enterpriseSupportTier         `json:"support_tiers"`
	SLATargets           []enterpriseSupportSLATarget    `json:"sla_targets"`
	ProfessionalServices []enterpriseProfessionalService `json:"professional_services"`
	EvidenceRefs         []string                        `json:"evidence_refs"`
}

type enterpriseSupportTier struct {
	ID                 string       `json:"id"`
	Name               string       `json:"name"`
	Coverage           string       `json:"coverage"`
	InitialResponseSLA string       `json:"initial_response_sla"`
	UpdateCadenceSLA   string       `json:"update_cadence_sla"`
	Escalation         string       `json:"escalation"`
	LicenseMode        license.Mode `json:"license_mode"`
	ContractBoundary   string       `json:"contract_boundary"`
}

type enterpriseSupportSLATarget struct {
	Severity           string `json:"severity"`
	AppliesTo          string `json:"applies_to"`
	InitialResponseSLA string `json:"initial_response_sla"`
	UpdateCadenceSLA   string `json:"update_cadence_sla"`
	TargetRestore      string `json:"target_restore"`
	Escalation         string `json:"escalation"`
}

type enterpriseProfessionalService struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	EngagementModel string   `json:"engagement_model"`
	Deliverables    []string `json:"deliverables"`
}

func (a *API) getEnterpriseSupportStatus(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildEnterpriseSupportStatus(a.licenseManager()))
}

func buildEnterpriseSupportStatus(mgr *license.Manager) enterpriseSupportStatus {
	if mgr == nil {
		mgr = license.Community()
	}
	mode := mgr.Mode(license.FeatureHASupport)
	return enterpriseSupportStatus{
		Served:           true,
		Capability:       enterpriseSupportCapability,
		Tier:             mgr.Tier(),
		LicenseState:     mgr.State(),
		SupportMode:      mode,
		LicenseFeature:   license.FeatureHASupport,
		ContractBoundary: "Commercial support terms control legal SLA credits and named contacts; this served endpoint exposes the product posture and standard package catalog.",
		SupportTiers: []enterpriseSupportTier{
			{
				ID:                 "business-hours",
				Name:               "Enterprise business-hours support",
				Coverage:           "Monday-Friday regional business hours, excluding published holidays",
				InitialResponseSLA: "P1: 4 hours; P2: 1 business day; P3: 2 business days",
				UpdateCadenceSLA:   "P1: every business day; P2/P3: on material status change",
				Escalation:         "Named support engineer with security engineering escalation for credential-impacting incidents",
				LicenseMode:        mode,
				ContractBoundary:   "Requires the ha_support Enterprise feature to be enabled.",
			},
			{
				ID:                 "24x7-production",
				Name:               "Enterprise 24x7 production support",
				Coverage:           "24x7 for production outages and credential-security incidents",
				InitialResponseSLA: "P1: 1 hour; P2: 4 hours; P3: 1 business day",
				UpdateCadenceSLA:   "P1: every 4 hours until mitigated; P2: every business day; P3: on material status change",
				Escalation:         "On-call support engineer, incident commander escalation, and security engineering bridge for P1 incidents",
				LicenseMode:        mode,
				ContractBoundary:   "Requires the ha_support Enterprise feature to be enabled and a production-support order form.",
			},
		},
		SLATargets: []enterpriseSupportSLATarget{
			{
				Severity:           "P1",
				AppliesTo:          "Production outage, signer unavailability, active credential compromise, or failed revocation path",
				InitialResponseSLA: "1 hour for 24x7 production support; 4 business hours for business-hours support",
				UpdateCadenceSLA:   "Every 4 hours for 24x7 P1 incidents until mitigated",
				TargetRestore:      "Mitigation path or documented workaround; contractual restoration target is set in the support order form",
				Escalation:         "Incident commander plus security engineering escalation",
			},
			{
				Severity:           "P2",
				AppliesTo:          "Degraded issuance, delayed rotation, connector backlog, or non-critical protocol outage",
				InitialResponseSLA: "4 hours for 24x7 production support; 1 business day for business-hours support",
				UpdateCadenceSLA:   "Every business day while active",
				TargetRestore:      "Workaround, patch, or operational guidance as appropriate",
				Escalation:         "Support engineer with product engineering escalation when reproduction is confirmed",
			},
			{
				Severity:           "P3",
				AppliesTo:          "How-to questions, non-production defects, documentation gaps, and planned upgrade guidance",
				InitialResponseSLA: "1 business day for 24x7 production support; 2 business days for business-hours support",
				UpdateCadenceSLA:   "On material status change",
				TargetRestore:      "Answer, documentation patch, or backlog classification",
				Escalation:         "Support engineer triage",
			},
		},
		ProfessionalServices: []enterpriseProfessionalService{
			{
				ID:              "deployment-architecture",
				Name:            "Deployment architecture review",
				EngagementModel: "Fixed-scope design review for production rollout",
				Deliverables: []string{
					"Tenant and RLS boundary review",
					"PostgreSQL, NATS JetStream, signer isolation, backup, and disaster-recovery topology review",
					"Production readiness report with required remediations and residual risks",
				},
			},
			{
				ID:              "migration-readiness",
				Name:            "Credential migration readiness",
				EngagementModel: "Project package for PKI, SSH CA, secrets, or workload-identity migration",
				Deliverables: []string{
					"Source inventory and ownership map",
					"Migration wave plan with rollback checkpoints",
					"Operator handoff covering issuance, rotation, revocation, audit, and connector delivery paths",
				},
			},
			{
				ID:              "incident-retainer",
				Name:            "Credential incident retainer",
				EngagementModel: "Pre-arranged response support for credential compromise events",
				Deliverables: []string{
					"Pre-incident access and escalation runbook",
					"Compromise-response tabletop for issuance, revocation, rotation, and audit evidence",
					"Post-incident evidence pack and control-improvement backlog",
				},
			},
		},
		EvidenceRefs: []string{
			"internal/license/license.go: FeatureHASupport",
			"internal/api/enterprise_support.go: CAP-MODEL-04",
			"docs/editions.md: ha_support",
			"docs/features/platform-and-api.md: Enterprise support",
		},
	}
}
