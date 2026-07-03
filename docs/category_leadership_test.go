package docs

import (
	"strings"
	"testing"
)

func TestCategoryLeadershipLedgerRecordsRED006ImplementedDecisions(t *testing.T) {
	page := read(t, "category-leadership.md")
	index := read(t, "index.md")

	if !strings.Contains(index, "category-leadership.md") {
		t.Fatal("docs index must link the REPORT-004 category leadership ledger")
	}

	required := []string{
		"REPORT-004",
		"Category-Leadership",
		"COMPETE-001",
		"CAP-K8S-03",
		"COMPETE-021",
		"CAP-ISS-04",
		"COMPETE-012",
		"CAP-SCALE-01",
		"COMPETE-013",
		"CAP-SCALE-02",
		"COMPETE-034",
		"CAP-MODEL-02",
		"COMPETE-036",
		"CAP-API-07",
		"Idempotent automation + webhooks/eventing",
		"COMPETE-039",
		"CAP-IAM-02",
		"Multi-team / business-unit segmentation / multi-tenancy",
		"COMPETE-040",
		"CAP-KEY-05",
		"Multiple algorithms (RSA / ECDSA / Ed25519) + PQC",
		"COMPETE-041",
		"CAP-MODEL-01",
		"Self-hostable, run-anywhere",
		"COMPETE-042",
		"CAP-MODEL-03",
		"Air-gapped / on-prem + data residency",
		"COMPETE-044",
		"CAP-POL-06",
		"Tamper-evident / signed audit log",
		"GET /api/v1/audit/events",
		"GET /api/v1/audit/export",
		"internal/audit/chain_test.go",
		"internal/audit/audit_test.go",
		"internal/server/breakglass_served_test.go",
		"TestChainDetectsTampering",
		"TestEvidenceBundleVerifies",
		"TestServedBreakglassReconcileRecordsAuditChain",
		"/api/v1/platform/distribution",
		"trstctl-cli platform distribution",
		"internal/api/platform_distribution_test.go",
		"TestServedPlatformDistributionCAPMODEL01",
		"internal/server/airgap_served_test.go",
		"TestServedAirGapIssuesCertificateAndManagesSecretWithZeroOutboundEgress",
		"docs/airgap.md",
		"values-airgap.yaml",
		"internal/server/crypto_agility_served_test.go",
		"internal/server/protocols_pqc_served_test.go",
		"TestServedCryptoAgilityProfilesValidateBoundaryAlgorithms",
		"TestServedProtocolsIssueHybridPQCLeaves",
		"/api/v1/managed-offering/status",
		"POST /api/v1/notification-channels/{id}/test",
		"internal/server/managed_offering_served_test.go",
		"internal/server/idempotency_served_test.go",
		"internal/server/notifications_served_test.go",
		"internal/server/auth_served_test.go",
		"TestServedOIDCLoginEndToEnd",
		"docs/features/discovery-and-inventory.md",
		"docs/features/acme-and-dns.md",
		"docs/performance.md",
		"docs/features/platform-and-api.md",
		"NARRATIVE-001",
		"PACKAGING-001",
		"PACKAGING-004",
		"RED-006",
		"Implemented packaging proof",
		"self-hosted non-human identity management / Machine IAM control plane",
		"no per-certificate and no ephemeral-identity billing",
		"Managed is first-party operated",
		"Provider is MSP or self-hosted provider-plane operation",
	}
	for _, want := range required {
		if !strings.Contains(page, want) {
			t.Errorf("category-leadership.md missing REPORT-004 marker %q", want)
		}
	}

	forbidden := []string{
		"decision-track residual",
		"needs human product approval",
		"outside the served Category-Leadership numerator",
		"no per-cert pricing decided",
		"public managed-service packaging has been decided",
		"dominant category leader",
	}
	lower := strings.ToLower(page)
	for _, phrase := range forbidden {
		if strings.Contains(lower, strings.ToLower(phrase)) {
			t.Errorf("category-leadership.md overclaims an undecided or unproved leadership point: %q", phrase)
		}
	}

	servedEvidence := map[string][]string{
		"features/discovery-and-inventory.md": {"CAP-K8S-03", "Ingress", "Gateway"},
		"features/acme-and-dns.md":            {"CAP-ISS-04", "External Account Binding"},
		"performance.md":                      {"CAP-SCALE-01", "CAP-SCALE-02", "100k", "1M"},
		"features/platform-and-api.md": {
			"CAP-API-07",
			"POST /api/v1/identities/{id}/transitions",
			"POST /api/v1/notification-channels/{id}/test",
			"CAP-SCALE-01",
			"CAP-SCALE-02",
			"CAP-MODEL-02",
			"/api/v1/managed-offering/status",
			"trstctl-cli managed-offering status",
			"tenant-provisioning form",
			"CAP-IAM-02",
			"Multi-tenant topology",
			"PostgreSQL itself",
			"tenant_id",
			"WithTenant",
			"CAP-MODEL-01",
			"Self-hostable, run-anywhere",
			"GET /api/v1/platform/distribution",
			"trstctl-cli platform distribution",
			"host-archive",
			"Docker Compose",
			"Kubernetes/Helm",
			"external-datastore",
			"embedded-Postgres scan receipts",
			"OpenAPI/CLI route parity",
			"architecture linter",
			"CAP-MODEL-03",
			"Air-gapped / on-prem + data residency",
			"TRSTCTL_AIRGAP_ENABLED",
			"values-airgap.yaml",
			"zero public egress",
		},
		"features/policy-and-governance.md": {
			"CAP-POL-06",
			"Tamper-evident / signed audit log",
			"GET /api/v1/audit/events",
			"GET /api/v1/audit/export",
			"VerifyChain",
			"JOSE-signed evidence bundle",
			"hash-chained",
		},
		"features/issuance-and-cas.md": {
			"CAP-KEY-05",
			"Multiple algorithms (RSA / ECDSA / Ed25519) + PQC",
			"POST /api/v1/profiles",
			"Hybrid-ML-DSA-44-ECDSA-P256",
			"ML-DSA-65",
			"SLH-DSA-SHA2-128s",
		},
		"features/lifecycle-and-pqc.md": {
			"RSA",
			"ECDSA",
			"Ed25519",
			"ML-DSA",
			"ML-KEM",
			"SLH-DSA",
			"POST /api/v1/profiles",
		},
	}
	for rel, markers := range servedEvidence {
		body := read(t, rel)
		for _, marker := range markers {
			if !strings.Contains(body, marker) {
				t.Errorf("%s missing served leadership evidence marker %q", rel, marker)
			}
		}
	}
}

func TestNarrative005SovereigntyProofBlockCarriesNHILabel(t *testing.T) {
	readme := read(t, "../README.md")
	start := strings.Index(readme, "Three choices set trstctl apart:")
	if start == -1 {
		t.Fatal("README.md missing the first proof block")
	}
	rest := readme[start:]
	end := strings.Index(rest, "## What it answers")
	if end == -1 {
		t.Fatal("README.md first proof block no longer ends before What it answers")
	}
	proofBlock := rest[:end]

	for _, want := range []string{
		"Self-hosted",
		"infrastructure you control",
		"No credential data ships to a vendor cloud",
		"data-sovereign NHI / Machine IAM",
	} {
		if !strings.Contains(proofBlock, want) {
			t.Errorf("README.md first proof block must keep NARRATIVE-005 sovereignty/NHI marker %q", want)
		}
	}
}
