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
		"/api/v1/managed-offering/status",
		"POST /api/v1/notification-channels/{id}/test",
		"internal/server/managed_offering_served_test.go",
		"internal/server/idempotency_served_test.go",
		"internal/server/notifications_served_test.go",
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
