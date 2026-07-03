package docs

import (
	"strings"
	"testing"
)

func TestProductDecisionRegisterCapturesReport007ImplementedDecisions(t *testing.T) {
	page := read(t, "product-decision-register.md")
	index := read(t, "index.md")

	if !strings.Contains(index, "product-decision-register.md") {
		t.Fatal("docs index must link the REPORT-007 product decision register")
	}

	required := []string{
		"REPORT-007",
		"Implemented",
		"RED-006",
		"2026-07-03",
		"NARRATIVE-001",
		"self-hosted non-human identity management / Machine IAM control plane",
		"NARRATIVE-002",
		"no per-certificate and no ephemeral-identity billing is product policy",
		"NARRATIVE-003",
		"live eval receipts",
		"OWASP NHI mapping",
		"NARRATIVE-004",
		"served-now, conditional, partial, and roadmap",
		"PACKAGING-001",
		"billable unit",
		"PACKAGING-002",
		"Community, Enterprise, Provider, and Managed",
		"PACKAGING-003",
		"certificate counters are operational telemetry",
		"PACKAGING-004",
		"Managed is a first-party operated packaging column",
		"Provider remains the MSP and self-hosted provider-plane packaging path",
	}
	for _, want := range required {
		if !strings.Contains(page, want) {
			t.Errorf("product-decision-register.md missing REPORT-007 marker %q", want)
		}
	}

	forbidden := []string{
		"Needs human decision",
		"not product truth until approved",
		"recommended but not product truth",
		"still needs human approval",
		"first-party SaaS, MSP/Provider, or self-hosted Provider",
	}
	lower := strings.ToLower(page)
	for _, phrase := range forbidden {
		if strings.Contains(lower, phrase) {
			t.Errorf("product-decision-register.md turns a recommendation into product truth: %q", phrase)
		}
	}
}
