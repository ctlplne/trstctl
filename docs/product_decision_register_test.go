package docs

import (
	"strings"
	"testing"
	"time"
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

func TestProductDecisionRegisterCapturesReport007Recommendations(t *testing.T) {
	page := read(t, "product-decision-register.md")
	index := read(t, "index.md")

	if !strings.Contains(index, "product-decision-register.md") {
		t.Fatal("docs index must link the REPORT-007 product decision register")
	}

	for _, want := range []string{
		"REPORT-007",
		"Needs human decision",
		"Approved",
		"Implemented",
		"Promotion records",
		"Owner",
		"Decision date",
		"Test evidence",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("product-decision-register.md missing decision-promotion guardrail marker %q", want)
		}
	}

	statuses := productDecisionStatuses(page)
	if len(statuses) == 0 {
		t.Fatal("product-decision-register.md must list product-decision rows")
	}
	promotionRecords := productDecisionPromotionRecords(page)
	for id, status := range statuses {
		if status != "Approved" && status != "Implemented" {
			continue
		}
		record, ok := promotionRecords[id]
		if !ok {
			t.Errorf("%s is %s but has no owner/date/test promotion record", id, status)
			continue
		}
		if got := record["Status"]; got != status {
			t.Errorf("%s promotion record status = %q, want %q", id, got, status)
		}
		if strings.TrimSpace(record["Owner"]) == "" {
			t.Errorf("%s promotion record must name the human owner", id)
		}
		if _, err := time.Parse("2006-01-02", record["Decision date"]); err != nil {
			t.Errorf("%s promotion record must carry a YYYY-MM-DD decision date: %v", id, err)
		}
		if !strings.Contains(record["Test evidence"], "Test") {
			t.Errorf("%s promotion record must cite concrete test evidence, got %q", id, record["Test evidence"])
		}
	}
}

func productDecisionStatuses(page string) map[string]string {
	statuses := map[string]string{}
	inDecisionTable := false
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(line, "## ") {
			heading := strings.TrimSpace(line)
			inDecisionTable = heading == "## Narrative decisions" || heading == "## Packaging decisions"
			continue
		}
		if !inDecisionTable {
			continue
		}
		cells := productDecisionMarkdownTableCells(line)
		if len(cells) < 2 {
			continue
		}
		if strings.HasPrefix(cells[0], "NARRATIVE-") || strings.HasPrefix(cells[0], "PACKAGING-") {
			statuses[cells[0]] = cells[1]
		}
	}
	return statuses
}

func productDecisionPromotionRecords(page string) map[string]map[string]string {
	records := map[string]map[string]string{}
	var headers []string
	inPromotionRecords := false
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(line, "## ") {
			inPromotionRecords = strings.TrimSpace(line) == "## Promotion records"
			headers = nil
			continue
		}
		if !inPromotionRecords {
			continue
		}
		cells := productDecisionMarkdownTableCells(line)
		if len(cells) == 0 || strings.HasPrefix(cells[0], "---") {
			continue
		}
		if cells[0] == "ID" {
			headers = cells
			continue
		}
		if len(headers) == 0 || len(cells) != len(headers) {
			continue
		}
		row := map[string]string{}
		for i, header := range headers {
			row[header] = cells[i]
		}
		if strings.HasPrefix(row["ID"], "NARRATIVE-") || strings.HasPrefix(row["ID"], "PACKAGING-") {
			records[row["ID"]] = row
		}
	}
	return records
}

func productDecisionMarkdownTableCells(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil
	}
	raw := strings.Split(strings.Trim(line, "|"), "|")
	cells := make([]string, 0, len(raw))
	for _, cell := range raw {
		cells = append(cells, strings.TrimSpace(cell))
	}
	return cells
}
