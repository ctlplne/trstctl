// SPDX-License-Identifier: BUSL-1.1

package mcpserver

import (
	_ "embed"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/rca"
)

// ResultSchemaID is the version every tool result names in its schema field. The
// JSON Schema it stands for (draft-07, result.schema.json) is published in the
// tool listing, so an MCP client can check each result before it relies on it.
const ResultSchemaID = "trstctl.mcp.tool-result/v1"

//go:embed result.schema.json
var resultSchema []byte

// ResultSchema returns the published JSON Schema of a tool result.
func ResultSchema() []byte { return append([]byte(nil), resultSchema...) }

// Confidence says how the evidence behind a finding is known.
type Confidence string

const (
	// ConfidenceVerified is an observation whose signature the control plane
	// checked, such as a signed relay or agent receipt.
	ConfidenceVerified Confidence = "verified"
	// ConfidenceObserved was reported from outside trstctl's own record, such as
	// a discovery scan or an agent's inventory, without a checked signature.
	ConfidenceObserved Confidence = "observed"
	// ConfidenceRecorded is trstctl's record of its own action or an operator's
	// statement: an event, an inventory row, an approval.
	ConfidenceRecorded Confidence = "recorded"
	// ConfidenceInferred is a correlation that can be wrong, such as a match by
	// name only.
	ConfidenceInferred Confidence = "inferred"
)

// Finding is one structured finding a tool returns alongside its narrative.
// FindingID is stable for the same fact: the same evidence yields the same ID on
// every call. EvidenceIDs are kind:id references a caller can read back.
// ObservedAt is when the evidence was recorded or observed, and null when the
// record carries no time.
type Finding struct {
	FindingID   string            `json:"finding_id"`
	Kind        string            `json:"kind"`
	Summary     string            `json:"summary"`
	EvidenceIDs []string          `json:"evidence_ids"`
	Source      string            `json:"source"`
	ObservedAt  *time.Time        `json:"observed_at"`
	Confidence  Confidence        `json:"confidence"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// At returns t as a finding time, or nil for a zero time.
func At(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// evidenceFindings turns a gathered evidence bundle into findings, one per cited
// record, so the investigation tools answer with the same structure as the rest.
func evidenceFindings(ev rca.Evidence) []Finding {
	out := make([]Finding, 0, len(ev.Items))
	seen := map[string]bool{}
	for _, it := range ev.Items {
		if it.Citation == "" || seen[it.Citation] {
			continue
		}
		seen[it.Citation] = true
		source := strings.TrimSpace(it.Source)
		if source == "" {
			source, _, _ = strings.Cut(it.Citation, "#")
		}
		out = append(out, Finding{
			FindingID: "record:" + it.Citation, Kind: source + "_record", Summary: it.Summary,
			EvidenceIDs: []string{it.Citation}, Source: source, ObservedAt: At(it.At),
			Confidence: recordConfidence(source),
		})
	}
	return out
}

// recordConfidence: a crypto inventory row was read by a scan; every other
// surface the investigation tools read is trstctl's own record.
func recordConfidence(source string) Confidence {
	if source == "cbom" {
		return ConfidenceObserved
	}
	return ConfidenceRecorded
}
