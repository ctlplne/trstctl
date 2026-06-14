// Package secretscan ingests leaked-secret findings from scanners (trufflehog,
// gitleaks) into the inventory/graph with provenance (S20.4, F39) so an exposed
// credential appears in the same graph and risk view as everything else, and can
// be driven straight into the compromise workflow (S12.1). The defining safety
// rule: the secret VALUE is never parsed into a Finding or persisted/logged (AN-8);
// ingestion is audited (AN-2).
package secretscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/graph"
)

// Finding is a leaked-credential finding — location and rule only, never the value.
type Finding struct {
	Scanner       string
	RuleID        string
	File          string
	Line          int
	CredentialRef string
}

// ParseGitleaks parses a gitleaks JSON report, deliberately dropping the matched
// secret value (the "Secret"/"Match" fields are never read).
func ParseGitleaks(b []byte) ([]Finding, error) {
	var raw []struct {
		RuleID    string `json:"RuleID"`
		File      string `json:"File"`
		StartLine int    `json:"StartLine"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("secretscan: parse gitleaks: %w", err)
	}
	out := make([]Finding, 0, len(raw))
	for _, r := range raw {
		out = append(out, Finding{Scanner: "gitleaks", RuleID: r.RuleID, File: r.File, Line: r.StartLine, CredentialRef: r.RuleID + "@" + r.File})
	}
	return out, nil
}

// ParseTrufflehog parses trufflehog --json output (JSONL), dropping the "Raw"
// secret value.
func ParseTrufflehog(b []byte) ([]Finding, error) {
	var out []Finding
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var o struct {
			DetectorName   string `json:"DetectorName"`
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int    `json:"line"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			return nil, fmt.Errorf("secretscan: parse trufflehog: %w", err)
		}
		f := o.SourceMetadata.Data.Filesystem.File
		out = append(out, Finding{Scanner: "trufflehog", RuleID: o.DetectorName, File: f, Line: o.SourceMetadata.Data.Filesystem.Line, CredentialRef: o.DetectorName + "@" + f})
	}
	return out, nil
}

// Ingestor merges findings into the graph and optionally drives remediation.
type Ingestor struct {
	tenantID string
	graph    *graph.Graph
	audit    auditsink.Auditor
	trigger  func(ctx context.Context, credentialRef string) error // compromise workflow hook (S12.1)
}

// New constructs an Ingestor. trigger may be nil (no auto-remediation).
func New(tenantID string, g *graph.Graph, audit auditsink.Auditor, trigger func(ctx context.Context, credentialRef string) error) *Ingestor {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Ingestor{tenantID: tenantID, graph: g, audit: audit, trigger: trigger}
}

// Ingest records findings in the graph with provenance and, if drive is set,
// triggers the compromise workflow for each. No secret value is recorded or logged.
func (i *Ingestor) Ingest(ctx context.Context, findings []Finding, drive bool) (int, error) {
	for _, f := range findings {
		id := fmt.Sprintf("leak:%s:%s:%d", f.Scanner, f.File, f.Line)
		i.graph.AddNode(graph.Node{
			ID: id, Kind: graph.KindCredential, Name: f.CredentialRef,
			Attrs: map[string]string{"tenant_id": i.tenantID, "provenance": f.Scanner, "rule": f.RuleID, "file": f.File, "exposed": "true"},
		})
		_ = i.audit.Audit(ctx, "secretscan.finding", i.tenantID,
			[]byte(fmt.Sprintf(`{"scanner":%q,"rule":%q,"file":%q,"ref":%q}`, f.Scanner, f.RuleID, f.File, f.CredentialRef)))
		if drive && i.trigger != nil {
			if err := i.trigger(ctx, f.CredentialRef); err != nil {
				return 0, fmt.Errorf("secretscan: drive remediation for %s: %w", f.CredentialRef, err)
			}
		}
	}
	return len(findings), nil
}
